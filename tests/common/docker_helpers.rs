// tests/common/docker_helpers.rs

//! Utilitários para gerenciar ambientes Docker Compose para testes de integração.
//!
//! Fornece a struct `DockerComposeEnv` para controlar o ciclo de vida (`up`, `down`, `start`, `stop`)
//! dos serviços Docker definidos em um arquivo `docker-compose.yml`, e para
//! consultar informações sobre esses serviços, como portas mapeadas e status de saúde.

use anyhow::{bail, Context as AnyhowContext, Result};
use std::io::{BufRead, BufReader, ErrorKind as IoErrorKind}; // Adicionado IoErrorKind
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn}; // `trace` e `warn` são usados

/// Contador global para garantir sufixos de nome de projeto únicos para Docker Compose.
static PROJECT_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Representa e gerencia um ambiente Docker Compose isolado para um teste.
#[derive(Debug)]
pub struct DockerComposeEnv {
    /// Caminho para o arquivo `docker-compose.yml` a ser usado.
    compose_file_path: String,
    /// Nome único do projeto Docker Compose para esta instância.
    project_name: String,
}

impl DockerComposeEnv {
    /// Cria uma nova instância de `DockerComposeEnv`.
    ///
    /// # Arguments
    /// * `compose_file_path`: Caminho para o arquivo `docker-compose.yml`.
    /// * `project_name_prefix`: Prefixo para o nome do projeto Docker Compose.
    ///   Um sufixo único (contador e parte de UUID) será adicionado.
    pub fn new(compose_file_path: &str, project_name_prefix: &str) -> Self {
        let unique_id_num = PROJECT_COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
        let unique_id_uuid_short = uuid::Uuid::new_v4().as_simple().to_string()[..8].to_string();

        let sanitized_prefix = project_name_prefix
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>();
        
        let mut project_name = format!("{}_{}_{:03}", sanitized_prefix, unique_id_uuid_short, unique_id_num);
        const MAX_PROJECT_NAME_LEN: usize = 60; 
        if project_name.len() > MAX_PROJECT_NAME_LEN {
            project_name.truncate(MAX_PROJECT_NAME_LEN);
        }
        project_name = project_name.trim_end_matches(|c| c == '-' || c == '_').to_string();

        info!(
            "Criando DockerComposeEnv para projeto: '{}' usando arquivo: '{}'",
            project_name, compose_file_path
        );
        DockerComposeEnv { compose_file_path: compose_file_path.to_string(), project_name }
    }

    /// Retorna o nome do projeto Docker Compose.
    pub fn project_name(&self) -> &str {
        &self.project_name
    }

    /// Retorna todas as variáveis de ambiente necessárias para evitar warnings do Docker Compose.
    ///
    /// Centraliza a definição das variáveis de ambiente para garantir consistência
    /// entre os comandos `up` e `down`.
    fn get_compose_env_vars(&self, config_filename_opt: Option<&str>, tls_enabled: bool) -> Vec<(String, String)> {
        let mcp_config_path = if let Some(config_filename) = config_filename_opt {
            format!("/app/test_configs/{}", config_filename)
        } else {
            "/dev/null".to_string()
        };

        vec![
            ("MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV".to_string(), mcp_config_path),
            ("MCP_TYPEDB__ADDRESS".to_string(), "typedb-server-it:1729".to_string()),
            ("TLS_ENABLED".to_string(), if tls_enabled { "true".to_string() } else { "false".to_string() }),
            ("target_typedb_host_port".to_string(), "typedb-server-it:1729".to_string()),
            ("timeout_duration".to_string(), "120".to_string()),
            ("target_typedb_service_name".to_string(), "typedb-server-it".to_string()),
            ("sleep_interval".to_string(), "3".to_string()),
            ("elapsed_time".to_string(), "0".to_string()),
        ]
    }

    /// Executa um comando `docker compose`.
    ///
    /// # Arguments
    /// * `global_args`: Argumentos globais do Docker Compose (ex: `["--profile", "myprofile"]`).
    /// * `subcommand_args`: Argumentos do subcomando Docker Compose (ex: `["up", "-d"]`).
    /// * `env_vars_for_command_process`: Variáveis de ambiente para o processo `docker compose` em si,
    ///   usadas para substituição no arquivo YAML.
    fn run_compose_command(
        &self,
        global_args: &[&str],
        subcommand_args: &[&str],
        env_vars_for_command_process: Option<&[(&str, String)]>,
    ) -> Result<ExitStatus> {
        let mut command = Command::new("docker");
        command.arg("compose");
        command.arg("-f").arg(&self.compose_file_path);
        command.arg("-p").arg(self.project_name());
        
        command.args(global_args);    // Argumentos globais ANTES do subcomando
        command.args(subcommand_args); // Subcomando e seus argumentos

        if let Some(vars) = env_vars_for_command_process {
            for (key, value) in vars {
                command.env(key, value); // Define ENV para o processo `docker compose`
                debug!("Para comando `docker compose`: setando ENV {}={}", key, value);
            }
        }

        debug!("Executando comando Docker Compose: {:?}", command);

        let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
            .with_context(|| format!("Falha ao iniciar 'docker compose {:?} {:?}' para projeto '{}'", global_args, subcommand_args, self.project_name()))?;

        let stdout_output_shared = Arc::new(Mutex::new(Vec::new()));
        let stderr_output_shared = Arc::new(Mutex::new(Vec::new()));

        if let Some(stdout) = child.stdout.take() {
            let stdout_clone = stdout_output_shared.clone();
            let project_name_clone = self.project_name().to_string();
            std::thread::spawn(move || {
                BufReader::new(stdout).lines().for_each(|line_result| {
                    match line_result {
                        Ok(line) => {
                            trace!("[Compose STDOUT {}]: {}", project_name_clone, line);
                            if let Ok(mut guard) = stdout_clone.lock() { guard.push(line); }
                        }
                        Err(e) => warn!("[Compose STDOUT {}]: Erro ao ler linha: {}", project_name_clone, e),
                    }
                });
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let stderr_clone = stderr_output_shared.clone();
            let project_name_clone = self.project_name().to_string();
            std::thread::spawn(move || {
                BufReader::new(stderr).lines().for_each(|line_result| {
                    match line_result {
                        Ok(line) => {
                            warn!("[Compose STDERR {}]: {}", project_name_clone, line);
                            if let Ok(mut guard) = stderr_clone.lock() { guard.push(line); }
                        }
                        Err(e) => warn!("[Compose STDERR {}]: Erro ao ler linha: {}", project_name_clone, e),
                    }
                });
            });
        }

        let status = child.wait().with_context(|| format!("Falha ao esperar 'docker compose {:?} {:?}' para projeto '{}'", global_args, subcommand_args, self.project_name()))?;

        if !status.success() {
            let stdout_log = stdout_output_shared.lock().unwrap_or_else(|e| e.into_inner()).join("\n");
            let stderr_log = stderr_output_shared.lock().unwrap_or_else(|e| e.into_inner()).join("\n");
            bail!(
                "Comando docker compose '{:?} {:?}' falhou para projeto '{}' com status: {}.\nSTDOUT:\n{}\nSTDERR:\n{}",
                global_args, subcommand_args, self.project_name(), status, stdout_log, stderr_log
            );
        }
        Ok(status)
    }

    /// Inicia o ambiente Docker Compose.
    ///
    /// # Arguments
    /// * `config_filename`: Nome do arquivo de configuração TOML (ex: "default.test.toml") para o MCP Server.
    /// * `active_profiles`: Opcional. Perfis do Docker Compose a serem ativados.
    /// * `wait_for_health`: Se `true`, usa `--wait` do Docker Compose para aguardar healthchecks.
    /// * `tls_enabled`: Se `true`, define TLS_ENABLED=true para o healthcheck do Dockerfile.
    pub fn up(&self, config_filename: &str, active_profiles: Option<Vec<String>>, wait_for_health: bool, tls_enabled: bool) -> Result<()> {
        info!(
            "Iniciando ambiente Docker Compose para projeto: '{}', config MCP: '{}', perfis: {:?}, wait_for_health: {}, tls_enabled: {}",
            self.project_name(), config_filename, active_profiles.as_deref().unwrap_or_default(), wait_for_health, tls_enabled
        );

        let env_vars_for_compose_process = self.get_compose_env_vars(Some(config_filename), tls_enabled);
        let env_vars_refs: Vec<(&str, String)> = env_vars_for_compose_process
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        
        let mut up_subcommand_args: Vec<&str> = 
            vec!["up", "-d", "--remove-orphans", "--force-recreate", "--build"];
        
        if wait_for_health {
            up_subcommand_args.push("--wait");
        }

        let mut global_args_owned: Vec<String> = Vec::new();
        if let Some(profiles) = &active_profiles {
            if !profiles.is_empty() {
                for profile_name in profiles {
                    global_args_owned.push("--profile".to_string());
                    global_args_owned.push(profile_name.clone());
                }
            }
        }
        let global_args_str_refs: Vec<&str> = global_args_owned.iter().map(AsRef::as_ref).collect();

        self.run_compose_command(
            &global_args_str_refs,
            &up_subcommand_args,
            Some(&env_vars_refs),
        )
        .with_context(|| format!("Falha em 'docker compose up' para projeto '{}', config MCP: '{}', perfis: {:?}", self.project_name(), config_filename, active_profiles.as_deref().unwrap_or_default()))?;

        info!("Ambiente Docker Compose para projeto '{}' iniciado (comando 'up' enviado).", self.project_name());
        Ok(())
    }

    /// Derruba o ambiente Docker Compose.
    ///
    /// # Arguments
    /// * `remove_volumes`: Se `true`, remove os volumes nomeados.
    pub fn down(&self, remove_volumes: bool) -> Result<()> {
        info!(
            "Derrubando ambiente Docker Compose para projeto: '{}' (remover volumes: {})",
            self.project_name(), remove_volumes
        );
        
        // Usa as mesmas variáveis de ambiente para evitar warnings do Docker Compose
        let env_vars_for_compose_process = self.get_compose_env_vars(None, false);
        let env_vars_refs: Vec<(&str, String)> = env_vars_for_compose_process
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        
        let mut subcommand_args = vec!["down", "--remove-orphans"];
        if remove_volumes {
            subcommand_args.push("-v");
        }
        subcommand_args.push("--timeout");
        subcommand_args.push("30"); // Timeout para parada graciosa

        match self.run_compose_command(&[], &subcommand_args, Some(&env_vars_refs)) {
            Ok(_) => {
                info!("Ambiente Docker Compose para projeto '{}' derrubado.", self.project_name());
                
                // Cleanup adicional para garantir remoção completa de containers órfãos
                if let Err(e) = self.force_cleanup_orphaned_containers() {
                    warn!("Cleanup adicional de containers órfãos falhou para projeto '{}': {}. Isso pode ser normal se não houver containers órfãos.", self.project_name(), e);
                }
            },
            Err(e) => {
                error!("Erro ao derrubar ambiente Docker Compose para projeto '{}': {}. Tentando cleanup forçado.", self.project_name(), e);
                
                // Tenta cleanup forçado mesmo se down() falhou
                if let Err(cleanup_err) = self.force_cleanup_orphaned_containers() {
                    warn!("Cleanup forçado também falhou para projeto '{}': {}", self.project_name(), cleanup_err);
                }
                
                return Err(e);
            }
        }
        Ok(())
    }

    /// Força a remoção de containers órfãos para este projeto, mesmo se docker compose down falhou.
    fn force_cleanup_orphaned_containers(&self) -> Result<()> {
        debug!("Executando cleanup forçado de containers órfãos para projeto '{}'", self.project_name());
        
        // Lista containers órfãos para este projeto específico
        let list_output = Command::new("docker")
            .arg("ps")
            .arg("-a")
            .arg("--filter")
            .arg(&format!("label=com.docker.compose.project={}", self.project_name()))
            .arg("--format")
            .arg("{{.ID}}")
            .output()
            .with_context(|| format!("Falha ao listar containers para projeto '{}'", self.project_name()))?;

        if !list_output.status.success() {
            bail!("Falha ao listar containers órfãos para projeto '{}'", self.project_name());
        }

        let container_ids_string = String::from_utf8_lossy(&list_output.stdout);
        let container_ids: Vec<&str> = container_ids_string
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();

        if container_ids.is_empty() {
            debug!("Nenhum container órfão encontrado para projeto '{}'", self.project_name());
        } else {
            info!("Removendo {} containers órfãos para projeto '{}': {:?}", 
                  container_ids.len(), self.project_name(), container_ids);

            // Remove containers órfãos forçadamente
            let mut remove_cmd = Command::new("docker");
            remove_cmd.arg("rm").arg("-f");
            remove_cmd.args(&container_ids);

            let remove_output = remove_cmd.output()
                .with_context(|| format!("Falha ao executar 'docker rm -f' para containers órfãos do projeto '{}'", self.project_name()))?;

            if !remove_output.status.success() {
                let stderr = String::from_utf8_lossy(&remove_output.stderr);
                bail!("Falha ao remover containers órfãos para projeto '{}': {}", self.project_name(), stderr);
            }

            info!("Containers órfãos removidos com sucesso para projeto '{}'", self.project_name());
        }

        // Cleanup adicional: remover redes órfãs do projeto
        self.force_cleanup_orphaned_networks()
            .with_context(|| format!("Falha no cleanup de redes órfãs para projeto '{}'", self.project_name()))?;

        Ok(())
    }

    /// Força a remoção de redes órfãs para este projeto.
    fn force_cleanup_orphaned_networks(&self) -> Result<()> {
        debug!("Executando cleanup forçado de redes órfãs para projeto '{}'", self.project_name());

        // Lista redes órfãs para este projeto específico
        let list_output = Command::new("docker")
            .arg("network")
            .arg("ls")
            .arg("--filter")
            .arg(&format!("label=com.docker.compose.project={}", self.project_name()))
            .arg("--format")
            .arg("{{.ID}}")
            .output()
            .with_context(|| format!("Falha ao listar redes para projeto '{}'", self.project_name()))?;

        if !list_output.status.success() {
            bail!("Falha ao listar redes órfãs para projeto '{}'", self.project_name());
        }

        let network_ids_string = String::from_utf8_lossy(&list_output.stdout);
        let network_ids: Vec<&str> = network_ids_string
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();

        if network_ids.is_empty() {
            debug!("Nenhuma rede órfã encontrada para projeto '{}'", self.project_name());
            return Ok(());
        }

        info!("Removendo {} redes órfãs para projeto '{}': {:?}", 
              network_ids.len(), self.project_name(), network_ids);

        // Remove redes órfãs forçadamente
        let mut remove_cmd = Command::new("docker");
        remove_cmd.arg("network").arg("rm");
        remove_cmd.args(&network_ids);

        let remove_output = remove_cmd.output()
            .with_context(|| format!("Falha ao executar 'docker network rm' para redes órfãs do projeto '{}'", self.project_name()))?;

        if !remove_output.status.success() {
            let stderr = String::from_utf8_lossy(&remove_output.stderr);
            // Networks podem falhar ao remover se ainda estiverem em uso, isso é ok
            warn!("Algumas redes podem não ter sido removidas para projeto '{}': {}", self.project_name(), stderr);
        } else {
            info!("Redes órfãs removidas com sucesso para projeto '{}'", self.project_name());
        }

        Ok(())
    }
    
    /// Coleta e loga os logs de todos os serviços.
    pub fn logs_all_services(&self) -> Result<()> {
        info!("Coletando logs para projeto Docker Compose: {}", self.project_name());
        let output = Command::new("docker")
            .arg("compose")
            .arg("-f").arg(&self.compose_file_path)
            .arg("-p").arg(self.project_name())
            .arg("logs")
            .arg("--no-color").arg("--tail=all").arg("--timestamps")
            .output().with_context(|| format!("Falha ao executar 'docker compose logs' para projeto {}", self.project_name()))?;

        if !output.stdout.is_empty() {
            info!("[Compose Logs STDOUT {}]:\n{}", self.project_name(), String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            warn!("[Compose Logs STDERR {}]:\n{}", self.project_name(), String::from_utf8_lossy(&output.stderr));
        }
        if !output.status.success() {
            bail!("'docker compose logs' para projeto '{}' falhou com status {}", self.project_name(), output.status);
        }
        Ok(())
    }
    
    /// Obtém a porta do host mapeada para uma porta interna de um serviço.
    pub fn get_service_host_port(&self, service_name: &str, internal_port: u16) -> Result<u16> {
        debug!("Obtendo porta mapeada para serviço '{}', porta interna {} (projeto '{}')", service_name, internal_port, self.project_name());
        let output = Command::new("docker")
            .arg("compose")
            .arg("-f").arg(&self.compose_file_path)
            .arg("-p").arg(self.project_name())
            .arg("port")
            .arg(service_name)
            .arg(internal_port.to_string())
            .output().with_context(|| format!("Falha 'docker compose port {} {}' para projeto {}", service_name, internal_port, self.project_name()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            self.logs_all_services().unwrap_or_else(|e| error!("Erro adicional ao coletar logs: {}", e));
            bail!("'docker compose port {} {}' falhou (status {}): {}", service_name, internal_port, output.status, stderr);
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            self.logs_all_services().unwrap_or_else(|e| error!("Erro adicional ao coletar logs: {}", e));
            bail!("Saída de 'docker compose port {} {}' vazia. Serviço/perfil ativo?", service_name, internal_port);
        }
        stdout.rsplit_once(':').and_then(|(_,p)| p.parse().ok()).with_context(|| format!("Saída inesperada de 'port': '{}'", stdout))
    }

    /// Para um serviço específico.
    pub fn stop_service(&self, service_name: &str) -> Result<()> {
        info!("Parando serviço '{}' (projeto '{}')", service_name, self.project_name());
        self.run_compose_command(&[], &["stop", service_name], None)?;
        std::thread::sleep(Duration::from_secs(3)); // Tempo para parada
        Ok(())
    }

    /// Inicia um serviço previamente parado.
    pub fn start_service(&self, service_name: &str) -> Result<()> {
        info!("Iniciando serviço parado '{}' (projeto '{}')", service_name, self.project_name());
        self.run_compose_command(&[], &["start", service_name], None)?;
        std::thread::sleep(Duration::from_secs(3)); // Tempo para início
        Ok(())
    }
    
    /// Aguarda um serviço ficar saudável (via healthcheck Docker) ou estar no estado "running".
    pub async fn wait_for_service_healthy(&self, service_name: &str, timeout_duration: Duration) -> Result<()> {
        info!("Aguardando serviço '{}' (projeto '{}') ficar saudável/rodando (timeout: {:?})", service_name, self.project_name(), timeout_duration);
        let start_time = Instant::now();
        let check_interval = Duration::from_secs(2); // Intervalo entre verificações

        loop {
            if start_time.elapsed() >= timeout_duration {
                self.logs_all_services().unwrap_or_else(|e| error!("Erro ao obter logs durante timeout de wait_for_service_healthy: {}", e));
                bail!("Timeout esperando serviço '{}' (projeto '{}') ficar saudável/rodando.", service_name, self.project_name());
            }

            let ps_output_res = Command::new("docker")
                .arg("compose")
                .arg("-f").arg(&self.compose_file_path)
                .arg("-p").arg(self.project_name())
                .arg("ps").arg("--format").arg("json").arg(service_name)
                .output();

            let output_str = match ps_output_res {
                Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
                Ok(out) => { 
                    debug!("'docker compose ps' para serviço '{}' falhou (status {}). Stderr: {}. Tentando novamente...", service_name, out.status, String::from_utf8_lossy(&out.stderr));
                    tokio::time::sleep(check_interval).await;
                    continue;
                }
                Err(e) => {
                    // Tratar erro de execução do comando, ex: docker não encontrado ou permissão
                    if e.kind() == IoErrorKind::NotFound {
                         bail!("Comando 'docker' não encontrado. Certifique-se que o Docker está instalado e no PATH.");
                    }
                    warn!("'docker compose ps' para serviço '{}' falhou ao executar: {}. Tentando novamente...", service_name, e);
                    tokio::time::sleep(check_interval).await;
                    continue;
                }
            };
            
            if output_str.trim().is_empty() {
                debug!("'docker compose ps' para serviço '{}' não retornou contêineres (perfil pode não estar ativo). Tentando novamente...", service_name);
                tokio::time::sleep(check_interval).await;
                continue;
            }

            if let Some(first_line) = output_str.lines().next() {
                 match serde_json::from_str::<serde_json::Value>(first_line) {
                    Ok(service_info) => {
                        let container_state = service_info.get("State").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                        let container_status = service_info.get("Status").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                        
                        debug!("Serviço '{}' (projeto '{}') status contêiner: '{}', campo Status: '{}'", service_name, self.project_name(), container_state, container_status);

                        if container_state == "running" {
                            if container_status.contains("healthy") {
                                info!("Serviço '{}' (projeto '{}') está saudável (Status: {}).", service_name, self.project_name(), container_status);
                                return Ok(());
                            } else if !container_status.contains("starting") && !container_status.contains("unhealthy") {
                                info!("Serviço '{}' (projeto '{}') está rodando (Status: {}). Considerando pronto (sem healthcheck ativo ou já passou).", service_name, self.project_name(), container_status);
                                return Ok(());
                            } else if container_status.contains("unhealthy") {
                                 self.logs_all_services().unwrap_or_else(|e| error!("Erro ao obter logs durante unhealthy: {}", e));
                                bail!("Serviço '{}' (projeto '{}') está unhealthy. Status: {}", service_name, self.project_name(), container_status);
                            }
                        }
                    }
                    Err(e) => warn!("Falha ao parsear JSON do 'docker compose ps' para '{}': {}. Output: {}", service_name, e, first_line),
                }
            } else {
                debug!("'docker compose ps --format json' para '{}' não retornou linha JSON. Tentando novamente...", service_name);
            }
            tokio::time::sleep(check_interval).await;
        }
    }

    /// Inicia o ambiente Docker Compose (versão de compatibilidade).
    /// 
    /// Esta versão mantém compatibilidade com código existente que não especifica
    /// o parâmetro `wait_for_health`. Por padrão, usa `--wait` e TLS_ENABLED=false.
    ///
    /// # Arguments
    /// * `config_filename`: Nome do arquivo de configuração TOML (ex: "default.test.toml") para o MCP Server.
    /// * `active_profiles`: Opcional. Perfis do Docker Compose a serem ativados.
    #[allow(dead_code)]
    pub fn up_compat(&self, config_filename: &str, active_profiles: Option<Vec<String>>) -> Result<()> {
        self.up(config_filename, active_profiles, true, false)
    }
}

impl Drop for DockerComposeEnv {
    fn drop(&mut self) {
        info!("Limpando ambiente Docker Compose para projeto: '{}' (via Drop).", self.project_name());
        if let Err(e) = self.down(true) { 
            error!("Falha ao derrubar ambiente Docker Compose no drop para '{}': {}. Limpeza manual pode ser necessária.", self.project_name(), e);
        } else {
            info!("Ambiente Docker Compose para projeto '{}' derrubado com sucesso no drop.", self.project_name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants;
    use serial_test::serial; 

    fn create_minimal_compose_file_for_helper_tests() -> std::io::Result<tempfile::NamedTempFile> {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new()?;
        // Adicionado um healthcheck mais simples e rápido para o alpine-dummy-service
        writeln!(file, r#"
version: '3.8'
services:
  alpine-dummy-service:
    image: alpine:latest
    container_name: ${{COMPOSE_PROJECT_NAME}}-alpine-dummy
    command: ["sh", "-c", "echo 'Dummy service started. MCP_CONFIG_PATH_ENV_VAR=${{MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV}}' && apk add --no-cache netcat-openbsd && nc -lk -p 80 -e /bin/cat & sleep 30 && echo 'Dummy service stopping'"]
    ports:
      - "12345:80"
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 80 || exit 1"]
      interval: 2s
      timeout: 1s
      retries: 5
      start_period: 1s
"#)?;
        file.flush()?;
        Ok(file)
    }

    #[tokio::test]
    #[serial] 
    async fn test_docker_compose_env_new_generates_unique_project_name() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let dummy_compose_file = create_minimal_compose_file_for_helper_tests()?;
        let compose_path_str = dummy_compose_file.path().to_str().unwrap().to_string();

        let env1 = DockerComposeEnv::new(&compose_path_str, "test_prefix");
        let env2 = DockerComposeEnv::new(&compose_path_str, "test_prefix");
        assert_ne!(env1.project_name(), env2.project_name(), "Nomes de projeto deveriam ser únicos.");
        info!("Nome projeto 1: {}, Nome projeto 2: {}", env1.project_name(), env2.project_name());
        Ok(())
    }
    
    #[tokio::test]
    #[serial]
    async fn test_docker_compose_env_up_down_cycle_with_minimal_service() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let dummy_compose_file = create_minimal_compose_file_for_helper_tests()?;
        let compose_path_str = dummy_compose_file.path().to_str().unwrap().to_string();

        info!("Iniciando teste test_docker_compose_env_up_down_cycle_with_minimal_service");
        let env = DockerComposeEnv::new(&compose_path_str, "hlp_cycle_min");
        
        env.up("dummy_config.toml", None, true, false) 
            .context("Falha no env.up() no teste de ciclo de vida com serviço mínimo")?;
        
        env.wait_for_service_healthy("alpine-dummy-service", Duration::from_secs(20))
            .await
            .context("Serviço alpine-dummy-service não ficou saudável")?;
        info!("Serviço alpine-dummy-service está saudável.");

        let host_port = env.get_service_host_port("alpine-dummy-service", 80)
            .context("Falha ao obter porta mapeada para alpine-dummy-service")?;
        assert_eq!(host_port, 12345, "Porta mapeada para alpine-dummy-service incorreta.");
        info!("Porta do host para alpine-dummy-service:80 é {}", host_port);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore] 
    async fn test_real_services_up_down_and_port_retrieval() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        
        let compose_path_str = constants::DEFAULT_DOCKER_COMPOSE_TEST_FILE; 
        let env = DockerComposeEnv::new(compose_path_str, "hlp_real_svc");

        env.up(constants::DEFAULT_TEST_CONFIG_FILENAME, Some(vec!["typedb_default".to_string()]), true, false) // Ativa apenas typedb_default
            .context("Falha ao executar 'up' com config default e perfil typedb_default")?;

        env.wait_for_service_healthy(constants::TYPEDB_SERVICE_NAME, constants::DEFAULT_TYPEDB_READY_TIMEOUT)
            .await
            .with_context(|| format!("Serviço '{}' não ficou saudável", constants::TYPEDB_SERVICE_NAME))?;
        
        let typedb_host_port = env.get_service_host_port(constants::TYPEDB_SERVICE_NAME, constants::TYPEDB_INTERNAL_PORT)
            .with_context(|| format!("Falha ao obter porta para {}", constants::TYPEDB_SERVICE_NAME))?;
        assert_eq!(typedb_host_port, constants::TYPEDB_HOST_PORT);
        info!("Porta do TypeDB ({}) no host: {}", constants::TYPEDB_SERVICE_NAME, typedb_host_port);

        Ok(())
    }
}