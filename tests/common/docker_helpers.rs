// tests/common/docker_helpers.rs

//! Utilitários para gerenciar ambientes Docker Compose para testes de integração.
//!
//! Fornece a struct `DockerComposeEnv` para controlar o ciclo de vida (`up`, `down`, `start`, `stop`)
//! dos serviços Docker definidos em um arquivo `docker-compose.yml`, e para
//! consultar informações sobre esses serviços, como portas mapeadas e status de saúde.

use anyhow::{bail, Context as AnyhowContext, Result};
use std::io::{BufRead, BufReader};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

// Importa constantes do mesmo crate `common`
// use super::constants; // Já importado implicitamente por ser do mesmo módulo pai `common`

/// Contador global para garantir sufixos de nome de projeto únicos para Docker Compose.
/// Isso ajuda a isolar ambientes de teste se executados (incorretamente) em paralelo
/// ou se limpezas anteriores falharem.
static PROJECT_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Representa e gerencia um ambiente Docker Compose isolado, específico para uma execução de teste.
///
/// Esta struct é responsável por:
/// - Gerar um nome de projeto Docker Compose único.
/// - Iniciar (`up`) os serviços definidos no arquivo compose, passando configurações dinâmicas
///   como o caminho do arquivo de configuração do MCP Server e perfis ativos.
/// - Derrubar (`down`) os serviços e limpar recursos (volumes, redes) ao final do teste (via `Drop`).
/// - Fornecer utilitários para interagir com os serviços (ex: obter portas, parar/iniciar serviços,
///   verificar saúde).
#[derive(Debug)]
pub struct DockerComposeEnv {
    /// Caminho para o arquivo `docker-compose.yml` a ser usado.
    compose_file_path: String,
    /// Nome único do projeto Docker Compose para esta instância do ambiente.
    project_name: String,
}

impl DockerComposeEnv {
    /// Cria uma nova instância de `DockerComposeEnv` com um nome de projeto único.
    ///
    /// # Arguments
    /// * `compose_file_path`: Caminho para o arquivo `docker-compose.yml`.
    /// * `project_name_prefix`: Um prefixo para o nome do projeto Docker Compose. Um sufixo
    ///   único será adicionado para garantir isolamento.
    pub fn new(compose_file_path: &str, project_name_prefix: &str) -> Self {
        let unique_id_num = PROJECT_COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
        // Usar um UUID curto para maior singularidade e evitar colisões se os testes reiniciarem rapidamente.
        let unique_id_uuid_short = uuid::Uuid::new_v4().as_simple().to_string()[..8].to_string();

        // Sanitizar o prefixo para ser um nome de projeto Docker Compose válido
        let sanitized_prefix = project_name_prefix
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>();

        // Construir o nome do projeto, garantindo que não seja excessivamente longo.
        // Formato: <prefixo_sanitizado>_<uuid_curto>_<contador>
        let mut project_name = format!("{}_{}_{:03}", sanitized_prefix, unique_id_uuid_short, unique_id_num);

        const MAX_PROJECT_NAME_LEN: usize = 60; // Limite razoável para nomes de projeto
        if project_name.len() > MAX_PROJECT_NAME_LEN {
            project_name.truncate(MAX_PROJECT_NAME_LEN);
        }
        // Remover hífens ou underscores no final, se houver, após o truncamento.
        project_name = project_name.trim_end_matches(|c| c == '-' || c == '_').to_string();

        info!(
            "Criando DockerComposeEnv para projeto: '{}' usando arquivo: '{}'",
            project_name, compose_file_path
        );
        DockerComposeEnv { compose_file_path: compose_file_path.to_string(), project_name }
    }

    /// Retorna o nome do projeto Docker Compose gerenciado por esta instância.
    pub fn project_name(&self) -> &str {
        &self.project_name
    }

    /// Executa um comando `docker compose` com os argumentos fornecidos.
    ///
    /// Esta função configura o comando `docker compose` com o arquivo compose específico
    /// e o nome do projeto desta instância, além de quaisquer variáveis de ambiente
    /// que precisem ser definidas para a execução do próprio comando `docker compose`
    /// (usadas para substituição no arquivo YAML).
    ///
    /// # Arguments
    /// * `global_args`: Slice de strings representando argumentos globais do Docker Compose que devem 
    ///   vir antes do subcomando (ex: `["--profile", "typedb_default"]`).
    /// * `args`: Slice de strings representando os argumentos para `docker compose` (ex: `["up", "-d"]`).
    /// * `env_vars_for_command`: Opcional. Slice de tuplas `(&str, String)` representando variáveis de
    ///   ambiente a serem definidas para o processo do comando `docker compose`.
    ///   Estas são usadas pelo Docker Compose para substituição de variáveis no arquivo YAML.
    fn run_compose_command(
        &self,
        global_args: &[&str],
        args: &[&str],
        env_vars_for_command: Option<&[(&str, String)]>,
    ) -> Result<ExitStatus> {
        let mut command = Command::new("docker");
        command.arg("compose");
        command.arg("-f").arg(&self.compose_file_path);
        command.arg("-p").arg(self.project_name()); // Isola o projeto
        
        // Adicionar argumentos globais antes do subcomando
        command.args(global_args);

        command.args(args);

        // Define variáveis de ambiente para o processo `docker compose` em si.
        // Crucial para a substituição de variáveis no arquivo docker-compose.yml.
        if let Some(vars) = env_vars_for_command {
            for (key, value) in vars {
                command.env(key, value);
                debug!("Definindo ENV para comando docker-compose: {}={}", key, value);
            }
        }

        debug!("Executando comando Docker Compose: {:?}", command);

        let mut child =
            command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().with_context(|| {
                format!(
                    "Falha ao iniciar comando 'docker compose {:?}' para projeto '{}'",
                    args,
                    self.project_name()
                )
            })?;

        // Capturar stdout e stderr para logging (útil para depuração)
        let stdout_output_shared = Arc::new(Mutex::new(Vec::new()));
        let stderr_output_shared = Arc::new(Mutex::new(Vec::new()));

        if let Some(stdout) = child.stdout.take() {
            let stdout_clone = stdout_output_shared.clone();
            let project_name_clone = self.project_name().to_string(); // Clonar para mover para a thread
            std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line_result in reader.lines() {
                    match line_result {
                        Ok(line) => {
                            trace!("[Compose STDOUT {}]: {}", project_name_clone, line);
                            if let Ok(mut guard) = stdout_clone.lock() {
                                guard.push(line);
                            }
                        }
                        Err(e) => warn!(
                            "[Compose STDOUT {}]: Erro ao ler linha: {}",
                            project_name_clone, e
                        ),
                    }
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let stderr_clone = stderr_output_shared.clone();
            let project_name_clone = self.project_name().to_string(); // Clonar para mover para a thread
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line_result in reader.lines() {
                    match line_result {
                        Ok(line) => {
                            // Logar stderr do compose como WARN para destacá-lo
                            warn!("[Compose STDERR {}]: {}", project_name_clone, line);
                            if let Ok(mut guard) = stderr_clone.lock() {
                                guard.push(line);
                            }
                        }
                        Err(e) => warn!(
                            "[Compose STDERR {}]: Erro ao ler linha: {}",
                            project_name_clone, e
                        ),
                    }
                }
            });
        }

        let status = child.wait().with_context(|| {
            format!(
                "Falha ao esperar pelo comando 'docker compose {:?}' para projeto '{}'",
                args,
                self.project_name()
            )
        })?;

        if !status.success() {
            let stdout_log = stdout_output_shared.lock().unwrap_or_else(|e| e.into_inner()).join("\n");
            let stderr_log = stderr_output_shared.lock().unwrap_or_else(|e| e.into_inner()).join("\n");
            bail!(
                "Comando docker compose '{:?}' falhou para projeto '{}' com status: {}.\nSTDOUT:\n{}\nSTDERR:\n{}",
                args, self.project_name(), status, stdout_log, stderr_log
            );
        }
        Ok(status)
    }

    /// Inicia o ambiente Docker Compose, ativando perfis especificados e passando o
    /// nome do arquivo de configuração para o servidor MCP.
    ///
    /// # Arguments
    /// * `config_filename`: Nome do arquivo de configuração TOML (ex: "default.test.toml")
    ///   a ser usado pelo serviço MCP Server. Este arquivo deve estar em `tests/test_configs/`.
    /// * `active_profiles`: Opcional. Uma lista de nomes de perfis do Docker Compose a serem ativados.
    ///   Se `None` ou vazio, nenhum perfil específico é ativado (comportamento padrão do compose).
    ///
    /// # Returns
    /// `Result<()>` indicando sucesso ou falha.
    pub fn up(&self, config_filename: &str, active_profiles: Option<Vec<String>>) -> Result<()> {
        info!(
            "Iniciando ambiente Docker Compose para projeto: '{}', usando config: '{}', perfis ativos: {:?}",
            self.project_name(),
            config_filename,
            active_profiles.as_deref().unwrap_or_default() // Loga perfis de forma segura
        );

        // Caminho para o arquivo de configuração DENTRO do contêiner do servidor MCP.
        let mcp_config_path_in_container = format!("/app/test_configs/{}", config_filename);

        // Variável de ambiente a ser definida para o PROCESSO `docker compose up`.
        // O Docker Compose usará esta variável para substituir o placeholder
        // `${MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV}` no arquivo `docker-compose.test.yml`.
        let env_vars_for_compose_command_execution =
            vec![("MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV", mcp_config_path_in_container)];
        
        // Argumentos base para o comando `docker compose up`.
        let base_up_args: Vec<String> = 
            vec!["up", "-d", "--remove-orphans", "--force-recreate", "--build", "--wait"]
            .into_iter().map(String::from).collect();

        // Argumentos globais do Docker Compose (profiles)
        let mut global_args_owned: Vec<String> = Vec::new();
        
        // Adicionar argumentos de perfil se `active_profiles` for Some e não vazio.
        if let Some(profiles_to_activate) = &active_profiles {
            if !profiles_to_activate.is_empty() {
                for profile_name in profiles_to_activate {
                    global_args_owned.push("--profile".to_string());
                    global_args_owned.push(profile_name.clone());
                }
            }
        }
        
        // Converter para slice de &str para `run_compose_command`.
        let global_args_str_refs: Vec<&str> = 
            global_args_owned.iter().map(AsRef::as_ref).collect();
        let up_args_str_refs: Vec<&str> = 
            base_up_args.iter().map(AsRef::as_ref).collect();

        // Executar o comando `docker compose up` com os argumentos e ENVs apropriados.
        self.run_compose_command(
            &global_args_str_refs,
            &up_args_str_refs,
            Some(&env_vars_for_compose_command_execution),
        )
        .with_context(|| {
            format!(
                "Falha ao executar 'docker compose up' para projeto '{}' com config '{}' e perfis {:?}",
                self.project_name(),
                config_filename,
                active_profiles.as_deref().unwrap_or_default()
            )
        })?;

        info!(
            "Ambiente Docker Compose para projeto '{}' iniciado. Próximo passo: aguardar prontidão dos serviços.",
            self.project_name()
        );
        Ok(())
    }

    /// Derruba o ambiente Docker Compose.
    ///
    /// # Arguments
    /// * `remove_volumes`: Se `true`, remove os volumes nomeados associados ao projeto.
    pub fn down(&self, remove_volumes: bool) -> Result<()> {
        info!(
            "Derrubando ambiente Docker Compose para projeto: '{}' (remover volumes: {})",
            self.project_name(),
            remove_volumes
        );
        let mut args = vec!["down", "--remove-orphans"];
        if remove_volumes {
            args.push("-v"); // Remove volumes nomeados
            // Considerar remover --rmi local para acelerar teardown,
            // a menos que seja crucial para evitar acúmulo de imagens de teste.
            // args.push("--rmi");
            // args.push("local"); 
        }
        args.push("--timeout");
        args.push("30"); // Timeout para os contêineres pararem graciosamente

        // Definir variáveis de ambiente para evitar warnings do Docker Compose
        let env_vars_for_down_command = vec![
            ("MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV", "/app/test_configs/default.test.toml".to_string()),
            ("MCP_TYPEDB__ADDRESS", "typedb-server-it:1729".to_string()),
            ("TYPEDB_PASSWORD_TEST", "password".to_string()),
        ];

        match self.run_compose_command(&[], &args, Some(&env_vars_for_down_command)) {
            Ok(_) => info!(
                "Ambiente Docker Compose para projeto '{}' derrubado com sucesso.",
                self.project_name()
            ),
            Err(e) => {
                // Logar o erro, mas não propagar como pânico no Drop, pois pode mascarar o erro original do teste.
                error!(
                    "Erro ao derrubar ambiente Docker Compose para projeto '{}': {}. Pode ser necessário limpeza manual.",
                    self.project_name(),
                    e
                );
                return Err(e); // Ainda retornar o erro para que o chamador saiba
            }
        }
        Ok(())
    }

    // ... (outras funções como logs_all_services, get_service_host_port, stop_service, start_service, wait_for_service_healthy)
    // A função wait_for_service_healthy já parece robusta.
    // As funções stop_service e start_service podem precisar ser ajustadas para aceitar perfis
    // se quisermos parar/iniciar serviços que estão sob um perfil específico, mas para o
    // fluxo de teste principal, o `up` com perfis é o mais importante.

    /// Coleta e loga os logs de todos os serviços no ambiente Docker Compose.
    pub fn logs_all_services(&self) -> Result<()> {
        info!("Coletando logs para projeto: {}", self.project_name());
        let output = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(&self.compose_file_path)
            .arg("-p")
            .arg(self.project_name())
            .arg("logs")
            .arg("--no-color") // Para logs mais limpos
            .arg("--tail=all")  // Capturar todos os logs
            .arg("--timestamps")
            .output()
            .with_context(|| {
                format!(
                    "Falha ao executar 'docker compose logs' para projeto {}",
                    self.project_name()
                )
            })?;

        if !output.stdout.is_empty() {
            info!(
                "[Compose Logs STDOUT {}]:\n{}",
                self.project_name(),
                String::from_utf8_lossy(&output.stdout)
            );
        }
        if !output.stderr.is_empty() {
            warn!( // stderr do logs pode conter informações úteis, não necessariamente erros
                "[Compose Logs STDERR {}]:\n{}",
                self.project_name(),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        if !output.status.success() {
            bail!(
                "Comando 'docker compose logs' para projeto '{}' falhou com status {}. Verifique STDERR.",
                self.project_name(), output.status
            );
        }
        Ok(())
    }
    
    /// Obtém a porta do host mapeada para uma porta interna de um serviço Docker Compose.
    pub fn get_service_host_port(&self, service_name: &str, internal_port: u16) -> Result<u16> {
        debug!(
            "Obtendo porta mapeada para serviço '{}', porta interna {} no projeto '{}'",
            service_name,
            internal_port,
            self.project_name()
        );

        let output = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(&self.compose_file_path)
            .arg("-p")
            .arg(self.project_name())
            .arg("port")
            .arg(service_name)
            .arg(internal_port.to_string())
            .output()
            .with_context(|| {
                format!(
                    "Falha ao executar 'docker compose port {} {}' para projeto {}",
                    service_name,
                    internal_port,
                    self.project_name()
                )
            })?;

        if !output.status.success() {
            let stderr_output = String::from_utf8_lossy(&output.stderr);
            self.logs_all_services().unwrap_or_else(|log_err| {
                error!("Falha adicional ao coletar logs gerais após falha do 'port': {}", log_err);
            });
            bail!(
                "Comando 'docker compose port {} {}' falhou com status {} e stderr: {}",
                service_name,
                internal_port,
                output.status,
                stderr_output
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            self.logs_all_services().unwrap_or_else(|log_err| {
                error!("Falha ao coletar logs gerais após saída vazia do 'port': {}", log_err);
            });
            bail!(
                "Saída do comando 'docker compose port {} {}' está vazia. O serviço pode não estar expondo a porta, não estar rodando, ou o perfil não foi ativado.",
                service_name, internal_port
            );
        }

        stdout.rsplit_once(':')
            .and_then(|(_, port_str)| port_str.parse::<u16>().ok())
            .with_context(|| format!("Formato de saída inesperado do 'docker compose port': '{}'. Esperado 'IP:PORTA'.", stdout))
    }

    /// Para (stops) um serviço específico no ambiente Docker Compose.
    pub fn stop_service(&self, service_name: &str) -> Result<()> {
        info!("Parando serviço '{}' no projeto '{}'", service_name, self.project_name());
        self.run_compose_command(&[], &["stop", service_name], None)?;
        info!("Comando para parar serviço '{}' no projeto '{}' executado.", service_name, self.project_name());
        std::thread::sleep(Duration::from_secs(5)); // Dar tempo para o serviço parar
        Ok(())
    }

    /// Inicia (starts) um serviço específico previamente parado no ambiente Docker Compose.
    pub fn start_service(&self, service_name: &str) -> Result<()> {
        info!("Iniciando serviço parado '{}' no projeto '{}'", service_name, self.project_name());
        self.run_compose_command(&[], &["start", service_name], None)?;
        info!("Comando para iniciar serviço parado '{}' no projeto '{}' executado.", service_name, self.project_name());
        std::thread::sleep(Duration::from_secs(5)); // Dar tempo para o serviço iniciar
        Ok(())
    }
    
    /// Aguarda até que um serviço específico seja considerado saudável (via healthcheck Docker)
    /// ou esteja no estado "running" (se não houver healthcheck).
    pub async fn wait_for_service_healthy(
        &self,
        service_name: &str,
        timeout_duration: Duration,
    ) -> Result<()> {
        info!(
            "Aguardando serviço '{}' (projeto '{}') ficar saudável/rodando (timeout: {:?})",
            service_name,
            self.project_name(),
            timeout_duration
        );
        let start_time = Instant::now();
        let check_interval = Duration::from_secs(3);

        loop {
            if start_time.elapsed() >= timeout_duration {
                self.logs_all_services().unwrap_or_else(|e| error!("Erro ao obter logs durante timeout de wait_for_service_healthy: {}", e));
                bail!(
                    "Timeout esperando serviço '{}' (projeto '{}') ficar saudável/rodando.",
                    service_name,
                    self.project_name()
                );
            }

            // O nome do contêiner é geralmente <project_name>-<service_name>-<index>
            let _container_name_pattern_for_ps = format!("{}-{}-", self.project_name(), service_name);
            
            // Usar `docker compose ps --format json` para obter o status de forma estruturada
            let ps_output = Command::new("docker")
                .arg("compose")
                .arg("-f")
                .arg(&self.compose_file_path)
                .arg("-p")
                .arg(self.project_name())
                .arg("ps")
                .arg("--format")
                .arg("json")
                .arg(service_name) // Filtra pelo nome do serviço
                .output();

            let output_str = match &ps_output {
                Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
                Ok(out) => { // Comando executou, mas falhou (ex: serviço não existe se perfil não ativo)
                    debug!("'docker compose ps' para serviço '{}' falhou (status {}). Stderr: {}. Tentando novamente...", service_name, out.status, String::from_utf8_lossy(&out.stderr));
                    tokio::time::sleep(check_interval).await;
                    continue;
                }
                Err(e) => {
                    warn!("'docker compose ps' para serviço '{}' falhou ao executar: {}. Tentando novamente...", service_name, e);
                    tokio::time::sleep(check_interval).await;
                    continue;
                }
            };
            
            // `docker compose ps --format json` retorna um JSON por linha para cada contêiner do serviço
            // Para serviços com scale=1, haverá apenas uma linha.
            if output_str.trim().is_empty() {
                debug!("'docker compose ps' para serviço '{}' não retornou contêineres. O perfil pode não estar ativo ou o serviço ainda não foi criado. Tentando novamente...", service_name);
                tokio::time::sleep(check_interval).await;
                continue;
            }

            // Parsear o primeiro JSON (ou o único)
            if let Some(first_line) = output_str.lines().next() {
                 match serde_json::from_str::<serde_json::Value>(first_line) {
                    Ok(service_info) => {
                        let container_state = service_info.get("State").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                        let container_status = service_info.get("Status").and_then(|s| s.as_str()).unwrap_or("").to_lowercase(); // "Status" inclui health
                        
                        debug!("Serviço '{}' (projeto '{}') status do contêiner: '{}', Status field: '{}'", service_name, self.project_name(), container_state, container_status);

                        if container_state == "running" {
                            if container_status.contains("healthy") {
                                info!("Serviço '{}' (projeto '{}') está saudável (Status: {}).", service_name, self.project_name(), container_status);
                                return Ok(());
                            } else if !container_status.contains("starting") && !container_status.contains("unhealthy") {
                                // Se não tem healthcheck ou o healthcheck passou (e não é "starting")
                                info!("Serviço '{}' (projeto '{}') está rodando (Status: {}). Considerando pronto.", service_name, self.project_name(), container_status);
                                return Ok(());
                            } else if container_status.contains("unhealthy") {
                                 self.logs_all_services().unwrap_or_else(|e| error!("Erro ao obter logs durante unhealthy de wait_for_service_healthy: {}", e));
                                bail!("Serviço '{}' (projeto '{}') está unhealthy. Status: {}", service_name, self.project_name(), container_status);
                            }
                            // Se "starting" ou ainda não "healthy", continua no loop
                        } else if container_state == "exited" || container_state == "created" {
                             debug!("Serviço '{}' (projeto '{}') não está 'running'. State: '{}'. Aguardando...", service_name, self.project_name(), container_state);
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Falha ao parsear JSON do 'docker compose ps' para serviço '{}' (projeto '{}'): {}. Output: {}",
                            service_name, self.project_name(), e, first_line
                        );
                    }
                }
            } else {
                debug!("'docker compose ps --format json' para o serviço '{}' não retornou nenhuma linha JSON parseável. O serviço pode não estar ativo. Tentando novamente...", service_name);
            }
            tokio::time::sleep(check_interval).await;
        }
    }
}

impl Drop for DockerComposeEnv {
    fn drop(&mut self) {
        info!(
            "Limpando ambiente Docker Compose para projeto: '{}' (via Drop)",
            self.project_name()
        );
        if let Err(e) = self.down(true) { // Sempre remove volumes no Drop para testes limpos
            error!(
                "Falha ao derrubar o ambiente Docker Compose no drop para projeto '{}': {}. \
                Pode ser necessário limpar manualmente.",
                self.project_name(),
                e
            );
        } else {
            info!(
                "Ambiente Docker Compose para projeto '{}' derrubado com sucesso no drop.",
                self.project_name()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::constants; // Para usar constantes como DEFAULT_TEST_CONFIG_FILENAME
    use serial_test::serial; // Para garantir execução serial dos testes que manipulam Docker

    // Função helper para criar um docker-compose.test.yml mínimo para os testes deste módulo.
    // Nota: Para testes reais do Typedb-MCP-Server, usaremos o docker-compose.test.yml principal.
    fn create_minimal_compose_file_for_helper_tests() -> std::io::Result<tempfile::NamedTempFile> {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(file, "version: '3.8'")?;
        writeln!(file, "services:")?;
        writeln!(file, "  alpine-dummy-service:")?;
        writeln!(file, "    image: alpine:latest")?;
        writeln!(file, "    container_name: ${{COMPOSE_PROJECT_NAME}}-alpine-dummy")?; // Usar nome do projeto
        writeln!(file, "    command: [\"sh\", \"-c\", \"echo 'Dummy service for helper tests started. MCP_CONFIG_PATH_ENV_VAR=${{MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV}}' && sleep 30 && echo 'Dummy service for helper tests stopping'\"]")?;
        writeln!(file, "    ports:")?;
        writeln!(file, "      - \"12345:80\"")?; // Porta interna 80, para get_service_host_port
        writeln!(file, "    healthcheck:")?; // Healthcheck simples
        writeln!(file, "      test: [\"CMD-SHELL\", \"echo 'healthcheck for dummy' && exit 0\"]")?;
        writeln!(file, "      interval: 2s")?;
        writeln!(file, "      timeout: 1s")?;
        writeln!(file, "      retries: 3")?;
        writeln!(file, "      start_period: 1s")?;
        file.flush()?;
        Ok(file)
    }

    #[tokio::test]
    #[serial] // Garante que os testes Docker não rodem em paralelo e causem conflitos de nome/porta.
    async fn test_docker_compose_env_new_generates_unique_project_name() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let dummy_compose_file = create_minimal_compose_file_for_helper_tests().expect("Falha ao criar dummy compose file");
        let compose_path_str = dummy_compose_file.path().to_str().unwrap().to_string();

        let env1 = DockerComposeEnv::new(&compose_path_str, "test_prefix");
        let env2 = DockerComposeEnv::new(&compose_path_str, "test_prefix");
        assert_ne!(env1.project_name(), env2.project_name(), "Nomes de projeto deveriam ser únicos.");
        info!("Nome projeto 1: {}, Nome projeto 2: {}", env1.project_name(), env2.project_name());
    }
    
    #[tokio::test]
    #[serial]
    async fn test_docker_compose_env_up_down_cycle_with_minimal_service() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let dummy_compose_file = create_minimal_compose_file_for_helper_tests()?;
        let compose_path_str = dummy_compose_file.path().to_str().unwrap().to_string();

        info!("Iniciando teste test_docker_compose_env_up_down_cycle_with_minimal_service");
        let env = DockerComposeEnv::new(&compose_path_str, "hlp_cycle_min");
        
        // Testa `up`
        // Passando um nome de config fictício, e sem perfis ativos para este teste simples.
        env.up("dummy_config.toml", None) 
            .context("Falha no env.up() no teste de ciclo de vida com serviço mínimo")?;
        
        // Testa `wait_for_service_healthy`
        env.wait_for_service_healthy("alpine-dummy-service", Duration::from_secs(20))
            .await
            .context("Serviço alpine-dummy-service não ficou saudável")?;
        info!("Serviço alpine-dummy-service está saudável.");

        // Testa `get_service_host_port`
        let host_port = env.get_service_host_port("alpine-dummy-service", 80)
            .context("Falha ao obter porta mapeada para alpine-dummy-service")?;
        assert_eq!(host_port, 12345, "Porta mapeada para alpine-dummy-service incorreta.");
        info!("Porta do host para alpine-dummy-service:80 é {}", host_port);
        
        // `down` é chamado automaticamente pelo `Drop` trait.
        // Para testar explicitamente:
        // env.down(true).context("Falha no env.down() explícito")?;
        // info!("Ambiente Docker Compose derrubado explicitamente.");

        Ok(())
    }

    // Este teste depende do docker-compose.test.yml real e dos serviços definidos nele.
    // Pode ser mais lento.
    #[tokio::test]
    #[serial]
    #[ignore] // Ignorar por padrão, pois pode ser mais pesado e depende do setup completo.
    async fn test_real_services_up_down_and_port_retrieval() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        
        // Usa o arquivo docker-compose.test.yml real do projeto
        let compose_path_str = constants::DEFAULT_DOCKER_COMPOSE_TEST_FILE; 
        let env = DockerComposeEnv::new(compose_path_str, "hlp_real_svc");

        // Inicia com config default e perfil default para TypeDB
        env.up(constants::DEFAULT_TEST_CONFIG_FILENAME, Some(vec!["typedb_default".to_string(), "oauth_mock".to_string()]))
            .context("Falha ao executar 'up' com config default e perfil typedb_default")?;

        // Espera pelo TypeDB padrão
        env.wait_for_service_healthy(constants::TYPEDB_SERVICE_NAME, constants::DEFAULT_TYPEDB_READY_TIMEOUT)
            .await
            .with_context(|| format!("Serviço '{}' não ficou saudável", constants::TYPEDB_SERVICE_NAME))?;
        
        // Espera pelo Mock OAuth
        env.wait_for_service_healthy(constants::MOCK_OAUTH_SERVICE_NAME, constants::DEFAULT_MOCK_AUTH_READY_TIMEOUT)
            .await
            .with_context(|| format!("Serviço '{}' não ficou saudável", constants::MOCK_OAUTH_SERVICE_NAME))?;

        // Tenta obter a porta do TypeDB
        let typedb_host_port = env.get_service_host_port(constants::TYPEDB_SERVICE_NAME, constants::TYPEDB_INTERNAL_PORT)
            .with_context(|| format!("Falha ao obter porta para {}", constants::TYPEDB_SERVICE_NAME))?;
        assert_eq!(typedb_host_port, constants::TYPEDB_HOST_PORT);
        info!("Porta do TypeDB ({}) no host: {}", constants::TYPEDB_SERVICE_NAME, typedb_host_port);

        // `down` será chamado pelo Drop.
        Ok(())
    }
}