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
use super::constants;

// Contador global para garantir sufixos de nome de projeto únicos
static PROJECT_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Gerencia um ambiente Docker Compose isolado para testes de integração.
#[derive(Debug)]
pub struct DockerComposeEnv {
    compose_file_path: String,
    project_name: String,
}

impl DockerComposeEnv {
    /// Cria uma nova instância de `DockerComposeEnv`.
    pub fn new(compose_file_path: &str, project_name_prefix: &str) -> Self {
        let unique_id = PROJECT_COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
        let unique_suffix = format!("{}_{:03}", uuid::Uuid::new_v4().as_simple(), unique_id);

        let sanitized_prefix = project_name_prefix
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>();

        let mut project_name = format!("{}_{}", sanitized_prefix, unique_suffix);

        const MAX_PROJECT_NAME_LEN: usize = 40;
        if project_name.len() > MAX_PROJECT_NAME_LEN {
            project_name.truncate(MAX_PROJECT_NAME_LEN);
        }
        project_name = project_name.trim_end_matches(|c| c == '-' || c == '_').to_string();

        info!(
            "Criando DockerComposeEnv para projeto: '{}' usando arquivo: '{}'",
            project_name, compose_file_path
        );
        DockerComposeEnv {
            compose_file_path: compose_file_path.to_string(),
            project_name,
        }
    }

    /// Retorna o nome do projeto Docker Compose gerenciado por esta instância.
    pub fn project_name(&self) -> &str {
        &self.project_name
    }

    /// Executa um comando `docker compose` com os argumentos fornecidos.
    fn run_compose_command(&self, args: &[&str], env_vars: Option<&[(&str, String)]>) -> Result<ExitStatus> {
        let mut command = Command::new("docker");
        command.arg("compose");
        command
            .arg("-f")
            .arg(&self.compose_file_path)
            .arg("-p")
            .arg(self.project_name());

        command.args(args);

        if let Some(vars) = env_vars {
            for (key, value) in vars {
                command.env(key, value);
            }
        }

        debug!("Executando comando Docker Compose: {:?}", command);

        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("Falha ao iniciar docker compose com args '{:?}' para projeto '{}'", args, self.project_name()))?;

        let stdout_output_shared = Arc::new(Mutex::new(Vec::new()));
        let stderr_output_shared = Arc::new(Mutex::new(Vec::new()));

        if let Some(stdout) = child.stdout.take() {
            let stdout_clone = stdout_output_shared.clone();
            let project_name_clone = self.project_name().to_string();
            std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    match line {
                        Ok(l) => {
                            trace!("[Compose STDOUT {}]: {}", project_name_clone, l);
                            if let Ok(mut guard) = stdout_clone.lock() { guard.push(l); }
                        }
                        Err(e) => warn!("[Compose STDOUT {}]: Erro lendo linha: {}", project_name_clone, e),
                    }
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let stderr_clone = stderr_output_shared.clone();
            let project_name_clone = self.project_name().to_string();
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                     match line {
                        Ok(l) => {
                            warn!("[Compose STDERR {}]: {}", project_name_clone, l);
                             if let Ok(mut guard) = stderr_clone.lock() { guard.push(l); }
                        }
                        Err(e) => warn!("[Compose STDERR {}]: Erro lendo linha: {}", project_name_clone, e),
                    }
                }
            });
        }

        let status = child.wait().with_context(|| format!("Falha ao esperar pelo comando docker compose '{:?}' para projeto '{}'", args, self.project_name()))?;

        if !status.success() {
            let stdout_log = stdout_output_shared.lock().unwrap().join("\n");
            let stderr_log = stderr_output_shared.lock().unwrap().join("\n");
            bail!(
                "Comando docker compose '{:?}' falhou para projeto '{}' com status: {}.\nSTDOUT:\n{}\nSTDERR:\n{}",
                args, self.project_name(), status, stdout_log, stderr_log
            );
        }
        Ok(status)
    }

    /// Inicia o ambiente Docker Compose.
    pub fn up(&self, config_filename: &str) -> Result<()> {
        info!(
            "Iniciando ambiente Docker Compose para projeto: '{}', config: '{}'",
            self.project_name(), config_filename
        );
        let mcp_config_path_in_container = format!("/app/test_configs/{}", config_filename);
        let envs = [("MCP_CONFIG_PATH", mcp_config_path_in_container)];
        let env_vars_owned: Vec<(&str, String)> = envs.iter().map(|(k, v)| (*k, v.to_string())).collect();

        self.run_compose_command(
            &["up", "-d", "--remove-orphans", "--force-recreate", "--build", "--wait"],
            Some(&env_vars_owned),
        )?;
        info!("Ambiente Docker Compose para projeto '{}' iniciado e aguardando prontidão.", self.project_name());
        Ok(())
    }

    /// Derruba o ambiente Docker Compose.
    pub fn down(&self, remove_volumes: bool) -> Result<()> {
        info!(
            "Derrubando ambiente Docker Compose para projeto: '{}' (remover volumes: {})",
            self.project_name(), remove_volumes
        );
        let mut args = vec!["down", "--remove-orphans"];
        if remove_volumes {
            args.push("-v");
            args.push("--rmi");
            args.push("local");
        }
        args.push("--timeout");
        args.push("30");

        match self.run_compose_command(&args, None) {
            Ok(_) => info!("Ambiente Docker Compose para projeto '{}' derrubado com sucesso.", self.project_name()),
            Err(e) => {
                error!("Erro ao derrubar ambiente Docker Compose para projeto '{}': {}. Pode ser necessário limpeza manual.", self.project_name(), e);
                return Err(e);
            }
        }
        Ok(())
    }

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
            .arg("--no-color")
            .arg("--tail=500")
            .arg("--timestamps")
            .output()
            .with_context(|| format!("Falha ao executar 'docker compose logs' para projeto {}", self.project_name()))?;

        if !output.stdout.is_empty() {
            info!("[Compose Logs STDOUT {}]:\n{}", self.project_name(), String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            warn!("[Compose Logs STDERR {}]:\n{}", self.project_name(), String::from_utf8_lossy(&output.stderr));
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
            service_name, internal_port, self.project_name()
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
            .with_context(|| format!("Falha ao executar 'docker compose port {} {}' para projeto {}", service_name, internal_port, self.project_name()))?;

        if !output.status.success() {
            let stderr_output = String::from_utf8_lossy(&output.stderr);
            self.logs_all_services().unwrap_or_else(|log_err| {
                error!("Falha adicional ao coletar logs gerais após falha do 'port': {}", log_err);
            });
            bail!(
                "Comando 'docker compose port {} {}' falhou com status {} e stderr: {}",
                service_name, internal_port, output.status, stderr_output
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            self.logs_all_services().unwrap_or_else(|log_err| {
                error!("Falha ao coletar logs gerais após saída vazia do 'port': {}", log_err);
            });
            bail!(
                "Saída do comando 'docker compose port {} {}' está vazia. O serviço pode não estar expondo a porta ou não estar rodando.",
                service_name, internal_port
            );
        }

        stdout.rsplit_once(':')
            .and_then(|(_, port_str)| port_str.parse::<u16>().ok())
            .with_context(|| format!("Formato de saída inesperado do 'docker compose port': '{}'. Esperado 'IP:PORTA'.", stdout))
    }

    /// Para (stops) um serviço específico no ambiente Docker Compose.
    ///
    /// Executa `docker compose stop <service_name>`.
    pub fn stop_service(&self, service_name: &str) -> Result<()> {
        info!(
            "Parando serviço '{}' no projeto '{}'",
            service_name, self.project_name()
        );
        self.run_compose_command(&["stop", service_name], None)?;
        info!(
            "Comando para parar serviço '{}' no projeto '{}' executado com sucesso.",
            service_name, self.project_name()
        );
        // Aguardar um pouco para garantir que o serviço tenha tempo de parar.
        // Este é um tempo arbitrário e pode precisar de ajuste ou de uma verificação mais robusta.
        std::thread::sleep(Duration::from_secs(3));
        Ok(())
    }

    /// Inicia (starts) um serviço específico previamente parado no ambiente Docker Compose.
    ///
    /// Executa `docker compose start <service_name>`.
    /// Nota: Isto não reconstrói o contêiner, apenas inicia um existente.
    /// Se o serviço não existir (ex: após um `down -v`), este comando falhará.
    /// O método `up()` é mais adequado para garantir que o serviço esteja criado e rodando.
    pub fn start_service(&self, service_name: &str) -> Result<()> {
        info!(
            "Iniciando serviço parado '{}' no projeto '{}'",
            service_name, self.project_name()
        );
        self.run_compose_command(&["start", service_name], None)?;
        info!(
            "Comando para iniciar serviço parado '{}' no projeto '{}' executado com sucesso.",
            service_name, self.project_name()
        );
        // Aguardar um pouco para o serviço iniciar. Healthchecks devem ser usados para confirmar prontidão.
        std::thread::sleep(Duration::from_secs(3));
        Ok(())
    }


    /// Aguarda até que um serviço específico seja considerado saudável (via healthcheck) ou esteja no estado "running".
    pub async fn wait_for_service_healthy(&self, service_name: &str, timeout_duration: Duration) -> Result<()> {
        info!(
            "Aguardando serviço '{}' (projeto '{}') ficar saudável/rodando (timeout: {:?})",
            service_name, self.project_name(), timeout_duration
        );
        let start_time = Instant::now();
        let check_interval = Duration::from_secs(3);

        loop {
            if start_time.elapsed() >= timeout_duration {
                self.logs_all_services().ok();
                bail!(
                    "Timeout esperando serviço '{}' (projeto '{}') ficar saudável/rodando.",
                    service_name, self.project_name()
                );
            }

            let container_name_for_inspect = format!("{}-{}-1", self.project_name(), service_name);

            let output_result = Command::new("docker")
                .arg("inspect")
                .arg("--format")
                .arg("{{json .State}}")
                .arg(&container_name_for_inspect)
                .output();
            
            let output = match output_result {
                Ok(out) => out,
                Err(e) => {
                     warn!("'docker inspect' para serviço '{}' (contêiner: {}) falhou ao executar: {}. Tentando novamente...", service_name, container_name_for_inspect, e);
                     tokio::time::sleep(check_interval).await;
                     continue;
                }
            };

            if !output.status.success() {
                // Este caso é comum se o contêiner ainda não foi criado pelo `docker compose up`.
                // Continuar tentando até o timeout.
                debug!("'docker inspect' para serviço '{}' (contêiner: {}) falhou (status não sucesso). Stderr: {}. Tentando novamente...", service_name, container_name_for_inspect, String::from_utf8_lossy(&output.stderr));
                tokio::time::sleep(check_interval).await;
                continue;
            }

            let state_json_str = String::from_utf8_lossy(&output.stdout);
            if state_json_str.trim().is_empty() || state_json_str.trim() == "null" {
                 debug!("'docker inspect' para serviço '{}' (contêiner: {}) retornou JSON vazio ou nulo. Tentando novamente...", service_name, container_name_for_inspect);
                 tokio::time::sleep(check_interval).await;
                 continue;
            }
            trace!("Estado JSON para serviço '{}' (contêiner {}): {}", service_name, container_name_for_inspect, state_json_str);

            match serde_json::from_str::<serde_json::Value>(&state_json_str) {
                Ok(state_value) => {
                    let container_status = state_value.get("Status").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                    
                    if container_status != "running" {
                        debug!("Serviço '{}' (projeto '{}', contêiner '{}') não está 'running'. Status: '{}'. Aguardando...", service_name, self.project_name(), container_name_for_inspect, container_status);
                        tokio::time::sleep(check_interval).await;
                        continue;
                    }

                    if let Some(health_info) = state_value.get("Health") {
                        // Se Health for null, significa que não há healthcheck configurado.
                        if health_info.is_null() {
                             info!("Serviço '{}' (projeto '{}', contêiner '{}') está rodando e não possui healthcheck definido via Dockerfile/Compose. Considerando pronto.", service_name, self.project_name(), container_name_for_inspect);
                            return Ok(());
                        }
                        let health_status = health_info.get("Status").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                        debug!("Serviço '{}' (projeto '{}', contêiner '{}') status do contêiner: '{}', health_status: '{}'", service_name, self.project_name(), container_name_for_inspect, container_status, health_status);

                        if health_status == "healthy" {
                            info!("Serviço '{}' (projeto '{}', contêiner '{}') está saudável (health_status: healthy).", service_name, self.project_name(), container_name_for_inspect);
                            return Ok(());
                        }
                        if health_status == "unhealthy" {
                            self.logs_all_services().ok();
                            bail!(
                                "Serviço '{}' (projeto '{}', contêiner '{}') está unhealthy. Health Log: {:?}",
                                service_name, self.project_name(), container_name_for_inspect, health_info.get("Log")
                            );
                        }
                        // Se "starting", continua no loop
                    } else {
                        // Sem campo "Health", se está "running", consideramos pronto.
                        info!("Serviço '{}' (projeto '{}', contêiner '{}') está rodando e não possui campo 'Health' no inspect. Considerando pronto.", service_name, self.project_name(), container_name_for_inspect);
                        return Ok(());
                    }
                }
                Err(e) => {
                    warn!(
                        "Falha ao parsear JSON do estado do serviço '{}' (projeto '{}', contêiner '{}'): {}. Output: {}",
                        service_name, self.project_name(), container_name_for_inspect, e, state_json_str
                    );
                }
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
        if let Err(e) = self.down(true) {
            error!(
                "Falha ao derrubar o ambiente Docker Compose no drop para projeto '{}': {}. \
                Pode ser necessário limpar manualmente.",
                self.project_name(), e
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
    use reqwest::StatusCode;
    use serial_test::serial; 

    fn create_dummy_compose_file_for_helper_tests() -> std::io::Result<tempfile::NamedTempFile> {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(file, "version: '3.8'")?;
        writeln!(file, "services:")?;
        writeln!(file, "  alpine-dummy-service:")?;
        writeln!(file, "    image: alpine:latest")?;
        writeln!(file, "    command: [\"sh\", \"-c\", \"echo 'Dummy service for helper tests started' && sleep 5 && echo 'Dummy service for helper tests stopping' && exit 0\"]")?;
        writeln!(file, "    ports:")?;
        writeln!(file, "      - \"12345:80\"")?;
        writeln!(file, "    healthcheck:")?;
        writeln!(file, "      test: [\"CMD-SHELL\", \"echo 'healthcheck for dummy' && exit 0\"]")?;
        writeln!(file, "      interval: 2s")?;
        writeln!(file, "      timeout: 1s")?;
        writeln!(file, "      retries: 3")?;
        writeln!(file, "      start_period: 1s")?;
        file.flush()?;
        Ok(file)
    }

    #[tokio::test]
    #[serial]
    async fn test_docker_compose_env_new_and_drop_cycle() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init(); 
        let dummy_compose_file = create_dummy_compose_file_for_helper_tests()?;
        let compose_path_str = dummy_compose_file.path().to_str().unwrap().to_string();

        info!("Iniciando teste test_docker_compose_env_new_and_drop_cycle");
        {
            let env = DockerComposeEnv::new(&compose_path_str, "hlp_drop_test");
             env.up(constants::DEFAULT_TEST_CONFIG_FILENAME)
                 .context("Falha no env.up() no teste de ciclo de vida")?;
            info!("DockerComposeEnv para '{}' criado e 'up', será derrubado pelo Drop.", env.project_name());
            tokio::time::sleep(Duration::from_secs(2)).await;
        } 
        info!("Teste test_docker_compose_env_new_and_drop_cycle concluído.");
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore] 
    async fn test_docker_compose_up_down_port_and_healthy_and_start_stop() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        
        let compose_path_str = constants::DEFAULT_DOCKER_COMPOSE_TEST_FILE;
        let env = DockerComposeEnv::new(compose_path_str, "hlp_full_ops_test");

        env.up(constants::DEFAULT_TEST_CONFIG_FILENAME)
            .context("Falha ao executar 'up' no teste completo do helper")?;

        env.wait_for_service_healthy(constants::MOCK_OAUTH_SERVICE_NAME, Duration::from_secs(45))
            .await
            .with_context(|| format!("Serviço '{}' não ficou saudável após up", constants::MOCK_OAUTH_SERVICE_NAME))?;

        let host_port = env.get_service_host_port(constants::MOCK_OAUTH_SERVICE_NAME, constants::MOCK_OAUTH_INTERNAL_PORT)
            .with_context(|| format!("Falha ao obter porta mapeada para '{}'", constants::MOCK_OAUTH_SERVICE_NAME))?;
        
        assert_eq!(host_port, constants::MOCK_OAUTH_HOST_PORT, "Porta mapeada para mock-oauth-server não corresponde à esperada.");

        // Testar stop_service
        env.stop_service(constants::MOCK_OAUTH_SERVICE_NAME)
            .context("Falha ao parar o serviço mock-oauth2-server")?;
        info!("Serviço {} parado. Aguardando para confirmar.", constants::MOCK_OAUTH_SERVICE_NAME);
        // Verificar se o healthcheck falha ou o status é 'exited' (mais complexo de verificar robustamente sem `docker ps` parseado)
        // Uma forma simples é tentar acessar a porta (deve falhar) ou verificar se /livez falha.
        let livez_url = format!("http://localhost:{}/livez", constants::MOCK_OAUTH_HOST_PORT);
        let client = reqwest::Client::new();
        let resp_after_stop = client.get(&livez_url).send().await;
        assert!(resp_after_stop.is_err() || resp_after_stop.unwrap().status() != StatusCode::OK, 
            "Serviço {} ainda está respondendo após stop.", constants::MOCK_OAUTH_SERVICE_NAME);
        info!("Serviço {} não está respondendo após stop, como esperado.", constants::MOCK_OAUTH_SERVICE_NAME);


        // Testar start_service
        env.start_service(constants::MOCK_OAUTH_SERVICE_NAME)
            .context("Falha ao iniciar o serviço mock-oauth2-server")?;
        info!("Serviço {} iniciado. Aguardando healthcheck.", constants::MOCK_OAUTH_SERVICE_NAME);
        
        env.wait_for_service_healthy(constants::MOCK_OAUTH_SERVICE_NAME, Duration::from_secs(30))
            .await
            .with_context(|| format!("Serviço '{}' não ficou saudável após start", constants::MOCK_OAUTH_SERVICE_NAME))?;
        info!("Serviço {} saudável após start.", constants::MOCK_OAUTH_SERVICE_NAME);


        env.down(true).context("Falha ao executar 'down' no teste completo do helper")?;
        Ok(())
    }
}