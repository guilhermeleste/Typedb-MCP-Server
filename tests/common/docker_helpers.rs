// tests/common/docker_helpers.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste

//! Utilitários para gerenciar ambientes Docker Compose para testes de integração.

use std::process::{Command, ExitStatus, Stdio}; // Removido: Path
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};
pub use anyhow::{Context, Result, bail}; // Adicionado anyhow

/// Gerencia um ambiente Docker Compose isolado para testes de integração.
///
/// Cada instância utiliza um nome de projeto único, sufixado com um UUID,
/// para permitir a execução paralela de testes sem conflitos de contêineres
/// ou redes.
#[derive(Debug)]
pub struct DockerComposeEnv {
    compose_file: String,
    project_name: String,
}

impl DockerComposeEnv {
    /// Cria uma nova instância de `DockerComposeEnv`.
    ///
    /// Inicializa a configuração para um ambiente Docker Compose, gerando um
    /// nome de projeto único baseado no prefixo fornecido e um UUID.
    ///
    /// # Argumentos
    ///
    /// * `compose_file_path`: Caminho para o arquivo `docker-compose.yml` a ser usado.
    /// * `project_name_prefix`: Prefixo para o nome do projeto Docker Compose. Um UUID
    ///   será anexado a este prefixo para garantir unicidade.
    ///
    /// # Retorna
    ///
    /// Uma nova instância de `DockerComposeEnv`.
    pub fn new(compose_file_path: &str, project_name_prefix: &str) -> Self {
        let unique_suffix = uuid::Uuid::new_v4().simple().to_string();
        let project_name = format!("{}_{}", project_name_prefix, unique_suffix);
        info!("Criando DockerComposeEnv para o projeto: {} usando o arquivo: {}", project_name, compose_file_path);
        DockerComposeEnv {
            compose_file: compose_file_path.to_string(),
            project_name,
        }
    }

    fn run_compose_command(&self, args: &[&str], env_vars: Option<&[(&str, &str)]>) -> Result<ExitStatus> {
        let mut command = Command::new("docker");
        command.arg("compose"); // Adiciona o subcomando "compose"
        command
            .arg("-f")
            .arg(&self.compose_file)
            .arg("-p")
            .arg(&self.project_name);
        
        command.args(args);

        if let Some(vars) = env_vars {
            for (key, value) in vars {
                command.env(key, value);
            }
        }

        debug!("Executando comando docker-compose: {:?}", command);

        let child_result = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        let mut child = match child_result {
            Ok(c) => c,
            Err(e) => {
                let err_msg = format!("Falha ao iniciar docker-compose com args '{:?}': {}", args, e);
                error!("{}", err_msg);
                return Err(anyhow::anyhow!(err_msg));
            }
        };

        let mut stdout_lines = Vec::new();
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        debug!("[Compose STDOUT {}]: {}", self.project_name, l);
                        stdout_lines.push(l);
                    }
                    Err(e) => warn!("Erro lendo stdout do compose: {}",e),
                }
            }
        }
        
        let mut stderr_lines = Vec::new();
        if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                 match line {
                    Ok(l) => {
                        warn!("[Compose STDERR {}]: {}", self.project_name, l);
                        stderr_lines.push(l);
                    }
                    Err(e) => warn!("Erro lendo stderr do compose: {}",e),
                }
            }
        }

        let status = child.wait()?;
        
        if !status.success() {
            let err_msg = format!(
                "Comando docker-compose '{:?}' falhou para o projeto '{}' com status: {}.\nSTDOUT:\n{}\nSTDERR:\n{}",
                args, self.project_name, status, stdout_lines.join("\n"), stderr_lines.join("\n")
            );
            error!("{}", err_msg);
            // self.logs_all_services().ok(); // logs_all_services já loga, não precisa aqui
            return Err(anyhow::anyhow!(err_msg));
        }
        Ok(status)
    }

    /// Inicia o ambiente Docker Compose.
    ///
    /// Executa `docker-compose up -d --remove-orphans --force-recreate --build`.
    /// Garante que os contêineres sejam recriados e que os órfãos sejam removidos.
    ///
    /// # Retorna
    ///
    /// `Result<()>` indicando sucesso ou falha na inicialização do ambiente.
    pub fn up(&self) -> Result<()> {
        info!("Iniciando ambiente Docker Compose para o projeto: {}", self.project_name);
        self.run_compose_command(&["up", "-d", "--remove-orphans", "--force-recreate", "--build"], None)?; // Adicionado --build
        Ok(())
    }
    
    /// Inicia o ambiente Docker Compose com variáveis de ambiente personalizadas.
    ///
    /// Similar a `up()`, mas permite a passagem de variáveis de ambiente específicas
    /// para o comando `docker-compose up`.
    ///
    /// # Argumentos
    ///
    /// * `env_vars`: Um slice de tuplas `(&str, &str)` representando as variáveis
    ///   de ambiente (chave, valor) a serem definidas para o comando.
    ///
    /// # Retorna
    ///
    /// `Result<()>` indicando sucesso ou falha na inicialização do ambiente.
    pub fn up_with_envs(&self, env_vars: &[(&str, &str)]) -> Result<()> {
        info!("Iniciando ambiente Docker Compose para o projeto: {} com ENVs", self.project_name);
        self.run_compose_command(&["up", "-d", "--remove-orphans", "--force-recreate", "--build"], Some(env_vars))?;  // Adicionado --build
        Ok(())
    }

    /// Derruba o ambiente Docker Compose.
    ///
    /// Executa `docker-compose down`.
    ///
    /// # Argumentos
    ///
    /// * `remove_volumes`: Se `true`, adiciona a flag `-v` para remover os volumes
    ///   associados aos contêineres.
    ///
    /// # Retorna
    ///
    /// `Result<()>` indicando sucesso ou falha ao derrubar o ambiente.
    pub fn down(&self, remove_volumes: bool) -> Result<()> {
        info!("Derrubando ambiente Docker Compose para o projeto: {} (remover volumes: {})", self.project_name, remove_volumes);
        let mut args = vec!["down"];
        if remove_volumes {
            args.push("-v");
        }
        args.push("--remove-orphans");
        self.run_compose_command(&args, None)?;
        Ok(())
    }

    /// Pausa um serviço específico no ambiente Docker Compose.
    ///
    /// Executa `docker-compose pause <service_name>`.
    ///
    /// # Argumentos
    ///
    /// * `service_name`: O nome do serviço a ser pausado.
    ///
    /// # Retorna
    ///
    /// `Result<()>` indicando sucesso ou falha ao pausar o serviço.
    pub fn pause_service(&self, service_name: &str) -> Result<()> {
        info!("Pausando serviço '{}' no projeto '{}'", service_name, self.project_name);
        self.run_compose_command(&["pause", service_name], None)?;
        Ok(())
    }

    /// Retoma (unpauses) um serviço específico previamente pausado no ambiente Docker Compose.
    ///
    /// Executa `docker-compose unpause <service_name>`.
    ///
    /// # Argumentos
    ///
    /// * `service_name`: O nome do serviço a ser retomado.
    ///
    /// # Retorna
    ///
    /// `Result<()>` indicando sucesso ou falha ao retomar o serviço.
    pub fn unpause_service(&self, service_name: &str) -> Result<()> {
        info!("Retomando serviço '{}' no projeto '{}'", service_name, self.project_name);
        self.run_compose_command(&["unpause", service_name], None)?;
        Ok(())
    }
    
    /// Para (stops) um serviço específico no ambiente Docker Compose.
    ///
    /// Executa `docker-compose stop <service_name>`.
    ///
    /// # Argumentos
    ///
    /// * `service_name`: O nome do serviço a ser parado.
    ///
    /// # Retorna
    ///
    /// `Result<()>` indicando sucesso ou falha ao parar o serviço.
    pub fn stop_service(&self, service_name: &str) -> Result<()> {
        info!("Parando serviço '{}' no projeto '{}'", service_name, self.project_name);
        self.run_compose_command(&["stop", service_name], None)?;
        Ok(())
    }

    /// Coleta e exibe os logs de todos os serviços no ambiente Docker Compose.
    ///
    /// Executa `docker-compose logs --no-color --tail=200`.
    /// Os logs são enviados para a saída de tracing como `info` (STDOUT) ou `warn` (STDERR).
    ///
    /// # Retorna
    ///
    /// `Result<()>` indicando sucesso ou falha na coleta e exibição dos logs.
    pub fn logs_all_services(&self) -> Result<()> {
        info!("Coletando logs para o projeto: {}", self.project_name);
        let output = Command::new("docker")
            .arg("compose") // Adiciona o subcomando "compose"
            .arg("-f")
            .arg(&self.compose_file)
            .arg("-p")
            .arg(&self.project_name)
            .arg("logs")
            .arg("--no-color")
            // Considerar aumentar o --tail se necessário para depuração mais profunda
            .arg("--tail=250") // Aumentado para 250 linhas
            .output()
            .context(format!("Falha ao executar 'docker-compose logs' para o projeto {}", self.project_name))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stdout.trim().is_empty() {
                info!("[Compose Logs STDOUT {}]:\n{}", self.project_name, stdout);
            }
            if !stderr.trim().is_empty() {
                warn!("[Compose Logs STDERR {}]:\n{}", self.project_name, stderr);
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                "Erro ao coletar logs para o projeto {}: {}. Status: {}. Stderr: {}",
                self.project_name,
                output.status,
                output.status.code().unwrap_or(-1), // Adicionado para logar o código de saída
                stderr
            );
            // Retornar erro se o comando de logs falhar, pode indicar um problema maior.
            return Err(anyhow::anyhow!(
                "Falha ao coletar logs para o projeto {}. Status: {}. Stderr: {}",
                self.project_name, output.status, stderr
            ));
        }
        Ok(())
    }

    /// Obtém a porta do host mapeada para uma porta interna de um serviço específico.
    ///
    /// Executa `docker compose -p <project_name> -f <compose_file> port <service_name> <internal_port>`
    /// e parseia a saída para extrair a porta do host.
    ///
    /// # Argumentos
    ///
    /// * `service_name`: O nome do serviço Docker Compose.
    /// * `internal_port`: A porta interna do contêiner para a qual a porta do host foi mapeada.
    ///
    /// # Retorna
    ///
    /// `Result<u16>` contendo a porta do host mapeada, ou um erro se a porta não puder ser determinada.
    pub fn get_service_port(&self, service_name: &str, internal_port: u16) -> Result<u16> {
        debug!(
            "Obtendo porta mapeada para o serviço '{}', porta interna {} no projeto '{}'",
            service_name, internal_port, self.project_name
        );

        let output = Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(&self.compose_file)
            .arg("-p")
            .arg(&self.project_name)
            .arg("port")
            .arg(service_name)
            .arg(internal_port.to_string())
            .output()
            .context(format!(
                "Falha ao executar \'docker compose port {} {}\' para o projeto {}",
                service_name, internal_port, self.project_name
            ))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                "Erro ao obter porta para o serviço '{}': {}. Stderr: {}",
                service_name, output.status, stderr
            );
            bail!(
                "Comando 'docker compose port {} {}' falhou com status {} e stderr: {}",
                service_name, internal_port, output.status, stderr
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            // Adiciona logs antes de derrubar o ambiente para ajudar na depuração
            warn!("Saída do comando 'docker compose port' está vazia para {} porta {}. Tentando coletar logs gerais.", service_name, internal_port);
            self.logs_all_services().unwrap_or_else(|e| {
                error!("Falha ao coletar logs de depuração adicionais: {}", e);
            });
            bail!(
                "Saída do comando 'docker compose port {} {}' está vazia. O serviço pode não estar expondo a porta corretamente ou não estar rodando.",
                service_name, internal_port
            );
        }

        // A saída é geralmente no formato "0.0.0.0:PORTA" ou ":::PORTA" (para IPv6)
        match stdout.rsplit_once(':') {
            Some((_, port_str)) => {
                match port_str.parse::<u16>() {
                    Ok(port) => {
                        info!(
                            "Porta mapeada para o serviço '{}', porta interna {}: {}",
                            service_name, internal_port, port
                        );
                        Ok(port)
                    }
                    Err(e) => {
                        error!(
                            "Falha ao parsear a porta '{}' da saída '{}': {}",
                            port_str, stdout, e
                        );
                        bail!("Falha ao parsear a porta '{}' da saída '{}': {}", port_str, stdout, e)
                    }
                }
            }
            None => {
                error!("Formato de saída inesperado do 'docker compose port': {}", stdout);
                bail!("Formato de saída inesperado do 'docker compose port': {}", stdout)
            }
        }
    }

    /// Aguarda até que um serviço específico no ambiente Docker Compose seja considerado saudável.
    ///
    /// Verifica o status de saúde do contêiner do serviço em intervalos regulares.
    /// Se o serviço tiver um healthcheck configurado, aguarda o status "healthy".
    /// Se não tiver healthcheck, aguarda o status "running".
    ///
    /// # Argumentos
    ///
    /// * `service_name`: O nome do serviço a ser monitorado.
    /// * `timeout_duration`: A duração máxima de espera antes de retornar um erro de timeout.
    ///
    /// # Retorna
    ///
    /// `Result<()>`:
    /// * `Ok(())` se o serviço atingir o estado desejado dentro do timeout.
    /// * `Err(...)` se ocorrer timeout, o serviço ficar "unhealthy", ou houver falha
    ///   ao inspecionar o contêiner.
    pub async fn wait_for_service_healthy(
        &self,
        service_name: &str,
        timeout_duration: Duration,
    ) -> Result<()> { 
        info!("Aguardando serviço \'{}\' ficar saudável no projeto \'{}\' (timeout: {:?})", service_name, self.project_name, timeout_duration);
        let start_time = Instant::now();
        let check_interval = Duration::from_secs(2);

        loop {
            if start_time.elapsed() >= timeout_duration {
                let err_msg = format!("Timeout esperando pelo serviço \'{}\' no projeto \'{}\' ficar saudável.", service_name, self.project_name);
                error!("{}", err_msg);
                self.logs_all_services().ok(); 
                bail!(err_msg); 
            }

            let output = Command::new("docker")
                .arg("compose") 
                .arg("-f")
                .arg(&self.compose_file)
                .arg("-p")
                .arg(&self.project_name)
                .arg("ps")
                .arg("-q")
                .arg(service_name)
                .output()
                .context(format!("Falha ao executar 'docker-compose ps -q {}'", service_name))?;


            if !output.status.success() || output.stdout.is_empty() {
                warn!("Serviço '{}' não encontrado ou 'docker-compose ps' falhou. Tentando novamente...", service_name);
                tokio::time::sleep(check_interval).await;
                continue;
            }

            let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if container_id.is_empty() {
                warn!("ID do contêiner para o serviço \'{}\' está vazio. Tentando novamente...", service_name);
                tokio::time::sleep(check_interval).await;
                continue;
            }

            let health_output = Command::new("docker")
                .arg("inspect")
                .arg("--format")
                .arg("{{json .State}}") 
                .arg(&container_id)
                .output()
                .context(format!("Falha ao executar \'docker inspect\' para o container ID \'{}\'", container_id))?;

            if health_output.status.success() {
                let state_json_str = String::from_utf8_lossy(&health_output.stdout);
                debug!("Estado JSON completo para serviço \'{}\' (ID: {}): {}", service_name, container_id, state_json_str);

                match serde_json::from_str::<serde_json::Value>(&state_json_str) {
                    Ok(state_value) => {
                        let health_status = state_value.get("Health").and_then(|h| h.get("Status")).and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                        let container_status = state_value.get("Status").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                        
                        debug!("Status de saúde extraído para serviço '{}' (ID: {}): '{}', Status do contêiner: '{}'", service_name, container_id, health_status, container_status);

                        if health_status == "healthy" {
                            info!("Serviço '{}' está saudável (health_status: healthy) no projeto '{}'.", service_name, self.project_name);
                            return Ok(());
                        }
                        
                        if health_status == "unhealthy" {
                             let health_log_details = state_value.get("Health")
                                .and_then(|h| h.get("Log"))
                                .map_or_else(
                                    || "N/A".to_string(),
                                    |l_arr| l_arr.as_array().map_or_else(
                                        || "N/A".to_string(),
                                        |logs| logs.iter()
                                            .filter_map(|log_entry| log_entry.get("Output"))
                                            .filter_map(|output| output.as_str())
                                            .collect::<Vec<&str>>()
                                            .join("\n") // Usar \n para nova linha literal no log, não \\n
                                    )
                                );
                            let err_msg = format!(
                                "Serviço '{}' no projeto '{}' está unhealthy. Log de Healthcheck: {}",
                                service_name, self.project_name, health_log_details
                            );
                            error!("{}", err_msg);
                            self.logs_all_services().ok();
                            bail!(err_msg);
                        }

                        // Se health_status não é 'healthy' nem 'unhealthy'
                        if container_status == "running" {
                            // Caso especial para typedb-server-it que tem healthcheck: disable: true no compose
                            if service_name == "typedb-server-it" {
                                info!("Serviço '{}' (typedb-server-it) está rodando (container_status: running) e seu healthcheck no compose está desabilitado. Considerando pronto. Projeto: '{}'.", service_name, self.project_name);
                                return Ok(());
                            }

                            // Lógica refinada para outros serviços (incluindo typedb-mcp-server-it)
                            if health_status.is_empty() { // Health.Status é "" ou Health não existe
                                // Sem healthcheck definido ou ativo pela imagem/compose, ou ainda não reportou status.
                                // Se está rodando, consideramos pronto.
                                info!("Serviço '{}' está rodando (container_status: running) e Health.Status está vazio. Considerando pronto. Projeto: '{}'.", service_name, self.project_name);
                                return Ok(());
                            } else if health_status == "starting" {
                                debug!("Serviço '{}' (ID: {}) está rodando, Health.Status é 'starting'. Contêiner: '{}'. Aguardando healthcheck se tornar 'healthy'...", service_name, container_id, container_status);
                                // Continua no loop para esperar ficar 'healthy'
                            } else {
                                // Health.Status é algo diferente de "", "starting", "healthy", "unhealthy".
                                // Indica um healthcheck ativo que ainda não passou ou um estado inesperado.
                                debug!("Serviço '{}' (ID: {}) está rodando, Health.Status é '{}'. Contêiner: '{}'. Aguardando healthcheck se tornar 'healthy'...", service_name, container_id, health_status, container_status);
                                // Continua no loop
                            }
                        } else {
                             debug!("Serviço '{}' (ID: {}) não está 'running'. Saúde: '{}', Contêiner: '{}'. Aguardando...", service_name, container_id, health_status, container_status);
                        }
                    },
                    Err(e) => {
                        warn!("Falha ao parsear JSON do estado do contêiner \'{}\' (ID: {}): {}. Output: {}", service_name, container_id, e, state_json_str);
                    }
                }
            } else {
                warn!("Falha ao inspecionar saúde do contêiner \'{}\' (ID: {}). Stderr: {}", service_name, container_id, String::from_utf8_lossy(&health_output.stderr));
            }

            tokio::time::sleep(check_interval).await;
        }
    }
}

impl Drop for DockerComposeEnv {
    fn drop(&mut self) {
        info!("Limpando ambiente Docker Compose para o projeto: {} (via Drop)", self.project_name);
        // Tenta derrubar o ambiente, mas não falha o teste se `drop` falhar.
        // Opcionalmente, pode-se decidir se `remove_volumes` deve ser true ou false aqui.
        // Por padrão, para limpeza, `true` é geralmente melhor em testes.
        if let Err(e) = self.down(true) { // remove_volumes = true
            error!("Falha ao derrubar o ambiente Docker Compose no drop para o projeto {}: {}", self.project_name, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_compose_env_creation() {
        let _env = DockerComposeEnv::new("caminho/para/docker-compose.yml", "teste_projeto");
        // Adicione asserções conforme necessário para verificar a criação do ambiente
    }

    // Adicione mais testes conforme necessário
}