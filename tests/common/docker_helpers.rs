    /// Executa um comando docker-compose com variáveis de ambiente customizadas.
    ///
    /// Permite passar envs extras para o processo docker-compose (ex: para parametrizar OAuth/JWKS).
    pub fn run_command_with_env(&self, args: &[&str], envs: &[(&str, &str)]) -> Result<Output> {
        let command_str = format!(
            "docker-compose -f {} -p {} {} (envs: {:?})",
            self.compose_file_path.to_string_lossy(),
            self.project_name,
            args.join(" "),
            envs
        );
        tracing::info!("Executando comando Docker Compose com envs: {}", command_str);

        let mut cmd = Command::new("docker-compose");
        cmd.arg("-f")
            .arg(&self.compose_file_path)
            .arg("-p")
            .arg(&self.project_name)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let output = cmd.output()?;
        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            tracing::error!(
                "Comando Docker Compose falhou. stdout: {}, stderr: {}",
                stdout,
                stderr
            );
            Err(DockerHelperError::CommandFailed { command: command_str, stdout, stderr })
        } else {
            tracing::debug!(
                "Comando Docker Compose bem-sucedido. stdout: {}, stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(output)
        }
    }
// tests/common/docker_helpers.rs
//! Fornece utilitários para interagir com Docker e Docker Compose em testes.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::process::Command as TokioCommand;
use tracing::instrument;
use uuid::Uuid;

/// Erros que podem ocorrer ao interagir com o Docker.
#[derive(Error, Debug)]
pub enum DockerHelperError {
    /// Indica que um comando Docker Compose falhou.
    #[error("Comando Docker Compose falhou: {command}, stdout: {stdout}, stderr: {stderr}")]
    CommandFailed {
        command: String,
        stdout: String,
        stderr: String,
    },
    /// Indica que o tempo limite foi atingido ao esperar que um serviço ficasse saudável.
    #[error("Timeout esperando pelo serviço {service_name} ficar saudável: {elapsed:?} (limite: {timeout:?})")]
    HealthCheckTimeout {
        service_name: String,
        timeout: Duration,
        last_status: Option<bool>, // None se não houve healthcheck ou erro ao obtê-lo
    },
    #[error("Serviço '{0}' não encontrado ou não está em execução.")]
    ServiceNotFound(String),
    #[error("Command '{command}' failed with exit code {exit_code:?}. Stdout: '{stdout}'. Stderr: '{stderr}'")]
    ExecCommandFailed {
        service: String,
        command: String,
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
    },

    /// Error indicating that a requested port is not mapped or the service is not running.
    #[error("Port {internal_port} for service '{service}' is not mapped or the service is not running/accessible.")]
    PortNotMapped {
        service: String,
        internal_port: u16,
    },

    /// Error indicating that the `docker-compose port` command failed.
    #[error("Failed to query port {internal_port} for service '{service}': {error_message}")]
    PortQueryFailed {
        service: String,
        internal_port: u16,
        error_message: String,
    },
}

/// Alias para `Result` com `DockerHelperError`.
pub type Result<T> = std::result::Result<T, DockerHelperError>;

/// Representa um ambiente Docker Compose gerenciável.
///
/// Esta estrutura fornece métodos para iniciar, parar e verificar a saúde
/// dos serviços definidos em um arquivo `docker-compose.yml`.
///
/// Implementa `Drop` para garantir que `docker-compose down` seja chamado
/// quando a instância sai de escopo, limpando os recursos.
#[derive(Debug)]
pub struct DockerComposeEnv {
    compose_file_path: PathBuf,
    project_name: String,
}

impl DockerComposeEnv {

    /// Obtém o código de saída do processo principal do container de um serviço.
    ///
    /// Retorna Ok(i32) com o ExitCode, ou erro se não for possível determinar.
    #[tracing::instrument(skip(self), name="get_service_exit_code", fields(project=%self.project_name, service=%service_name))]
    pub fn get_service_exit_code(&self, service_name: &str) -> Result<i32> {
        // Obtém o container_id do serviço
        let output = self.run_command(&["ps", "-q", service_name])?;
        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if container_id.is_empty() {
            tracing::warn!("Serviço '{}' não encontrado ou não está rodando sob o projeto '{}'.", service_name, self.project_name);
            return Err(DockerHelperError::ServiceNotFound(service_name.to_string()));
        }

        // Executa docker inspect para obter o ExitCode
        let inspect_output = std::process::Command::new("docker")
            .args(["inspect", "--format={{.State.ExitCode}}", &container_id])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()?;

        if !inspect_output.status.success() {
            let stderr = String::from_utf8_lossy(&inspect_output.stderr).into_owned();
            tracing::error!("Falha ao inspecionar ExitCode do container '{}' (serviço '{}'): {}", container_id, service_name, stderr);
            return Err(DockerHelperError::CommandFailed {
                command: format!("docker inspect --format={{.State.ExitCode}} {}", container_id),
                stdout: String::from_utf8_lossy(&inspect_output.stdout).into_owned(),
                stderr,
            });
        }

        let exit_code_str = String::from_utf8_lossy(&inspect_output.stdout).trim().to_string();
        match exit_code_str.parse::<i32>() {
            Ok(code) => Ok(code),
            Err(e) => {
                tracing::error!("Falha ao converter ExitCode '{}' para i32: {}", exit_code_str, e);
                Err(DockerHelperError::CommandFailed {
                    command: format!("docker inspect --format={{.State.ExitCode}} {}", container_id),
                    stdout: exit_code_str,
                    stderr: format!("Erro de parse: {}", e),
                })
            }
        }
    }
    /// Cria uma nova instância para gerenciar um arquivo docker-compose específico.
    ///
    /// `compose_file` é o caminho para o arquivo `docker-compose.yml`.
    /// `project_name_prefix` é usado para prefixar containers e redes,
    /// permitindo a execução de múltiplos ambientes de teste em paralelo. Um sufixo
    /// UUID curto é adicionado para garantir unicidade.
    pub fn new(compose_file: impl AsRef<Path>, project_name_prefix: &str) -> Self {
        let unique_suffix = Uuid::new_v4().to_string()[..8].to_string();
        DockerComposeEnv {
            compose_file_path: compose_file.as_ref().to_path_buf(),
            project_name: format!("{}_{}", project_name_prefix, unique_suffix),
        }
    }

    /// Executa um comando `docker-compose` com os argumentos fornecidos.
    ///
    /// Internamente, adiciona `-f <compose_file_path>` e `-p <project_name>`
    /// aos argumentos.
    fn run_command(&self, args: &[&str]) -> Result<Output> {
        let command_str = format!(
            "docker-compose -f {} -p {} {}",
            self.compose_file_path.to_string_lossy(),
            self.project_name,
            args.join(" ")
        );
        tracing::info!("Executando comando Docker Compose: {}", command_str);

        let output = Command::new("docker-compose")
            .arg("-f")
            .arg(&self.compose_file_path)
            .arg("-p")
            .arg(&self.project_name)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            tracing::error!(
                "Comando Docker Compose falhou. stdout: {}, stderr: {}",
                stdout,
                stderr
            );
            Err(DockerHelperError::CommandFailed { command: command_str, stdout, stderr })
        } else {
            tracing::debug!(
                "Comando Docker Compose bem-sucedido. stdout: {}, stderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(output)
        }
    }

    /// Inicia os serviços definidos no arquivo compose.
    ///
    /// Executa `docker-compose up -d --build --remove-orphans`.
    /// O `--remove-orphans` garante que containers de execuções anteriores
    /// com o mesmo nome de projeto (improvável devido ao sufixo UUID) sejam removidos.
    #[tracing::instrument(skip(self), name="docker_compose_up", fields(project=%self.project_name))]
    pub fn up(&self) -> Result<()> {
        self.run_command(&["up", "-d", "--build", "--remove-orphans"])?;
        Ok(())
    }

    /// Para e remove os containers e redes. Opcionalmente remove volumes anônimos.
    ///
    /// Executa `docker-compose down --remove-orphans`.
    /// Se `remove_volumes` for `true`, adiciona `-v` para remover volumes anônimos.
    #[tracing::instrument(skip(self), name="docker_compose_down", fields(project=%self.project_name, remove_volumes=%remove_volumes))]
    pub fn down(&self, remove_volumes: bool) -> Result<()> {
        let mut args = vec!["down", "--remove-orphans"];
        if remove_volumes {
            args.push("-v");
        }
        self.run_command(&args)?;
        Ok(())
    }

    /// Verifica o status de saúde de um serviço específico definido no Docker Compose.
    ///
    /// Retorna `Ok(true)` se o serviço está saudável, `Ok(false)` se não está saudável
    /// ou não possui health check, e `Err` em caso de falha ao inspecionar.
    #[tracing::instrument(skip(self), name="check_service_health", fields(project=%self.project_name, service=%service_name))]
    pub fn is_service_healthy(&self, service_name: &str) -> Result<bool> {
        // Primeiro, obtemos o ID do container para o serviço.
        let output = self.run_command(&["ps", "-q", service_name])?;
        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if container_id.is_empty() {
            tracing::warn!("Serviço '{}' não encontrado ou não está rodando sob o projeto '{}'.", service_name, self.project_name);
            // Consideramos não encontrado como não saudável, mas poderia ser um erro específico.
            // Para simplificar, retornamos um erro claro.
            return Err(DockerHelperError::ServiceNotFound { service_name: service_name.to_string() });
        }

        // Agora, inspecionamos o container diretamente com o comando docker.
        let inspect_output = Command::new("docker")
            .args([
                "inspect",
                // Formato para obter o status de saúde. Se não houver healthcheck, .State.Health pode ser nulo.
                // Se .State.Health for nulo, {{if .State.Health}}...{{else}}...{{end}} retorna a parte do else.
                // Usamos "unknown" para indicar que não há healthcheck ou o estado não pôde ser determinado dessa forma.
                "--format={{if .State.Health}}{{.State.Health.Status}}{{else}}no_healthcheck{{end}}",
                &container_id,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;
        
        if !inspect_output.status.success() {
            let stderr = String::from_utf8_lossy(&inspect_output.stderr).into_owned();
            tracing::error!("Falha ao inspecionar container '{}' (serviço '{}'): {}", container_id, service_name, stderr);
            return Err(DockerHelperError::ParseError(format!(
                "Falha ao inspecionar container '{}' (serviço '{}'): {}",
                container_id, service_name, stderr
            )));
        }

        let health_status = String::from_utf8_lossy(&inspect_output.stdout).trim().to_string();
        tracing::debug!("Status de saúde para o serviço '{}' (container {}): {}", service_name, container_id, health_status);
        
        if health_status == "no_healthcheck" {
            tracing::warn!("Serviço '{}' (container {}) não possui um healthcheck configurado. Considerando como 'não saudável' para fins de espera.", service_name, container_id);
            return Ok(false);
        }
        
        Ok(health_status == "healthy")
    }

    /// Espera até que um serviço específico se torne saudável.
    ///
    /// Verifica o status de saúde do serviço em intervalos regulares (`poll_interval`)
    /// até que o serviço se torne saudável ou o `timeout` seja atingido.
    #[tracing::instrument(skip(self), name="wait_for_healthy_service", fields(project=%self.project_name, service=%service_name))]
    pub async fn wait_for_service_healthy(
        &self,
        service_name: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<()> {
        let start_time = Instant::now();
        tracing::info!(
            "Aguardando serviço '{}' ficar saudável (timeout: {:?}, poll: {:?})...",
            service_name,
            timeout,
            poll_interval
        );

        loop {
            match self.is_service_healthy(service_name) {
                Ok(true) => {
                    tracing::info!("Serviço '{}' está saudável (depois de {:?}).", service_name, start_time.elapsed());
                    return Ok(());
                }
                Ok(false) => {
                    // Continua no loop
                }
                Err(DockerHelperError::ServiceNotFound { .. }) => {
                    // Se o serviço não for encontrado, é um erro e não devemos continuar esperando.
                    tracing::error!("Serviço '{}' não encontrado ao tentar esperar por saúde.", service_name);
                    return Err(DockerHelperError::ServiceNotFound{ service_name: service_name.to_string()});
                }
                Err(e) => {
                    // Outros erros ao verificar a saúde também devem interromper a espera.
                    tracing::error!("Erro ao verificar saúde do serviço '{}': {:?}", service_name, e);
                    return Err(e);
                }
            }
            
            if start_time.elapsed() >= timeout {
                tracing::error!(
                    "Timeout ({:?}) esperando pelo serviço '{}' ficar saudável. Último status verificado: (ver logs anteriores).",
                    timeout,
                    service_name
                );
                return Err(DockerHelperError::HealthCheckTimeout {
                    service_name: service_name.to_string(),
                    elapsed: start_time.elapsed(),
                    timeout,
                });
            }
            tokio::time::sleep(poll_interval).await;
            tracing::debug!("Ainda esperando pelo serviço '{}' ficar saudável... ({:?} decorridos)", service_name, start_time.elapsed());
        }
    }
    
    /// Coleta os logs (stdout e stderr) de um serviço específico.
    ///
    /// Útil para depuração em caso de falhas de teste.
    #[tracing::instrument(skip(self), name="get_service_logs", fields(project=%self.project_name, service=%service_name))]
    pub fn get_service_logs(&self, service_name: &str) -> Result<String> {
        // O comando 'logs' pode falhar se o serviço não existir ou não tiver produzido logs.
        // É importante verificar se o serviço existe primeiro, ou tratar o erro de 'run_command'.
        // Para simplificar, vamos assumir que o serviço existe se esta função for chamada.
        // Se 'run_command' falhar (ex: serviço não existe), ele retornará DockerHelperError::CommandFailed.
        let output = self.run_command(&["logs", service_name])?;
        
        // Logs podem ir para stdout ou stderr dependendo da configuração do compose e do serviço.
        let stdout_logs = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr_logs = String::from_utf8_lossy(&output.stderr).into_owned();

        // Se ambos estiverem vazios, pode indicar que o serviço não produziu output ou não foi encontrado.
        // No entanto, um serviço pode legitimamente não ter logs.
        if stdout_logs.is_empty() && stderr_logs.is_empty() {
            tracing::warn!("Nenhum log (stdout/stderr) capturado para o serviço '{}' no projeto '{}'.", service_name, self.project_name);
        }

        Ok(format!(
            "--- STDOUT for service {} (project {}) ---
{}
--- STDERR for service {} (project {}) ---
{}",
            service_name, self.project_name, stdout_logs,
            service_name, self.project_name, stderr_logs
        ))
    }

    /// Retorna o nome do projeto Docker Compose.
    pub fn project_name(&self) -> &str {
        &self.project_name
    }

    /// Retorna o caminho do arquivo Docker Compose.
    pub fn compose_file_path(&self) -> &Path {
        &self.compose_file_path
    }

    /// Executa um comando dentro de um serviço específico do ambiente Docker Compose.
    ///
    /// # Argumentos
    /// * `service_name` - O nome do serviço conforme definido no arquivo docker-compose.yml.
    /// * `command_and_args` - Uma slice de strings onde o primeiro elemento é o comando
    ///   e os elementos subsequentes são seus argumentos.
    ///
    /// # Retorna
    /// `Ok(String)` contendo o `stdout` do comando se bem-sucedido (exit code 0).
    /// `Err(DockerHelperError::ExecCommandFailed)` se o comando falhar (exit code != 0)
    /// ou se houver um erro ao executar o comando `docker-compose exec`.
    /// `Err(DockerHelperError::CommandFailed)` se o próprio comando `docker-compose` falhar
    /// por outras razões.
    /// `Err(DockerHelperError::OutputDecodingError)` se a saída não puder ser decodificada.
    #[instrument(skip(self, command_and_args), fields(service=%service_name, project_name=%self.project_name(), command=command_and_args.join(" ")))]
    pub async fn exec_in_service(
        &self,
        service_name: &str,
        command_and_args: &[&str],
    ) -> Result<String, DockerHelperError> {
        if command_and_args.is_empty() {
            return Err(DockerHelperError::ExecCommandFailed {
                service: service_name.to_string(),
                command: "".to_string(),
                exit_code: None,
                stdout: "".to_string(),
                stderr: "Nenhum comando fornecido para exec_in_service.".to_string(),
            });
        }

        let command_str = command_and_args.join(" ");
        tracing::debug!(
            "Executando comando no serviço '{}': {}",
            service_name,
            command_str
        );

        let mut cmd = Command::new("docker-compose");
        cmd.arg("-p")
            .arg(&self.project_name)
            .arg("-f")
            .arg(&self.compose_file_path)
            .arg("exec")
            .arg("-T") // Desabilita pseudo-TTY, importante para captura de stdout/stderr
            .arg(service_name);

        for arg in command_and_args {
            cmd.arg(arg);
        }
        
        tracing::trace!("Comando docker-compose a ser executado: {:?}", cmd);

        let output = cmd.output().map_err(|e| DockerHelperError::IoError(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        if output.status.success() {
            tracing::debug!(
                "Comando '{}' no serviço '{}' executado com sucesso. Stdout: {}",
                command_str,
                service_name,
                stdout
            );
            Ok(stdout)
        } else {
            tracing::warn!(
                "Falha ao executar comando '{}' no serviço '{}'. Exit code: {:?}, Stderr: {}, Stdout: {}",
                command_str,
                service_name,
                output.status.code(),
                stderr,
                stdout
            );
            Err(DockerHelperError::ExecCommandFailed {
                service: service_name.to_string(),
                command: command_str,
                exit_code: output.status.code(),
                stdout,
                stderr,
            })
        }
    }

    /// Recupera a porta do host mapeada para a porta interna de um serviço.
    ///
    /// Esta função executa `docker-compose port <service_name> <internal_port>`
    /// para determinar o mapeamento.
    ///
    /// # Argumentos
    ///
    /// * `service_name`: O nome do serviço no arquivo Docker Compose.
    /// * `internal_port`: A porta interna do serviço para a qual o mapeamento é solicitado.
    ///
    /// # Retorna
    ///
    /// * `Ok(u16)`: O número da porta do host se o mapeamento existir e for encontrado.
    /// * `Err(DockerHelperError::PortNotMapped)`: Se a porta não estiver mapeada, o serviço
    ///   não estiver em execução, ou o serviço não existir.
    /// * `Err(DockerHelperError::PortQueryFailed)`: Se o comando `docker-compose port`
    ///   falhar por outros motivos ou sua saída não puder ser analisada.
    /// * `Err(DockerHelperError::CommandFailed)`: Se o comando `docker-compose` não puder ser executado.
    ///
    /// # Exemplos
    ///
    /// ```no_run
    /// # use std::path::PathBuf;
    /// # use tokio::time::Duration;
    /// # // Assume DockerComposeEnv is in scope and properly initialized
    /// # use your_crate::DockerComposeEnv; // Placeholder for actual path
    /// #
    /// # async fn example(env: &DockerComposeEnv) -> Result<(), Box<dyn std::error::Error>> {
    /// // Assumes 'env' is an initialized DockerComposeEnv that has successfully run 'up()'
    /// // e 'my_web_server' is healthy and maps internal port 80.
    /// let host_port = env.get_service_mapped_port("my_web_server", 80).await?;
    /// println!("Host port for my_web_server:80 is {}", host_port);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(self), fields(service=%service_name, internal_port=%internal_port, project_name=%self.project_name()))]
    pub async fn get_service_mapped_port(
        &self,
        service_name: &str,
        internal_port: u16,
    ) -> Result<u16, DockerHelperError> {
        let compose_file_arg = self.compose_file_path().to_string_lossy();
        let project_name_arg = self.project_name();

        let mut cmd = Command::new("docker-compose");
        cmd.arg("-p")
            .arg(project_name_arg)
            .arg("-f")
            .arg(compose_file_arg.as_ref())
            .arg("port")
            .arg(service_name)
            .arg(internal_port.to_string());

        tracing::debug!(command = ?cmd, "Executing docker-compose port command");

        let output = cmd.output().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to execute docker-compose port command");
            DockerHelperError::CommandFailed {
                command: format!("{:?}", cmd),
                error_message: e.to_string(),
                stdout: String::new(),
                stderr: String::new(),
            }
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        tracing::debug!(stdout = %stdout, stderr = %stderr, status = ?output.status.code(), "docker-compose port command output");

        if !output.status.success() {
            tracing::warn!(
                "docker-compose port command failed for service '{}', port {}. Stderr: {}",
                service_name,
                internal_port,
                stderr
            );
            if stderr.contains("No container found") || stderr.contains("Can't find public port") || stderr.contains("No such service") {
                 return Err(DockerHelperError::PortNotMapped {
                    service: service_name.to_string(),
                    internal_port,
                });
            }

            return Err(DockerHelperError::PortQueryFailed {
                service: service_name.to_string(),
                internal_port,
                error_message: format!(
                    "docker-compose port command failed with status {:?} and stderr: '{}'. Stdout: '{}'",
                    output.status.code(),
                    stderr,
                    stdout
                ),
            });
        }

        if stdout.is_empty() {
            tracing::warn!(
                "docker-compose port command succeeded for service '{}', port {}, but stdout was empty. Assuming port not mapped.",
                service_name,
                internal_port
            );
            return Err(DockerHelperError::PortNotMapped {
                service: service_name.to_string(),
                internal_port,
            });
        }

        if let Some(port_str) = stdout.rsplit(':').next() {
            port_str.parse::<u16>().map_err(|e| {
                tracing::error!(error = %e, port_str = %port_str, full_stdout = %stdout, "Failed to parse mapped port");
                DockerHelperError::PortQueryFailed {
                    service: service_name.to_string(),
                    internal_port,
                    error_message: format!(
                        "Failed to parse mapped port from output '{}': {}. Full stdout: '{}'",
                        port_str, e, stdout
                    ),
                }
            })
        } else {
             tracing::error!(full_stdout = %stdout, "Unexpected output format from 'docker-compose port'");
            Err(DockerHelperError::PortQueryFailed {
                service: service_name.to_string(),
                internal_port,
                error_message: format!("Unexpected output format from 'docker-compose port': '{}'", stdout),
            })
        }
    }
}

impl Drop for DockerComposeEnv {
    /// Garante que `docker-compose down` seja chamado quando `DockerComposeEnv` sai de escopo.
    ///
    /// Por padrão, remove volumes anônimos para garantir uma limpeza completa.
    /// Isso é crucial para limpar os recursos do Docker (containers, redes, volumes)
    /// após a conclusão de um teste, mesmo em caso de pânico.
    fn drop(&mut self) {
        tracing::info!(
            "Executando 'docker-compose down -v --remove-orphans' para o projeto: {} (arquivo: {})", 
            self.project_name, self.compose_file_path.display()
        );
        // Por padrão, o Drop remove os volumes.
        if let Err(e) = self.down(true) {
            // Não entrar em pânico no drop, pois isso pode mascarar a causa original de um pânico no teste.
            // Apenas logar o erro é a prática recomendada.
            tracing::error!(
                "Falha ao executar 'docker-compose down' para o projeto '{}' na limpeza (Drop): {:?}",
                self.project_name,
                e
            );
        } else {
            tracing::info!("'docker-compose down' concluído com sucesso para o projeto: {}", self.project_name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::NamedTempFile; // Usado para criar um docker-compose.yml temporário

    // Helper para inicializar tracing para testes, se necessário.
    fn setup_tracing() {
        // Inicializa o subscriber para coletar logs do `tracing`.
        // `try_init` é usado para evitar pânico se já estiver inicializado.
        // Configuração básica para exibir logs no stdout.
        // Em projetos maiores, pode-se usar `env_filter` para controlar o nível de log.
        let subscriber = tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG) // Mostra logs DEBUG e acima
            .with_test_writer() // Escreve no output do teste de forma organizada
            .try_init();
        if subscriber.is_err() {
            tracing::debug!("tracing_subscriber já inicializado.");
        }
    }

    /// Testa o ciclo de vida básico de um ambiente Docker Compose, incluindo health check.
    ///
    /// Este teste requer um ambiente Docker funcional.
    /// Cria um arquivo `docker-compose.yml` temporário com:
    /// 1. Um serviço (`httpd_healthy`) que deve se tornar saudável.
    /// 2. Um serviço (`httpd_unhealthy`) com um healthcheck que deve falhar.
    ///
    /// `#[ignore]` é usado porque este é um teste de integração que depende de Docker
    /// e pode ser lento ou instável em CIs sem Docker configurado adequadamente.
    #[tokio::test]
    #[ignore] // Ignorar por padrão, pois requer Docker e um arquivo compose válido.
    async fn test_docker_compose_env_lifecycle_and_health_check() {
        setup_tracing(); // Para ver os logs do `tracing`

        // --- Teste com serviço que deve se tornar saudável ---
        let compose_content_healthy = r#"
version: '3.8'
services:
  httpd_healthy:
    image: "httpd:2.4" # Imagem com comportamento previsível
    ports:
      - "8097:80" # Porta aleatória para evitar conflitos
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"] # Verifica se o servidor está respondendo
      interval: 2s
      timeout: 1s
      retries: 5
      start_period: 3s # Dá um tempo para o container iniciar antes do primeiro check
"#;
        let mut temp_compose_healthy = NamedTempFile::new().expect("Falha ao criar tempfile para compose saudável");
        write!(temp_compose_healthy, "{}", compose_content_healthy).expect("Falha ao escrever no tempfile");
        temp_compose_healthy.flush().expect("Falha ao fazer flush no tempfile");

        let project_prefix_healthy = "mcp_test_h_ok";
        let env_healthy = DockerComposeEnv::new(temp_compose_healthy.path(), project_prefix_healthy);

        assert!(env_healthy.up().is_ok(), "docker-compose up para 'httpd_healthy' falhou");

        let healthy_service_name = "httpd_healthy";
        match env_healthy.wait_for_service_healthy(
            healthy_service_name,
            Duration::from_secs(30), // Timeout mais generoso para CI
            Duration::from_secs(2)
        ).await {
            Ok(_) => tracing::info!("Serviço '{}' ficou saudável como esperado.", healthy_service_name),
            Err(e) => panic!("Serviço '{}' não ficou saudável: {:?}", healthy_service_name, e),
        }

        // Testar get_service_logs para o serviço saudável
        match env_healthy.get_service_logs(healthy_service_name) {
            Ok(logs) => {
                assert!(!logs.is_empty(), "Logs do serviço '{}' não deveriam estar vazios", healthy_service_name);
                tracing::debug!("Logs do {}: {}", healthy_service_name, logs);
                assert!(logs.contains("AH00558: httpd: Could not reliably determine the server's fully qualified domain name"), "Log do httpd não contém mensagem esperada de inicialização");
            }
            Err(e) => {
                panic!("Falha ao obter logs de '{}': {:?}", healthy_service_name, e);
            }
        }
        // `down` com remove_volumes=true será chamado no Drop de `env_healthy`.


        // --- Teste com serviço que deve falhar o health check (timeout) ---
        let compose_content_unhealthy = r#"
version: '3.8'
services:
  httpd_unhealthy:
    image: "httpd:2.4"
    ports:
      - "8098:80"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/nonexistent-path-for-failure"] # Deve falhar
      interval: 1s
      timeout: 1s
      retries: 2 # Poucas retentativas para falhar mais rápido
      start_period: 1s
"#;
        let mut temp_compose_unhealthy = NamedTempFile::new().expect("Falha ao criar tempfile para compose não saudável");
        write!(temp_compose_unhealthy, "{}", compose_content_unhealthy).expect("Falha ao escrever no tempfile");
        temp_compose_unhealthy.flush().expect("Falha ao fazer flush no tempfile");

        let project_prefix_unhealthy = "mcp_test_h_fail";
        let env_unhealthy = DockerComposeEnv::new(temp_compose_unhealthy.path(), project_prefix_unhealthy);

        assert!(env_unhealthy.up().is_ok(), "docker-compose up para 'httpd_unhealthy' falhou");

        let unhealthy_service_name = "httpd_unhealthy";
        let res_wait_unhealthy = env_unhealthy.wait_for_service_healthy(
            unhealthy_service_name,
            Duration::from_secs(10), // Timeout curto para o teste
            Duration::from_secs(1)
        ).await;
        
        assert!(res_wait_unhealthy.is_err(), "Esperava-se um timeout para serviço não saudável ('{}'), mas obteve Ok", unhealthy_service_name);
        if let Err(DockerHelperError::HealthCheckTimeout { service_name, .. }) = res_wait_unhealthy {
            assert_eq!(service_name, unhealthy_service_name);
            tracing::info!("Timeout corretamente ocorrido para serviço não saudável '{}'.", unhealthy_service_name);
        } else {
            panic!("Erro inesperado ao esperar por serviço não saudável '{}': {:?}", unhealthy_service_name, res_wait_unhealthy);
        }
        // `down` com remove_volumes=true será chamado no Drop de `env_unhealthy`.


        // --- Teste com serviço sem health check configurado ---
        let compose_content_no_check = r#"
version: '3.8'
services:
  httpd_no_check:
    image: "httpd:2.4"
    ports:
      - "8099:80"
    # Sem healthcheck explícito aqui
"#;
        let mut temp_compose_no_check = NamedTempFile::new().expect("Falha ao criar tempfile para compose sem check");
        write!(temp_compose_no_check, "{}", compose_content_no_check).expect("Falha ao escrever no tempfile");
        temp_compose_no_check.flush().expect("Falha ao fazer flush no tempfile");
        
        let project_prefix_no_check = "mcp_test_h_no_chk";
        let env_no_check = DockerComposeEnv::new(temp_compose_no_check.path(), project_prefix_no_check);

        assert!(env_no_check.up().is_ok(), "docker-compose up para 'httpd_no_check' falhou");
        
        let no_check_service_name = "httpd_no_check";
        // is_service_healthy para um serviço sem healthcheck deve retornar Ok(false)
        match env_no_check.is_service_healthy(no_check_service_name) {
            Ok(false) => tracing::info!("Serviço '{}' (sem healthcheck) corretamente identificado como não-saudável para espera.", no_check_service_name),
            Ok(true) => panic!("Serviço '{}' (sem healthcheck) inesperadamente saudável.", no_check_service_name),
            Err(e) => panic!("Erro ao verificar saúde de '{}': {:?}", no_check_service_name, e),
        }

        // wait_for_service_healthy para um serviço sem healthcheck deve dar timeout
        let res_wait_no_check = env_no_check.wait_for_service_healthy(
            no_check_service_name,
            Duration::from_secs(5), // Timeout curto
            Duration::from_secs(1)
        ).await;
        assert!(res_wait_no_check.is_err(), "Esperava-se um timeout para serviço sem healthcheck ('{}'), mas obteve Ok", no_check_service_name);
         if let Err(DockerHelperError::HealthCheckTimeout { service_name, .. }) = res_wait_no_check {
            assert_eq!(service_name, no_check_service_name);
            tracing::info!("Timeout corretamente ocorrido para serviço sem healthcheck '{}'.", no_check_service_name);
        } else {
            panic!("Erro inesperado ao esperar por serviço sem healthcheck '{}': {:?}", no_check_service_name, res_wait_no_check);
        }

        // Test get_service_logs para o serviço sem healthcheck
        match env_no_check.get_service_logs(no_check_service_name) {
            Ok(logs) => {
                assert!(!logs.is_empty(), "Logs do serviço '{}' não deveriam estar vazios", no_check_service_name);
                tracing::debug!("Logs do {}: {}", no_check_service_name, logs);
                assert!(logs.contains("AH00558: httpd: Could not reliably determine the server's fully qualified domain name"), "Log do httpd (sem check) não contém mensagem esperada");
            }
            Err(e) => {
                panic!("Falha ao obter logs de '{}': {:?}", no_check_service_name, e);
            }
        }
        // `down` com remove_volumes=true será chamado no Drop de `env_no_check`.
    }

    // Testes para `exec_in_service`
    #[tokio::test]
    #[serial_test::serial]
    async fn test_docker_exec_in_service() {
        setup_tracing(); // Configura o tracing para este teste

        let project_prefix = "mcp_test_exec";
        let service_name = "alpine_exec_test";

        let compose_content = format!(
            r#"
version: '3.8'
services:
  {}:
    image: alpine:latest
    # Comando para manter o container rodando por um tempo para os testes
    command: ["sh", "-c", "echo 'Container started for exec test' && sleep 60"] 
"#,
            service_name
        );

        let mut temp_compose_file =
            NamedTempFile::new().expect("Falha ao criar tempfile para teste de exec");
        write!(temp_compose_file, "{}", compose_content)
            .expect("Falha ao escrever no tempfile de exec");
        temp_compose_file
            .flush()
            .expect("Falha ao fazer flush no tempfile de exec");

        let env = DockerComposeEnv::new(temp_compose_file.path(), project_prefix);

        // Iniciar os serviços
        match env.up() {
            Ok(_) => tracing::info!("Serviços para teste de exec iniciados com sucesso."),
            Err(e) => panic!("Falha ao iniciar serviços para teste de exec: {:?}", e),
        }
        
        // Esperar um pouco para o container alpine estar pronto (sleep no comando ajuda)
        tokio::time::sleep(Duration::from_secs(2)).await;


        // Cenário 1: Comando bem-sucedido
        let cmd_echo = ["echo", "hello from alpine"];
        match env.exec_in_service(service_name, &cmd_echo) {
            Ok(stdout) => {
                assert_eq!(stdout.trim(), "hello from alpine");
                tracing::info!("Comando echo bem-sucedido: {}", stdout.trim());
            }
            Err(e) => panic!(
                "exec_in_service com echo falhou inesperadamente: {:?}",
                e
            ),
        }

        // Cenário 2: Comando malsucedido (exit code != 0)
        let cmd_cat_nonexistent = ["cat", "/nonexistentfile"];
        match env.exec_in_service(service_name, &cmd_cat_nonexistent) {
            Err(DockerHelperError::ExecCommandFailed {
                service: sn,
                command: cmd,
                exit_code,
                stdout,
                stderr,
            }) => {
                assert_eq!(sn, service_name);
                assert_eq!(cmd, "cat /nonexistentfile");
                assert_eq!(exit_code, Some(1));
                assert!(stdout.is_empty() || stdout == "\n"); // Pode ter uma quebra de linha
                assert!(stderr.contains("No such file or directory"));
                tracing::info!("Comando cat /nonexistentfile falhou como esperado. Stderr: {}", stderr.trim());
            }
            Ok(out) => panic!(
                "exec_in_service com cat /nonexistentfile deveria ter falhado, mas retornou Ok: {}",
                out
            ),
            Err(e) => panic!(
                "exec_in_service com cat /nonexistentfile falhou com erro inesperado: {:?}",
                e
            ),
        }
        
        // Cenário 3: Comando que não existe no container
        let cmd_nonexistent_command = ["nonexistentcommand123"];
        match env.exec_in_service(service_name, &cmd_nonexistent_command) {
            Err(DockerHelperError::ExecCommandFailed {
                service: sn,
                command: cmd,
                exit_code,
                stderr,
                .. // stdout pode variar
            }) => {
                assert_eq!(sn, service_name);
                assert_eq!(cmd, "nonexistentcommand123");
                // O exit code para "command not found" pode variar (ex: 127 ou 1)
                // docker-compose exec pode retornar 1 se o comando não for encontrado dentro do container
                // ou o próprio shell do container pode retornar 127.
                // Vamos verificar se não é zero.
                assert_ne!(exit_code, Some(0), "Exit code deveria ser não-zero para comando não encontrado.");
                // A mensagem de erro também pode variar dependendo do shell dentro do alpine
                assert!(stderr.contains("not found") || stderr.contains("No such file or directory"));
                tracing::info!("Comando nonexistentcommand123 falhou como esperado. Stderr: {}", stderr.trim());
            }
            Ok(out) => panic!(
                "exec_in_service com nonexistentcommand123 deveria ter falhado, mas retornou Ok: {}",
                out
            ),
            Err(e) => panic!(
                "exec_in_service com nonexistentcommand123 falhou com erro inesperado: {:?}",
                e
            ),
        }

        // Cenário 4: Serviço não existente (docker-compose exec lida com isso)
        // O erro retornado será ExecCommandFailed porque o comando `docker-compose exec ...` em si falhará.
        let cmd_echo_on_bad_service = ["echo", "hello"];
        match env.exec_in_service("nonexistentservice", &cmd_echo_on_bad_service) {
             Err(DockerHelperError::ExecCommandFailed {
                service: sn,
                command: cmd,
                exit_code,
                stderr,
                .. 
            }) => {
                assert_eq!(sn, "nonexistentservice");
                assert_eq!(cmd, "echo hello");
                assert_ne!(exit_code, Some(0)); // docker-compose cli retorna não-zero
                assert!(stderr.to_lowercase().contains("no such service"));
                tracing::info!("Comando em serviço não existente falhou como esperado. Stderr: {}", stderr.trim());
            }
            Ok(out) => panic!(
                "exec_in_service em serviço não existente deveria ter falhado, mas retornou Ok: {}",
                out
            ),
            Err(e) => panic!(
                "exec_in_service em serviço não existente falhou com erro inesperado: {:?}",
                e
            ),
        }


        // Cenário 5: Nenhum comando fornecido
        match env.exec_in_service(service_name, &[]) {
            Err(DockerHelperError::ExecCommandFailed {
                service: sn,
                command: cmd,
                stderr,
                ..
            }) => {
                assert_eq!(sn, service_name);
                assert_eq!(cmd, "");
                assert!(stderr.contains("Nenhum comando fornecido"));
                 tracing::info!("exec_in_service sem comando falhou como esperado.");
            }
             Ok(out) => panic!(
                "exec_in_service sem comando deveria ter falhado, mas retornou Ok: {}",
                out
            ),
            Err(e) => panic!(
                "exec_in_service sem comando falhou com erro inesperado: {:?}",
                e
            ),
        }


        // Limpeza: `down` será chamado no Drop de `env`.
        // Certificar que o `down` é chamado explicitamente para testar a remoção de volumes, se necessário,
        // mas o Drop já faz `down(true)`.
    }

    mod port_tests {
        use super::super::{DockerComposeEnv, DockerHelperError}; // Acessa itens do escopo do arquivo
        use super::setup_tracing; // Acessa setup_tracing de `mod tests`

        use std::io::Write;
        use tempfile::NamedTempFile;
        use tokio::time::Duration;
        use tokio::process::Command as TokioCommand; // Alias para evitar conflito

        const DOCKER_COMPOSE_PORTS_TEST_CONTENT: &str = r#"
version: '3.8'
services:
  web_server_ports_test:
    image: httpd:2.4
    ports:
      - "80" # Mapeia a porta 80 do container para uma porta aleatória no host
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80"]
      interval: 2s
      timeout: 1s
      retries: 5
      start_period: 2s

  no_explicit_mapping_ports_test:
    image: httpd:2.4
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80"]
      interval: 2s
      timeout: 1s
      retries: 5
      start_period: 2s

  no_exposed_port_service_ports_test:
    image: alpine:latest
    command: ["sleep", "infinity"]
"#;

        #[tokio::test]
        #[serial_test::serial]
        async fn test_get_service_mapped_port_functionality() {
            setup_tracing();

            let mut temp_compose_file = NamedTempFile::new().expect("Failed to create temp compose file for port test");
            write!(temp_compose_file, "{}", DOCKER_COMPOSE_PORTS_TEST_CONTENT)
                .expect("Failed to write to temp compose file");
            temp_compose_file.flush().expect("Failed to flush temp compose file");

            let project_prefix = "mcp_ports_test";
            let env = DockerComposeEnv::new(temp_compose_file.path(), project_prefix);

            tracing::info!("Starting Docker environment for port testing...");
            if let Err(e) = env.up().await {
                panic!("docker-compose up failed for port testing: {:?}", e);
            }
            tracing::info!("Docker environment for port testing started.");

            let web_service_name = "web_server_ports_test";
            let no_mapping_service_name = "no_explicit_mapping_ports_test";
            let no_exposed_service_name = "no_exposed_port_service_ports_test";

            tracing::info!("Waiting for '{}' to become healthy...", web_service_name);
            if let Err(e) = env.wait_for_service_healthy(web_service_name, Duration::from_secs(30), Duration::from_secs(2)).await {
                 let logs = env.get_service_logs(web_service_name).await.unwrap_or_else(|_| "Failed to get logs".to_string());
                 panic!("Service '{}' did not become healthy: {:?}. Logs:\n{}", web_service_name, e, logs);
            }
            tracing::info!("'{}' is healthy.", web_service_name);

            tracing::info!("Waiting for '{}' to become healthy...", no_mapping_service_name);
             if let Err(e) = env.wait_for_service_healthy(no_mapping_service_name, Duration::from_secs(30), Duration::from_secs(2)).await {
                let logs = env.get_service_logs(no_mapping_service_name).await.unwrap_or_else(|_| "Failed to get logs".to_string());
                panic!("Service '{}' did not become healthy: {:?}. Logs:\n{}", no_mapping_service_name, e, logs);
            }
            tracing::info!("'{}' is healthy.", no_mapping_service_name);

            // 1. Teste: Obter porta mapeada com sucesso
            tracing::info!("Test 1: Get mapped port for '{}', internal port 80", web_service_name);
            match env.get_service_mapped_port(web_service_name, 80).await {
                Ok(mapped_port) => {
                    tracing::info!("Successfully retrieved mapped port for '{}': {} -> {}", web_service_name, 80, mapped_port);
                    assert!(mapped_port > 1023, "Mapped port should be in the ephemeral range");
                }
                Err(e) => panic!("Failed to get mapped port for '{}', internal port 80: {:?}", web_service_name, e),
            }

            // 2. Teste: Tentar obter porta interna não exposta/mapeada
            tracing::info!("Test 2: Attempt to get mapped port for '{}', internal port 81 (not exposed)", web_service_name);
            match env.get_service_mapped_port(web_service_name, 81).await {
                Err(DockerHelperError::PortNotMapped { service, internal_port }) => {
                    assert_eq!(service, web_service_name);
                    assert_eq!(internal_port, 81);
                    tracing::info!("Correctly identified port 81 for '{}' as not mapped.", web_service_name);
                }
                Ok(port) => panic!("Expected PortNotMapped error for unexposed port 81 on '{}', but got Ok({})", web_service_name, port),
                Err(e) => panic!("Expected PortNotMapped for unexposed port 81 on '{}', but got different error: {:?}", web_service_name, e),
            }

            // 3. Teste: Tentar obter porta de um serviço que não existe
            let non_existent_service = "non_existent_service_ports_test";
            tracing::info!("Test 3: Attempt to get mapped port for non-existent service '{}'", non_existent_service);
            match env.get_service_mapped_port(non_existent_service, 80).await {
                Err(DockerHelperError::PortNotMapped { service, internal_port }) => {
                    assert_eq!(service, non_existent_service);
                    assert_eq!(internal_port, 80);
                     tracing::info!("Correctly failed for non-existent service '{}' (PortNotMapped).", non_existent_service);
                }
                Err(DockerHelperError::PortQueryFailed { service, internal_port, .. }) => {
                    assert_eq!(service, non_existent_service);
                    assert_eq!(internal_port, 80);
                    tracing::info!("Correctly failed for non-existent service '{}' (PortQueryFailed).", non_existent_service);
                }
                Ok(port) => panic!("Expected error for non-existent service '{}', but got Ok({})", non_existent_service, port),
                Err(e) => panic!("Expected error for non-existent service '{}', but got different error: {:?}", non_existent_service, e),
            }
            
            // 4. Teste: Serviço que existe mas não tem mapeamento explícito no compose
            tracing::info!("Test 4: Get mapped port for '{}' (no explicit mapping in compose), internal port 80", no_mapping_service_name);
            match env.get_service_mapped_port(no_mapping_service_name, 80).await {
                Err(DockerHelperError::PortNotMapped { service, internal_port }) => {
                    assert_eq!(service, no_mapping_service_name);
                    assert_eq!(internal_port, 80);
                    tracing::info!("Correctly identified port 80 for '{}' (no explicit host mapping) as not mapped.", no_mapping_service_name);
                }
                Ok(port) => panic!("Expected PortNotMapped for service '{}' port 80 (no explicit host mapping), but got Ok({})", no_mapping_service_name, port),
                Err(e) => panic!("Expected PortNotMapped for service '{}' port 80 (no explicit host mapping), but got different error: {:?}", no_mapping_service_name, e),
            }

            // 5. Teste: Serviço que roda mas não expõe a porta consultada
            tracing::info!("Test 5: Attempt to get mapped port for '{}', internal port 80 (service does not expose this port)", no_exposed_service_name);
            match env.get_service_mapped_port(no_exposed_service_name, 80).await {
                Err(DockerHelperError::PortNotMapped { service, internal_port }) => {
                    assert_eq!(service, no_exposed_service_name);
                    assert_eq!(internal_port, 80);
                    tracing::info!("Correctly identified port 80 for '{}' (service does not expose) as not mapped.", no_exposed_service_name);
                }
                 Ok(port) => panic!("Expected PortNotMapped error for unexposed port 80 on '{}', but got Ok({})", no_exposed_service_name, port),
                Err(e) => panic!("Expected PortNotMapped for unexposed port 80 on '{}', but got different error: {:?}", no_exposed_service_name, e),
            }

            // 6. Teste: Parar um serviço e tentar obter sua porta
            tracing::info!("Test 6: Stop service '{}' and attempt to get mapped port", web_service_name);
            let mut stop_cmd = TokioCommand::new("docker-compose"); // Usar o alias
            stop_cmd.arg("-p").arg(env.project_name())
                      .arg("-f").arg(env.compose_file_path().to_string_lossy().as_ref())
                      .arg("stop").arg(web_service_name);
            let stop_output = stop_cmd.output().await.expect("Failed to stop service");
            assert!(stop_output.status.success(), "Failed to stop service '{}': {:?}", web_service_name, stop_output);
            
            match env.get_service_mapped_port(web_service_name, 80).await {
                Err(DockerHelperError::PortNotMapped { service, internal_port }) => {
                    assert_eq!(service, web_service_name);
                    assert_eq!(internal_port, 80);
                    tracing::info!("Correctly identified port 80 for stopped service '{}' as not mapped.", web_service_name);
                }
                Ok(port) => panic!("Expected PortNotMapped error for stopped service '{}', but got Ok({})", web_service_name, port),
                Err(e) => panic!("Expected PortNotMapped for stopped service '{}', but got different error: {:?}", web_service_name, e),
            }

            tracing::info!("Port testing completed. Docker environment will be brought down by Drop.");
        }
    }
}
