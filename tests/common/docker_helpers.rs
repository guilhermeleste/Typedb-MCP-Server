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
        let mut command = Command::new("docker-compose");
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
        let output = Command::new("docker-compose")
            .arg("-f")
            .arg(&self.compose_file)
            .arg("-p")
            .arg(&self.project_name)
            .arg("logs")
            .arg("--no-color")
            .arg("--tail=200")
            .output()?;

        if output.status.success() {
            info!("[Logs Compose {} STDOUT]:\n{}", self.project_name, String::from_utf8_lossy(&output.stdout));
            if !output.stderr.is_empty() {
                warn!("[Logs Compose {} STDERR]:\n{}", self.project_name, String::from_utf8_lossy(&output.stderr));
            }
        } else {
            let err_msg = format!(
                "Falha ao obter logs do docker-compose para o projeto '{}'. Status: {}. Stderr: {}",
                self.project_name,
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            error!("{}", err_msg);
            return Err(anyhow::anyhow!(err_msg));
        }
        Ok(())
    }

    /// Aguarda até que um serviço específico se torne "healthy" ou "running".
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
    ) -> Result<()> { // Alterado para anyhow::Result
        info!("Aguardando serviço '{}' ficar saudável no projeto '{}' (timeout: {:?})", service_name, self.project_name, timeout_duration);
        let start_time = Instant::now();
        let check_interval = Duration::from_secs(2);

        loop {
            if start_time.elapsed() >= timeout_duration {
                let err_msg = format!("Timeout esperando pelo serviço '{}' no projeto '{}' ficar saudável.", service_name, self.project_name);
                error!("{}", err_msg);
                self.logs_all_services().ok(); // Tenta logar na falha
                bail!(err_msg); // Usa bail! de anyhow
            }

            let output = Command::new("docker-compose")
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
                warn!("ID do contêiner para o serviço '{}' está vazio. Tentando novamente...", service_name);
                tokio::time::sleep(check_interval).await;
                continue;
            }

            let health_output = Command::new("docker")
                .arg("inspect")
                .arg("--format")
                .arg("{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}")
                .arg(&container_id)
                .output()
                .context(format!("Falha ao executar 'docker inspect' para o container ID '{}'", container_id))?;


            if health_output.status.success() {
                let health_status = String::from_utf8_lossy(&health_output.stdout).trim().to_lowercase();
                debug!("Status de saúde/estado para serviço '{}' (ID: {}): '{}'", service_name, container_id, health_status);
                if health_status == "healthy" || (health_status == "running" && !service_has_healthcheck(self, service_name).unwrap_or(false)) {
                    info!("Serviço '{}' está saudável/rodando no projeto '{}'.", service_name, self.project_name);
                    return Ok(());
                } else if health_status == "unhealthy" {
                     let err_msg = format!("Serviço '{}' no projeto '{}' está unhealthy.", service_name, self.project_name);
                     error!("{}", err_msg);
                     self.logs_all_services().ok();
                     bail!(err_msg);
                }
            } else {
                warn!("Falha ao inspecionar saúde do contêiner '{}' (ID: {}). Stderr: {}", service_name, container_id, String::from_utf8_lossy(&health_output.stderr));
            }

            tokio::time::sleep(check_interval).await;
        }
    }
}

fn service_has_healthcheck(env: &DockerComposeEnv, service_name: &str) -> Result<bool> {
    let output = Command::new("docker-compose")
        .arg("-f")
        .arg(&env.compose_file)
        .arg("-p")
        .arg(&env.project_name)
        .arg("ps")
        .arg("-q")
        .arg(service_name)
        .output()
        .context(format!("Falha ao obter ID do container para o serviço {}", service_name))?;

    if !output.status.success() || output.stdout.is_empty() {
        return Ok(false);
    }
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if container_id.is_empty() { return Ok(false); }

    let inspect_output = Command::new("docker")
        .arg("inspect")
        .arg("--format")
        .arg("{{.State.Health}}")
        .arg(&container_id)
        .output()
        .context(format!("Falha ao inspecionar o container {}", container_id))?;
    
    if inspect_output.status.success() {
        let health_obj_str = String::from_utf8_lossy(&inspect_output.stdout).trim().to_lowercase();
        return Ok(!(health_obj_str.is_empty() || health_obj_str == "<no value>" || health_obj_str == "null"));
    }
    Ok(false)
}

impl Drop for DockerComposeEnv {
    fn drop(&mut self) {
        info!("Executando Drop para DockerComposeEnv (projeto: {}), derrubando ambiente...", self.project_name);
        if let Err(e) = self.down(true) {
            error!("Erro ao derrubar ambiente Docker Compose no drop para o projeto '{}': {}", self.project_name, e);
        } else {
            info!("Ambiente Docker Compose para o projeto '{}' derrubado com sucesso no drop.", self.project_name);
        }
    }
}