// tests/common/docker_helpers.rs
// Licença Apache 2.0
// Copyright 2025 Guilherme Leste

//! Utilitários para gerenciar ambientes Docker Compose para testes de integração.

use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

// Usar anyhow para tratamento de erro mais flexível nos helpers
pub use anyhow::Result; // Alterado para anyhow::Result

#[derive(Debug)]
pub struct DockerComposeEnv {
    compose_file: String,
    project_name: String, // Docker Compose usa o nome do diretório ou -p para nomear o projeto
}

impl DockerComposeEnv {
    /// Cria uma nova instância para gerenciar um ambiente Docker Compose.
    ///
    /// # Arguments
    ///
    /// * `compose_file_path`: Caminho para o arquivo docker-compose.yml.
    /// * `project_name_prefix`: Um prefixo para o nome do projeto Docker Compose,
    ///   ajudando a isolar execuções de teste paralelas se usarem o mesmo compose file.
    ///   O nome real do projeto será algo como `<project_name_prefix>_<timestamp_ou_uuid>`.
    pub fn new(compose_file_path: &str, project_name_prefix: &str) -> Self {
        // Gerar um nome de projeto único para evitar conflitos
        let unique_suffix = uuid::Uuid::new_v4().simple().to_string();
        let project_name = format!("{}_{}", project_name_prefix, unique_suffix);
        info!("Criando DockerComposeEnv para o projeto: {} usando o arquivo: {}", project_name, compose_file_path);
        DockerComposeEnv {
            compose_file: compose_file_path.to_string(),
            project_name,
        }
    }

    /// Executa um comando `docker-compose`.
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

        let status = command
            .stdout(Stdio::piped()) // Capturar stdout
            .stderr(Stdio::piped()) // Capturar stderr
            .status()?; // Retorna std::io::Result<ExitStatus>

        // Log de saída apenas se houver erro ou para debugging
        // if !status.success() || std::env::var("LOG_COMPOSE_OUTPUT").is_ok() {
        //     if let Some(stdout) = child.stdout {
        //         let reader = BufReader::new(stdout);
        //         for line in reader.lines() {
        //             info!("[Compose STDOUT {}]: {}", self.project_name, line.unwrap_or_default());
        //         }
        //     }
        //     if let Some(stderr) = child.stderr {
        //         let reader = BufReader::new(stderr);
        //         for line in reader.lines() {
        //             warn!("[Compose STDERR {}]: {}", self.project_name, line.unwrap_or_default());
        //         }
        //     }
        // }
        
        if !status.success() {
            let err_msg = format!(
                "Comando docker-compose '{:?}' falhou para o projeto '{}' com status: {}",
                args, self.project_name, status
            );
            error!("{}", err_msg);
            // Tentar obter logs do docker-compose em caso de falha
            self.logs_all_services().ok(); // O .ok() ignora o erro de logs_all_services se falhar
            return Err(anyhow::anyhow!(err_msg));
        }
        Ok(status)
    }

    /// Sobe os serviços definidos no arquivo docker-compose em modo detached.
    pub fn up(&self) -> Result<()> {
        info!("Iniciando ambiente Docker Compose para o projeto: {}", self.project_name);
        self.run_compose_command(&["up", "-d", "--remove-orphans", "--force-recreate"], None)?; // Adicionado --force-recreate
        Ok(())
    }
    
    /// Sobe os serviços com variáveis de ambiente específicas.
    pub fn up_with_envs(&self, env_vars: &[(&str, &str)]) -> Result<()> {
        info!("Iniciando ambiente Docker Compose para o projeto: {} com ENVs", self.project_name);
        self.run_compose_command(&["up", "-d", "--remove-orphans", "--force-recreate"], Some(env_vars))?;
        Ok(())
    }


    /// Derruba os serviços e opcionalmente remove os volumes.
    pub fn down(&self, remove_volumes: bool) -> Result<()> {
        info!("Derrubando ambiente Docker Compose para o projeto: {} (remover volumes: {})", self.project_name, remove_volumes);
        let mut args = vec!["down"];
        if remove_volumes {
            args.push("-v");
        }
        args.push("--remove-orphans"); // Adicionado para limpar órfãos
        self.run_compose_command(&args, None)?;
        Ok(())
    }

    /// Pausa um serviço.
    pub fn pause_service(&self, service_name: &str) -> Result<()> {
        info!("Pausando serviço '{}' no projeto '{}'", service_name, self.project_name);
        self.run_compose_command(&["pause", service_name], None)?;
        Ok(())
    }

    /// Retoma um serviço pausado.
    pub fn unpause_service(&self, service_name: &str) -> Result<()> {
        info!("Retomando serviço '{}' no projeto '{}'", service_name, self.project_name);
        self.run_compose_command(&["unpause", service_name], None)?;
        Ok(())
    }
    
    /// Para um serviço.
    pub fn stop_service(&self, service_name: &str) -> Result<()> {
        info!("Parando serviço '{}' no projeto '{}'", service_name, self.project_name);
        self.run_compose_command(&["stop", service_name], None)?;
        Ok(())
    }

    /// Coleta e exibe logs de todos os serviços.
    pub fn logs_all_services(&self) -> Result<()> {
        info!("Coletando logs para o projeto: {}", self.project_name);
        let output = Command::new("docker-compose")
            .arg("-f")
            .arg(&self.compose_file)
            .arg("-p")
            .arg(&self.project_name)
            .arg("logs")
            .arg("--no-color") // Para facilitar a leitura se for capturado programaticamente
            .arg("--tail=200") // Limitar a quantidade de logs
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

    /// Aguarda um serviço ficar saudável, verificando o status do contêiner.
    pub async fn wait_for_service_healthy(
        &self,
        service_name: &str,
        timeout_duration: Duration,
    ) -> Result<()> {
        info!("Aguardando serviço '{}' ficar saudável no projeto '{}' (timeout: {:?})", service_name, self.project_name, timeout_duration);
        let start_time = Instant::now();
        let check_interval = Duration::from_secs(2); // Intervalo entre verificações

        loop {
            if start_time.elapsed() >= timeout_duration {
                let err_msg = format!("Timeout esperando pelo serviço '{}' no projeto '{}' ficar saudável.", service_name, self.project_name);
                error!("{}", err_msg);
                self.logs_all_services().ok();
                return Err(anyhow::anyhow!(err_msg));
            }

            // docker-compose ps -q <service_name> | xargs docker inspect --format "{{.State.Health.Status}}"
            let output = Command::new("docker-compose")
                .arg("-f")
                .arg(&self.compose_file)
                .arg("-p")
                .arg(&self.project_name)
                .arg("ps")
                .arg("-q")
                .arg(service_name)
                .output()?;

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
                .arg("{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}") // Tenta Health.Status, fallback para State.Status
                .arg(&container_id)
                .output()?;

            if health_output.status.success() {
                let health_status = String::from_utf8_lossy(&health_output.stdout).trim().to_lowercase();
                debug!("Status de saúde/estado para serviço '{}' (ID: {}): '{}'", service_name, container_id, health_status);
                if health_status == "healthy" || (health_status == "running" && !service_has_healthcheck(self, service_name)?) {
                    info!("Serviço '{}' está saudável/rodando no projeto '{}'.", service_name, self.project_name);
                    return Ok(());
                } else if health_status == "unhealthy" {
                     let err_msg = format!("Serviço '{}' no projeto '{}' está unhealthy.", service_name, self.project_name);
                     error!("{}", err_msg);
                     self.logs_all_services().ok();
                     return Err(anyhow::anyhow!(err_msg));
                }
            } else {
                warn!("Falha ao inspecionar saúde do contêiner '{}' (ID: {}). Stderr: {}", service_name, container_id, String::from_utf8_lossy(&health_output.stderr));
            }

            tokio::time::sleep(check_interval).await;
        }
    }
}

/// Verifica se um serviço no docker-compose.yml tem uma seção de healthcheck definida.
fn service_has_healthcheck(env: &DockerComposeEnv, service_name: &str) -> Result<bool> {
    // Este é um hack. Uma solução melhor seria parsear o docker-compose.yml.
    // Por ora, vamos assumir que se o `docker inspect` não tem `Health`, não há healthcheck.
    // No entanto, o formato do `docker inspect` pode não ter o campo `Health` se não configurado.
    // Uma forma mais robusta (mas mais complexa) é ler e parsear o compose file.
    // Por simplicidade, se `{{if .State.Health}}` for falso, significa que não há Health section.
    let output = Command::new("docker-compose")
        .arg("-f")
        .arg(&env.compose_file)
        .arg("-p")
        .arg(&env.project_name)
        .arg("ps")
        .arg("-q")
        .arg(service_name)
        .output()?;
    if !output.status.success() || output.stdout.is_empty() {
        return Ok(false); // Serviço não encontrado, assume que não tem healthcheck
    }
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if container_id.is_empty() { return Ok(false); }

    let inspect_output = Command::new("docker")
        .arg("inspect")
        .arg("--format")
        .arg("{{.State.Health}}") // Apenas pega o objeto Health
        .arg(&container_id)
        .output()?;
    
    if inspect_output.status.success() {
        let health_obj_str = String::from_utf8_lossy(&inspect_output.stdout).trim().to_lowercase();
        // Se o objeto Health existir e não for "<no value>" ou similar, então tem healthcheck.
        return Ok(!(health_obj_str.is_empty() || health_obj_str == "<no value>" || health_obj_str == "null"));
    }
    Ok(false)
}


impl Drop for DockerComposeEnv {
    fn drop(&mut self) {
        info!("Executando Drop para DockerComposeEnv (projeto: {}), derrubando ambiente...", self.project_name);
        if let Err(e) = self.down(true) { // Sempre remove volumes no drop para limpeza
            error!("Erro ao derrubar ambiente Docker Compose no drop para o projeto '{}': {}", self.project_name, e);
        } else {
            info!("Ambiente Docker Compose para o projeto '{}' derrubado com sucesso no drop.", self.project_name);
        }
    }
}