// MIT License
//
// Copyright (c) 2025 Guilherme Leste
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Utilitários para gerenciar ambientes Docker Compose para testes de integração.
//!
//! Fornece a struct `DockerComposeEnv` para controlar o ciclo de vida (`up`, `down`, `start`, `stop`)
//! dos serviços Docker definidos em um arquivo `docker-compose.yml`, e para
//! consultar informações sobre esses serviços, como portas mapeadas e status de saúde.
//!
//! O gerenciamento de nomes de projeto únicos para cada instância de `DockerComposeEnv`
//! permite que múltiplos ambientes de teste coexistam sem conflitos de nome de contêiner,
//! rede ou volume, o que é crucial para execuções de teste paralelas ou sequenciais limpas.

use anyhow::{bail, Context as AnyhowContext, Result};
use std::io::{BufRead, BufReader, ErrorKind as IoErrorKind};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

// Importa constantes do mesmo crate `common` para fácil acesso e consistência.
use super::constants;

/// Contador global para gerar sufixos numéricos únicos para nomes de projeto Docker Compose.
/// Isso ajuda a isolar os recursos Docker (contêineres, redes, volumes) de diferentes
/// execuções de `TestEnvironment`.
static PROJECT_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Representa e gerencia um ambiente Docker Compose isolado, específico para um teste ou suíte de testes.
///
/// Cada instância desta struct opera sobre um projeto Docker Compose com um nome único,
/// permitindo o controle independente do ciclo de vida dos serviços definidos no
/// arquivo compose especificado.
#[derive(Debug)]
pub struct DockerComposeEnv {
    /// O caminho completo para o arquivo `docker-compose.yml` que define os serviços.
    compose_file_path: String,
    /// O nome do projeto Docker Compose, gerado para ser único para esta instância.
    /// Usado com a flag `-p` nos comandos `docker compose`.
    project_name: String,
}

impl DockerComposeEnv {
    /// Cria uma nova instância de `DockerComposeEnv`.
    ///
    /// Gera um nome de projeto Docker Compose único usando o `project_name_prefix`
    /// fornecido, um contador atômico e uma porção de um UUIDv4 para garantir
    /// alta probabilidade de unicidade, mesmo em execuções paralelas (embora
    /// os testes de integração geralmente sejam executados serialmente devido a portas de host).
    ///
    /// # Arguments
    /// * `compose_file_path`: Caminho para o arquivo `docker-compose.yml` a ser usado.
    /// * `project_name_prefix`: Um prefixo descritivo para o nome do projeto Docker Compose.
    ///   O nome final será algo como `prefixo_uuidcurto_contador`.
    pub fn new(compose_file_path: &str, project_name_prefix: &str) -> Self {
        let unique_id_num = PROJECT_COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
        // Pega os primeiros 8 caracteres do UUID para manter o nome do projeto razoavelmente curto.
        let unique_id_uuid_short = uuid::Uuid::new_v4().as_simple().to_string()[..8].to_string();

        // Sanitiza o prefixo para conter apenas caracteres válidos em nomes de projeto Docker.
        let sanitized_prefix = project_name_prefix
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect::<String>();

        // Monta o nome do projeto e garante que não exceda o limite de comprimento.
        let mut project_name = format!("{}_{}_{:03}", sanitized_prefix, unique_id_uuid_short, unique_id_num);
        const MAX_PROJECT_NAME_LEN: usize = 60; // Limite prático para nomes de projeto Docker
        if project_name.len() > MAX_PROJECT_NAME_LEN {
            project_name.truncate(MAX_PROJECT_NAME_LEN);
        }
        // Remove hífens ou underscores no final, se houver, após o truncamento.
        project_name = project_name.trim_end_matches(|c| c == '-' || c == '_').to_string();

        info!(
            "Criando DockerComposeEnv para projeto: '{}' usando arquivo: '{}'",
            project_name, compose_file_path
        );
        DockerComposeEnv { compose_file_path: compose_file_path.to_string(), project_name }
    }

    /// Retorna o nome do projeto Docker Compose associado a esta instância.
    pub fn project_name(&self) -> &str {
        &self.project_name
    }

    /// Prepara as variáveis de ambiente que serão passadas para o processo `docker compose`.
    ///
    /// Estas variáveis são usadas pelo Docker Compose para substituição dentro do arquivo YAML
    /// e também podem ser lidas pelos scripts de `command:` dos contêineres.
    ///
    /// # Arguments
    /// * `config_filename_opt`: Opcional. O nome do arquivo de configuração TOML (ex: "default.test.toml")
    ///   que o servidor MCP deve usar. Será formatado como um caminho dentro do contêiner.
    /// * `tls_enabled_mcp`: Indica se o servidor MCP (e seu healthcheck no Dockerfile) deve operar
    ///   em modo TLS.
    /// * `typedb_address_for_mcp_opt`: Opcional. O endereço de rede (nome do serviço:porta)
    ///   do TypeDB que o servidor MCP deve usar para se conectar.
    fn get_compose_env_vars(
        &self,
        config_filename_opt: Option<&str>,
        tls_enabled_mcp: bool,
        typedb_address_for_mcp_opt: Option<String>,
    ) -> Vec<(String, String)> {
        let mcp_config_path = config_filename_opt
            .map_or_else(
                // Se nenhum config_filename é passado (ex: para `down`), usa um default
                // para evitar que a variável `MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV` fique vazia.
                || "/app/test_configs/default.test.toml".to_string(),
                |config_filename| format!("/app/test_configs/{}", config_filename),
            );

        // Este é o endereço que o SERVIDOR MCP (dentro do seu contêiner) usará
        // para se conectar ao TypeDB. Será passado via MCP_TYPEDB__ADDRESS.
        let mcp_target_typedb_address = typedb_address_for_mcp_opt.unwrap_or_else(|| {
            // Default se não fornecido (ex: para `down` ou se o TestEnvironment não especificar).
            // Aponta para o serviço TypeDB padrão sem TLS.
            format!(
                "{}:{}",
                constants::TYPEDB_SERVICE_NAME,
                constants::TYPEDB_INTERNAL_PORT
            )
        });

        vec![
            (
                // Usada pelo Docker Compose para popular MCP_CONFIG_PATH no contêiner MCP.
                "MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV".to_string(),
                mcp_config_path,
            ),
            (
                // Usada pelo servidor MCP e seu script de inicialização DENTRO do contêiner
                // para saber a qual TypeDB se conectar.
                "MCP_TYPEDB__ADDRESS".to_string(),
                mcp_target_typedb_address,
            ),
            (
                // Usada pelo HEALTHCHECK no Dockerfile do servidor MCP para saber se usa http ou https.
                "TLS_ENABLED".to_string(),
                if tls_enabled_mcp { "true".to_string() } else { "false".to_string() },
            ),
            (
                // Usada pelos contêineres TypeDB para definir a senha de admin.
                // Também usada pelo servidor MCP para se autenticar com o TypeDB.
                "TYPEDB_PASSWORD_TEST".to_string(),
                std::env::var("TYPEDB_PASSWORD_TEST").unwrap_or_else(|_| "password".to_string()),
            ),
            // As variáveis abaixo são usadas principalmente pelo script `command:` dentro do
            // contêiner `typedb-mcp-server-it` para a lógica de espera do TypeDB.
            // Elas são mais por conveniência do script e podem ser simplificadas se o script
            // derivar toda a informação necessária de `MCP_TYPEDB__ADDRESS`.
            ("timeout_duration".to_string(), "120".to_string()),
            ("sleep_interval".to_string(), "3".to_string()),
            ("elapsed_time".to_string(), "0".to_string()),
        ]
    }

    /// Executa um comando `docker compose` genérico para este ambiente.
    ///
    /// Captura stdout e stderr do comando e os loga. Retorna um erro se o comando falhar.
    ///
    /// # Arguments
    /// * `global_args`: Argumentos globais do Docker Compose (ex: `["--profile", "myprofile"]`).
    ///                  Estes são inseridos *antes* do subcomando (up, down, etc.).
    /// * `subcommand_args`: Argumentos do subcomando Docker Compose (ex: `["up", "-d"]`).
    /// * `env_vars_for_command_process`: Variáveis de ambiente a serem definidas para o
    ///   processo `docker compose` em si.
    fn run_compose_command(
        &self,
        global_args: &[&str],
        subcommand_args: &[&str],
        env_vars_for_command_process: Option<&[(&str, String)]>,
    ) -> Result<ExitStatus> {
        let mut command = Command::new("docker");
        command.arg("compose");
        // Argumentos específicos do projeto devem vir antes dos globais e do subcomando.
        command.arg("-f").arg(&self.compose_file_path);
        command.arg("-p").arg(self.project_name());

        command.args(global_args);    // Ex: --profile <nome>
        command.args(subcommand_args); // Ex: up -d --wait

        if let Some(vars) = env_vars_for_command_process {
            for (key, value) in vars {
                command.env(key, value);
                debug!("Para comando `docker compose`: setando ENV {}={}", key, value);
            }
        }

        debug!("Executando comando Docker Compose: {:?}", command);

        let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
            .with_context(|| format!("Falha ao iniciar 'docker compose {:?} {:?}' para projeto '{}'", global_args, subcommand_args, self.project_name()))?;

        // Threads para capturar e logar stdout/stderr em tempo real.
        let stdout_output_shared = Arc::new(Mutex::new(Vec::new()));
        let stderr_output_shared = Arc::new(Mutex::new(Vec::new()));

        if let Some(stdout) = child.stdout.take() {
            let stdout_clone = stdout_output_shared.clone();
            let project_name_clone = self.project_name().to_string(); // Clonar para a thread
            std::thread::spawn(move || {
                BufReader::new(stdout).lines().for_each(|line_result| {
                    match line_result {
                        Ok(line) => {
                            // Logar em trace para não poluir logs de teste, a menos que haja erro.
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
            let project_name_clone = self.project_name().to_string(); // Clonar para a thread
            std::thread::spawn(move || {
                BufReader::new(stderr).lines().for_each(|line_result| {
                    match line_result {
                        Ok(line) => {
                            // Stderr do Docker Compose é frequentemente informativo (ex: "Creating network..."),
                            // então logamos como `warn` para visibilidade.
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
            // Em caso de falha, obter os logs acumulados para o erro.
            let stdout_log = stdout_output_shared.lock().unwrap_or_else(|e| e.into_inner()).join("\n");
            let stderr_log = stderr_output_shared.lock().unwrap_or_else(|e| e.into_inner()).join("\n");
            bail!(
                "Comando docker compose '{:?} {:?}' falhou para projeto '{}' com status: {}.\nSTDOUT:\n{}\nSTDERR:\n{}",
                global_args, subcommand_args, self.project_name(), status, stdout_log, stderr_log
            );
        }
        Ok(status)
    }

    /// Inicia todos os serviços definidos no arquivo Docker Compose e ativados pelos perfis.
    ///
    /// Reconstrói imagens se necessário (`--build`), remove contêineres órfãos
    /// (`--remove-orphans`), e força a recriação de contêineres (`--force-recreate`).
    ///
    /// # Arguments
    /// * `config_filename`: Nome do arquivo de configuração TOML (ex: "default.test.toml")
    ///   a ser usado pelo servidor MCP.
    /// * `active_profiles`: Opcional. Uma lista de nomes de perfis do Docker Compose a serem ativados.
    /// * `wait_for_health`: Se `true`, o comando `up` usará a flag `--wait` para aguardar
    ///   que os serviços atinjam um estado saudável (conforme definido por seus `healthcheck`s)
    ///   antes de retornar.
    /// * `tls_enabled_mcp`: Indica se o servidor MCP (e seu healthcheck Dockerfile) está
    ///   configurado para usar TLS. Passado como variável de ambiente para o Dockerfile.
    /// * `typedb_address_for_mcp`: O endereço (nome_serviço:porta) do TypeDB que o servidor MCP
    ///   (dentro do seu contêiner) deve usar para se conectar.
    pub fn up(
        &self,
        config_filename: &str,
        active_profiles: Option<Vec<String>>,
        wait_for_health: bool,
        tls_enabled_mcp: bool,
        typedb_address_for_mcp: String,
    ) -> Result<()> {
        info!(
            "Iniciando ambiente Docker Compose para projeto: '{}', config MCP: '{}', perfis: {:?}, wait_for_health: {}, tls_enabled_mcp: {}, typedb_addr_for_mcp: {}",
            self.project_name(),
            config_filename,
            active_profiles.as_deref().unwrap_or_default(),
            wait_for_health,
            tls_enabled_mcp,
            typedb_address_for_mcp
        );

        let env_vars_for_compose_process = self.get_compose_env_vars(
            Some(config_filename),
            tls_enabled_mcp,
            Some(typedb_address_for_mcp),
        );
        let env_vars_refs: Vec<(&str, String)> = env_vars_for_compose_process
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();

        let mut up_subcommand_args: Vec<&str> =
            vec!["up", "-d", "--remove-orphans", "--force-recreate", "--build"];
        if wait_for_health {
            up_subcommand_args.push("--wait");
        }

        // Constrói os argumentos de perfil globais
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
        .with_context(|| {
            format!(
                "Falha em 'docker compose up' para projeto '{}', config MCP: '{}', perfis: {:?}",
                self.project_name(),
                config_filename,
                active_profiles.as_deref().unwrap_or_default()
            )
        })?;

        info!(
            "Ambiente Docker Compose para projeto '{}' iniciado (comando 'up' enviado).",
            self.project_name()
        );
        Ok(())
    }

    /// Derruba (para e remove) todos os serviços do ambiente Docker Compose.
    ///
    /// # Arguments
    /// * `remove_volumes`: Se `true`, também remove os volumes nomeados associados ao projeto,
    ///   efetivamente limpando todos os dados persistidos.
    pub fn down(&self, remove_volumes: bool) -> Result<()> {
        info!(
            "Derrubando ambiente Docker Compose para projeto: '{}' (remover volumes: {})",
            self.project_name(), remove_volumes
        );

        // Passa None para config_filename e typedb_address_override, pois não são
        // estritamente necessários para 'down', mas get_compose_env_vars os espera.
        // tls_enabled_mcp=false também é um valor seguro para 'down'.
        let env_vars_for_compose_process = self.get_compose_env_vars(None, false, None);
        let env_vars_refs: Vec<(&str, String)> = env_vars_for_compose_process
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();

        let mut subcommand_args = vec!["down", "--remove-orphans"];
        if remove_volumes {
            subcommand_args.push("-v"); // Flag para remover volumes
        }
        subcommand_args.push("--timeout");
        subcommand_args.push("30"); // Timeout em segundos para parada graciosa

        match self.run_compose_command(&[], &subcommand_args, Some(&env_vars_refs)) {
            Ok(_) => {
                info!("Ambiente Docker Compose para projeto '{}' derrubado.", self.project_name());
                // Tenta um cleanup adicional de contêineres caso o 'down' não tenha pego tudo.
                if let Err(e) = self.force_cleanup_orphaned_containers() {
                     warn!("Cleanup adicional de containers órfãos falhou para projeto '{}': {}. Isso pode ser normal se não houver containers órfãos.", self.project_name(), e);
                }
            },
            Err(e) => {
                error!("Erro ao derrubar ambiente Docker Compose para projeto '{}': {}. Tentando cleanup forçado.", self.project_name(), e);
                // Mesmo se 'down' falhar, tenta limpar os contêineres.
                if let Err(cleanup_err) = self.force_cleanup_orphaned_containers() {
                    warn!("Cleanup forçado também falhou para projeto '{}': {}", self.project_name(), cleanup_err);
                }
                return Err(e); // Propaga o erro original do 'down'
            }
        }
        Ok(())
    }

    /// Força a remoção de quaisquer contêineres que possam ter ficado órfãos
    /// para este projeto Docker Compose. Útil após falhas de `down`.
    fn force_cleanup_orphaned_containers(&self) -> Result<()> {
        debug!("Executando cleanup forçado de containers órfãos para projeto '{}'", self.project_name());

        let list_output = Command::new("docker")
            .arg("ps")
            .arg("-a") // Lista todos os contêineres (rodando e parados)
            .arg("--filter")
            .arg(&format!("label=com.docker.compose.project={}", self.project_name()))
            .arg("--format")
            .arg("{{.ID}}") // Obtém apenas os IDs dos contêineres
            .output()
            .with_context(|| format!("Falha ao listar containers para projeto '{}'", self.project_name()))?;

        if !list_output.status.success() {
            bail!("Falha ao listar containers órfãos para projeto '{}': Stderr: {}", self.project_name(), String::from_utf8_lossy(&list_output.stderr));
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

            let mut remove_cmd = Command::new("docker");
            remove_cmd.arg("rm").arg("-f"); // Força a remoção
            remove_cmd.args(&container_ids);

            let remove_output = remove_cmd.output()
                .with_context(|| format!("Falha ao executar 'docker rm -f' para containers órfãos do projeto '{}'", self.project_name()))?;

            if !remove_output.status.success() {
                let stderr = String::from_utf8_lossy(&remove_output.stderr);
                // Pode haver erros se um contêiner já foi removido por outro processo, então logamos como warning.
                warn!("Potencial falha ao remover containers órfãos para projeto '{}': {}", self.project_name(), stderr);
            } else {
                info!("Containers órfãos removidos com sucesso para projeto '{}'", self.project_name());
            }
        }
        // Após remover contêineres, tenta remover redes órfãs.
        self.force_cleanup_orphaned_networks()
            .with_context(|| format!("Falha no cleanup de redes órfãs para projeto '{}'", self.project_name()))?;
        Ok(())
    }

    /// Força a remoção de quaisquer redes que possam ter ficado órfãs
    /// para este projeto Docker Compose.
    fn force_cleanup_orphaned_networks(&self) -> Result<()> {
        debug!("Executando cleanup forçado de redes órfãs para projeto '{}'", self.project_name());
        let list_output = Command::new("docker")
            .arg("network")
            .arg("ls")
            .arg("--filter")
            .arg(&format!("label=com.docker.compose.project={}", self.project_name()))
            .arg("--format")
            .arg("{{.ID}}") // Obtém IDs das redes
            .output()
            .with_context(|| format!("Falha ao listar redes para projeto '{}'", self.project_name()))?;

        if !list_output.status.success() {
            bail!("Falha ao listar redes órfãs para projeto '{}': Stderr: {}", self.project_name(), String::from_utf8_lossy(&list_output.stderr));
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
        let mut remove_cmd = Command::new("docker");
        remove_cmd.arg("network").arg("rm");
        remove_cmd.args(&network_ids);
        let remove_output = remove_cmd.output()
            .with_context(|| format!("Falha ao executar 'docker network rm' para redes órfãs do projeto '{}'", self.project_name()))?;

        if !remove_output.status.success() {
            let stderr = String::from_utf8_lossy(&remove_output.stderr);
            // É comum que a remoção de rede falhe se ainda houver endpoints (mesmo de contêineres parados),
            // então logamos como warning. A limpeza de contêineres deve ser feita antes.
            warn!("Algumas redes podem não ter sido removidas para projeto '{}' (podem ainda ter endpoints): {}", self.project_name(), stderr);
        } else {
            info!("Redes órfãs removidas com sucesso para projeto '{}'", self.project_name());
        }
        Ok(())
    }

    /// Coleta e loga os logs de todos os serviços definidos no arquivo Docker Compose.
    /// Útil para depuração após a falha de um teste.
    pub fn logs_all_services(&self) -> Result<()> {
        info!("Coletando logs para projeto Docker Compose: {}", self.project_name());
        let output = Command::new("docker")
            .arg("compose")
            .arg("-f").arg(&self.compose_file_path)
            .arg("-p").arg(self.project_name())
            .arg("logs")
            .arg("--no-color") // Facilita a leitura em logs de texto.
            .arg("--tail=all") // Pega todos os logs.
            .arg("--timestamps") // Adiciona timestamps.
            .output().with_context(|| format!("Falha ao executar 'docker compose logs' para projeto {}", self.project_name()))?;

        if !output.stdout.is_empty() {
            info!("[Compose Logs STDOUT {}]:\n{}", self.project_name(), String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            // Erros do comando 'logs' em si.
            warn!("[Compose Logs STDERR {}]:\n{}", self.project_name(), String::from_utf8_lossy(&output.stderr));
        }
        if !output.status.success() {
            bail!("'docker compose logs' para projeto '{}' falhou com status {}", self.project_name(), output.status);
        }
        Ok(())
    }

    /// Obtém a porta do *host* que está mapeada para uma porta interna de um serviço específico.
    ///
    /// # Arguments
    /// * `service_name`: O nome do serviço conforme definido no arquivo Docker Compose.
    /// * `internal_port`: A porta interna do contêiner para a qual se deseja a porta do host.
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
            // Tenta obter logs de todos os serviços para ajudar na depuração
            self.logs_all_services().unwrap_or_else(|e| error!("Erro adicional ao coletar logs de todos os serviços: {}", e));
            bail!("'docker compose port {} {}' falhou (status {}): {}", service_name, internal_port, output.status, stderr);
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            self.logs_all_services().unwrap_or_else(|e| error!("Erro adicional ao coletar logs de todos os serviços: {}", e));
            bail!("Saída de 'docker compose port {} {}' vazia. O serviço está rodando e o perfil correto está ativo?", service_name, internal_port);
        }
        // A saída de `docker compose port` é geralmente `0.0.0.0:XXXX` ou `[::]:XXXX`.
        // Precisamos pegar apenas o XXXX.
        stdout.rsplit_once(':').and_then(|(_,p)| p.parse().ok()).with_context(|| format!("Saída inesperada de 'docker compose port': '{}'", stdout))
    }

    /// Para um serviço específico dentro do ambiente Docker Compose.
    pub fn stop_service(&self, service_name: &str) -> Result<()> {
        info!("Parando serviço '{}' (projeto '{}')", service_name, self.project_name());
        self.run_compose_command(&[], &["stop", service_name], None)?;
        std::thread::sleep(Duration::from_secs(3)); // Pequena pausa para permitir que o serviço pare.
        Ok(())
    }

    /// Inicia um serviço previamente parado dentro do ambiente Docker Compose.
    pub fn start_service(&self, service_name: &str) -> Result<()> {
        info!("Iniciando serviço parado '{}' (projeto '{}')", service_name, self.project_name());
        self.run_compose_command(&[], &["start", service_name], None)?;
        std::thread::sleep(Duration::from_secs(3)); // Pequena pausa para permitir que o serviço inicie.
        Ok(())
    }

    /// Aguarda até que um serviço específico atinja um estado saudável (conforme seu `healthcheck`
    /// no Docker Compose) ou esteja no estado "running" (se nenhum healthcheck estiver definido
    /// ou se o healthcheck já passou e o estado é apenas "running").
    ///
    /// # Arguments
    /// * `service_name`: O nome do serviço a ser aguardado.
    /// * `timeout_duration`: A duração máxima de espera.
    pub async fn wait_for_service_healthy(&self, service_name: &str, timeout_duration: Duration) -> Result<()> {
        info!("Aguardando serviço '{}' (projeto '{}') ficar saudável/rodando (timeout: {:?})", service_name, self.project_name(), timeout_duration);
        let start_time = Instant::now();
        let check_interval = Duration::from_secs(2); // Intervalo entre verificações

        loop {
            if start_time.elapsed() >= timeout_duration {
                self.logs_all_services().unwrap_or_else(|e| error!("Erro ao obter logs durante timeout de wait_for_service_healthy para '{}': {}", service_name, e));
                bail!("Timeout esperando serviço '{}' (projeto '{}') ficar saudável/rodando.", service_name, self.project_name());
            }

            let ps_output_res = Command::new("docker")
                .arg("compose")
                .arg("-f").arg(&self.compose_file_path)
                .arg("-p").arg(self.project_name())
                .arg("ps").arg("--format").arg("json").arg(service_name) // Pede formato JSON para o serviço específico
                .output();

            let output_str = match ps_output_res {
                Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
                Ok(out) => {
                    debug!("'docker compose ps' para serviço '{}' falhou (status {}). Stderr: {}. Tentando novamente...", service_name, out.status, String::from_utf8_lossy(&out.stderr));
                    tokio::time::sleep(check_interval).await;
                    continue; // Tenta novamente
                }
                Err(e) => {
                    if e.kind() == IoErrorKind::NotFound {
                         bail!("Comando 'docker' não encontrado. Certifique-se que o Docker está instalado e no PATH.");
                    }
                    warn!("'docker compose ps' para serviço '{}' falhou ao executar: {}. Tentando novamente...", service_name, e);
                    tokio::time::sleep(check_interval).await;
                    continue; // Tenta novamente
                }
            };

            // O output de `docker compose ps --format json <service_name>` é uma stream de objetos JSON,
            // um por contêiner do serviço (se houver scale > 1, o que não é comum para estes testes).
            // Pegamos a primeira linha/objeto.
            if output_str.trim().is_empty() {
                debug!("'docker compose ps --format json' para serviço '{}' não retornou contêineres (perfil pode não estar ativo ou serviço ainda não criado). Tentando novamente...", service_name);
                tokio::time::sleep(check_interval).await;
                continue;
            }

            if let Some(first_line) = output_str.lines().next() {
                 match serde_json::from_str::<serde_json::Value>(first_line) {
                    Ok(service_info) => {
                        // O campo "State" (ex: "running", "exited") indica o estado do ciclo de vida do contêiner.
                        // O campo "Status" (ex: "Up X seconds (healthy)", "Up Y seconds (starting)") contém o status do healthcheck.
                        let container_state = service_info.get("State").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();
                        let container_status_field = service_info.get("Status").and_then(|s| s.as_str()).unwrap_or("").to_lowercase();

                        debug!("Serviço '{}' (projeto '{}') estado do contêiner: '{}', campo Status: '{}'", service_name, self.project_name(), container_state, container_status_field);

                        if container_state == "running" {
                            if container_status_field.contains("healthy") {
                                info!("Serviço '{}' (projeto '{}') está saudável (Status: {}).", service_name, self.project_name(), container_status_field);
                                return Ok(());
                            } else if !container_status_field.contains("starting") && !container_status_field.contains("unhealthy") {
                                // Se não está "starting" nem "unhealthy", e está "running", consideramos pronto
                                // (pode ser que não tenha healthcheck ou o healthcheck já passou e o status é só "Up X seconds").
                                info!("Serviço '{}' (projeto '{}') está rodando (Status: {}). Considerando pronto.", service_name, self.project_name(), container_status_field);
                                return Ok(());
                            } else if container_status_field.contains("unhealthy") {
                                 self.logs_all_services().unwrap_or_else(|e| error!("Erro ao obter logs durante estado 'unhealthy' do serviço '{}': {}",service_name, e));
                                bail!("Serviço '{}' (projeto '{}') está unhealthy. Status: {}", service_name, self.project_name(), container_status_field);
                            }
                            // else (ainda "starting" ou outro estado transitório), continua esperando
                        } else if container_state == "exited" {
                            // Se saiu, algo deu errado. Logar e falhar.
                            self.logs_all_services().unwrap_or_else(|e| error!("Erro ao obter logs após serviço '{}' sair: {}",service_name, e));
                            bail!("Serviço '{}' (projeto '{}') saiu inesperadamente. Estado do contêiner: {}", service_name, self.project_name(), container_state);
                        }
                        // else (outro estado como "creating", "restarting"), continua esperando
                    }
                    Err(e) => warn!("Falha ao parsear JSON do 'docker compose ps' para serviço '{}': {}. Output: '{}'. Tentando novamente...", service_name, e, first_line),
                }
            } else {
                debug!("'docker compose ps --format json' para serviço '{}' não retornou uma linha JSON válida. Output: '{}'. Tentando novamente...", service_name, output_str.trim());
            }
            tokio::time::sleep(check_interval).await;
        }
    }

    /// Inicia o ambiente Docker Compose (versão de compatibilidade).
    ///
    /// Esta versão mantém compatibilidade com código existente que pode não especificar
    /// todos os novos parâmetros de `up`. Por padrão, usa `wait_for_health = true`,
    /// `tls_enabled_mcp = false`, e o endereço TypeDB padrão.
    #[allow(dead_code)] // Usado por testes mais antigos ou como um default conveniente.
    pub fn up_compat(&self, config_filename: &str, active_profiles: Option<Vec<String>>) -> Result<()> {
        self.up(
            config_filename,
            active_profiles,
            true,  // wait_for_health
            false, // tls_enabled_mcp
            // Endereço TypeDB que o MCP Server usará (default para o serviço não-TLS)
            format!("{}:{}", constants::TYPEDB_SERVICE_NAME, constants::TYPEDB_INTERNAL_PORT)
        )
    }
}

impl Drop for DockerComposeEnv {
    /// Garante que o ambiente Docker Compose seja derrubado quando `DockerComposeEnv` sai de escopo.
    /// Remove volumes para garantir um estado limpo para a próxima execução de teste.
    fn drop(&mut self) {
        info!("Limpando ambiente Docker Compose para projeto: '{}' (via Drop).", self.project_name());
        if let Err(e) = self.down(true) { // `remove_volumes = true`
            error!("Falha ao derrubar ambiente Docker Compose no drop para '{}': {}. Limpeza manual pode ser necessária.", self.project_name(), e);
        } else {
            info!("Ambiente Docker Compose para projeto '{}' derrubado com sucesso no drop.", self.project_name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial; // Para garantir que testes que manipulam Docker rodem serialmente.

    /// Cria um arquivo docker-compose.yml mínimo para os testes deste helper.
    /// Este arquivo define um serviço simples 'alpine-dummy-service' que pode ser
    /// iniciado e parado para testar a funcionalidade de `DockerComposeEnv`.
    fn create_minimal_compose_file_for_helper_tests() -> std::io::Result<tempfile::NamedTempFile> {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new()?;
        // O comando do alpine-dummy-service usa ferramentas nativas do Alpine (busybox nc)
        // para manter um servidor simples na porta 80 que responde aos healthchecks.
        writeln!(file, r#"
version: '3.8'
services:
  alpine-dummy-service:
    image: alpine:latest
    container_name: ${{COMPOSE_PROJECT_NAME}}-alpine-dummy
    command: ["sh", "-c", "echo 'Dummy service started. MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV=${{MCP_CONFIG_PATH_FOR_TEST_CONTAINER_HOST_ENV}} MCP_TYPEDB__ADDRESS=${{MCP_TYPEDB__ADDRESS}} TYPEDB_PASSWORD_TEST=${{TYPEDB_PASSWORD_TEST}}' && while true; do echo 'HTTP/1.1 200 OK\\r\\n\\r\\nPong' | nc -l -p 80; sleep 0.1; done"]
    ports:
      - "80" # Docker mapeará para uma porta aleatória do host, que `get_service_host_port` pode obter.
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 80 || exit 1"] # Healthcheck simples na porta 80
      interval: 2s
      timeout: 1s
      retries: 5
      start_period: 1s # Tempo para o serviço iniciar antes do primeiro healthcheck
"#)?;
        file.flush()?; // Garante que o conteúdo seja escrito no disco.
        Ok(file)
    }

    #[tokio::test]
    #[serial] // Garante que este teste não rode em paralelo com outros que usam Docker.
    async fn test_docker_compose_env_new_generates_unique_project_name() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init(); // Para logs de teste
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

        // Endereço TypeDB não é relevante para este serviço dummy, mas `up` espera.
        let dummy_typedb_addr = "dummy-typedb:1729".to_string();
        env.up("dummy_config.toml", None, true, false, dummy_typedb_addr)
            .context("Falha no env.up() no teste de ciclo de vida com serviço mínimo")?;

        // Aguarda o serviço ficar saudável (healthcheck definido no YAML)
        env.wait_for_service_healthy("alpine-dummy-service", Duration::from_secs(20))
            .await
            .context("Serviço alpine-dummy-service não ficou saudável")?;
        info!("Serviço alpine-dummy-service está saudável.");

        // Obtém a porta do host mapeada para a porta interna 80 do serviço.
        let host_port = env.get_service_host_port("alpine-dummy-service", 80)
            .context("Falha ao obter porta mapeada para alpine-dummy-service")?;
        // Como a porta do host é aleatória (definido como "80" no compose),
        // apenas verificamos se uma porta > 0 foi atribuída.
        assert!(host_port > 0, "Porta mapeada para alpine-dummy-service incorreta: {}", host_port);
        info!("Porta do host para alpine-dummy-service (interna :80) é {}", host_port);

        // O Drop de `env` chamará `down()` automaticamente no final do escopo.
        Ok(())
    }

    #[tokio::test]
    #[serial]
    #[ignore] // Este teste usa o `docker-compose.test.yml` real, pode ser mais pesado e requerer setup.
    async fn test_real_services_up_down_and_port_retrieval() -> Result<()> {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let compose_path_str = constants::DEFAULT_DOCKER_COMPOSE_TEST_FILE;
        let env = DockerComposeEnv::new(compose_path_str, "hlp_real_svc");

        // Endereço para o MCP Server se conectar ao TypeDB padrão.
        let typedb_addr_for_mcp = format!("{}:{}", constants::TYPEDB_SERVICE_NAME, constants::TYPEDB_INTERNAL_PORT);
        env.up(
            constants::DEFAULT_TEST_CONFIG_FILENAME,
            Some(vec!["typedb_default".to_string()]), // Ativa o perfil para o TypeDB padrão
            true,  // wait_for_health
            false, // tls_enabled_mcp
            typedb_addr_for_mcp // MCP se conecta ao TypeDB padrão
        ).context("Falha ao executar 'up' com config default e perfil typedb_default")?;

        // Aguarda o serviço TypeDB padrão ficar saudável.
        env.wait_for_service_healthy(constants::TYPEDB_SERVICE_NAME, constants::DEFAULT_TYPEDB_READY_TIMEOUT)
            .await
            .with_context(|| format!("Serviço '{}' não ficou saudável", constants::TYPEDB_SERVICE_NAME))?;

        // Obtém a porta do host para o serviço TypeDB padrão.
        let typedb_host_port = env.get_service_host_port(constants::TYPEDB_SERVICE_NAME, constants::TYPEDB_INTERNAL_PORT)
            .with_context(|| format!("Falha ao obter porta para {}", constants::TYPEDB_SERVICE_NAME))?;
        // Verifica se a porta mapeada no host é a esperada (1729).
        assert_eq!(typedb_host_port, constants::TYPEDB_HOST_PORT);
        info!("Porta do TypeDB ('{}') no host: {}", constants::TYPEDB_SERVICE_NAME, typedb_host_port);

        // O Drop de `env` chamará `down()` automaticamente.
        Ok(())
    }
}