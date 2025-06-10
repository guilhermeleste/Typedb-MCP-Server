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

//! Infrastructure Helpers para garantir cleanup robusto de containers Docker
//!
//! Este módulo fornece utilitários para:
//! - Verificar se portas estão disponíveis antes de iniciar testes
//! - Forçar cleanup de containers órfãos
//! - Validar que cleanup foi bem-sucedido
//! - Registrar episódios de falha de infraestrutura

use anyhow::{bail, Context, Result};
use std::process::Command;
use tracing::{debug, info, warn};

/// Verifica se uma porta está disponível para uso.
///
/// # Argumentos
/// * `port` - Número da porta a verificar
///
/// # Retorna
/// * `Ok(true)` se a porta está disponível
/// * `Ok(false)` se a porta está em uso
/// * `Err` se houve erro na verificação
pub fn is_port_available(port: u16) -> Result<bool> {
    let output =
        Command::new("ss").args(["-tlnp"]).output().context("Falha ao executar 'ss -tlnp'")?;

    if !output.status.success() {
        bail!("Comando 'ss -tlnp' falhou: {}", String::from_utf8_lossy(&output.stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let port_pattern = format!(":{}\\s", port);
    let is_available = !stdout.contains(&port_pattern);

    debug!("Verificação de porta {}: {}", port, if is_available { "disponível" } else { "em uso" });
    Ok(is_available)
}

/// Lista todos os containers Docker que podem estar relacionados aos testes MCP.
///
/// # Retorna
/// Lista de (container_id, image, status, ports) para containers relacionados a testes
pub fn list_test_containers() -> Result<Vec<(String, String, String, String)>> {
    let output = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"])
        .output()
        .context("Falha ao executar 'docker ps -a'")?;

    if !output.status.success() {
        bail!("Comando 'docker ps -a' falhou: {}", String::from_utf8_lossy(&output.stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut containers = Vec::new();

    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 4 {
            let (id, image, status, ports) = (parts[0], parts[1], parts[2], parts[3]);

            // Filtrar containers relacionados a testes MCP
            if image.contains("mcp")
                || image.contains("typedb")
                || id.contains("mcp")
                || ports.contains("1729")
                || ports.contains("8787")
                || ports.contains("8443")
            {
                containers.push((
                    id.to_string(),
                    image.to_string(),
                    status.to_string(),
                    ports.to_string(),
                ));
            }
        }
    }

    Ok(containers)
}

/// Remove containers órfãos relacionados aos testes.
///
/// # Argumentos
/// * `force` - Se true, para containers rodando antes de remover
///
/// # Retorna
/// Número de containers removidos
pub fn cleanup_orphaned_test_containers(force: bool) -> Result<usize> {
    let containers = list_test_containers()?;
    let mut removed_count = 0;

    info!("Encontrados {} containers relacionados a testes", containers.len());

    for (container_id, image, status, ports) in containers {
        info!(
            "Processando container: {} (imagem: {}, status: {}, portas: {})",
            container_id, image, status, ports
        );

        // Se o container está rodando e force=true, parar primeiro
        if status.contains("Up") && force {
            info!("Parando container rodando: {}", container_id);
            let stop_output = Command::new("docker")
                .args(["stop", &container_id])
                .output()
                .context(format!("Falha ao parar container {}", container_id))?;

            if !stop_output.status.success() {
                warn!(
                    "Falha ao parar container {}: {}",
                    container_id,
                    String::from_utf8_lossy(&stop_output.stderr)
                );
                continue;
            }
        }

        // Remover o container
        info!("Removendo container: {}", container_id);
        let rm_output = Command::new("docker")
            .args(["rm", &container_id])
            .output()
            .context(format!("Falha ao remover container {}", container_id))?;

        if rm_output.status.success() {
            info!("Container {} removido com sucesso", container_id);
            removed_count += 1;
        } else {
            warn!(
                "Falha ao remover container {}: {}",
                container_id,
                String::from_utf8_lossy(&rm_output.stderr)
            );
        }
    }

    info!("Cleanup concluído: {} containers removidos", removed_count);
    Ok(removed_count)
}

/// Verifica se as portas críticas do MCP estão disponíveis.
///
/// # Retorna
/// * `Ok(())` se todas as portas estão disponíveis
/// * `Err` com detalhes das portas ocupadas
pub fn verify_critical_ports_available() -> Result<()> {
    let critical_ports = [1729, 8787, 8443, 9090]; // TypeDB, MCP HTTP, MCP HTTPS, Prometheus
    let mut occupied_ports = Vec::new();

    for &port in &critical_ports {
        if let Ok(false) = is_port_available(port) {
            occupied_ports.push(port);
        }
    }

    if !occupied_ports.is_empty() {
        bail!(
            "Portas críticas ocupadas: {:?}. Execute cleanup manual antes dos testes.",
            occupied_ports
        );
    }

    debug!("Todas as portas críticas estão disponíveis: {:?}", critical_ports);
    Ok(())
}

/// Executa cleanup completo e verifica que foi bem-sucedido.
///
/// Esta função implementa uma estratégia robusta de cleanup:
/// 1. Lista containers existentes
/// 2. Para e remove containers relacionados a testes
/// 3. Verifica que portas estão livres
/// 4. Retorna relatório detalhado
pub fn robust_cleanup_and_verify() -> Result<()> {
    info!("Iniciando cleanup robusto da infraestrutura de teste");

    // Passo 1: Cleanup de containers órfãos
    let removed_count = cleanup_orphaned_test_containers(true)?;

    // Passo 2: Pequena pausa para garantir que ports sejam liberadas
    std::thread::sleep(std::time::Duration::from_secs(2));

    // Passo 3: Verificar se portas críticas estão disponíveis
    verify_critical_ports_available().context("Falha na verificação de portas após cleanup")?;

    info!("Cleanup robusto concluído com sucesso: {} containers removidos, todas as portas críticas disponíveis", removed_count);
    Ok(())
}

/// Helper para ser usado no início de testes críticos.
///
/// Executa verificação prévia e cleanup se necessário, garantindo
/// que o ambiente está limpo antes de iniciar o teste.
pub fn ensure_clean_test_environment() -> Result<()> {
    debug!("Verificando ambiente limpo antes do teste");

    match verify_critical_ports_available() {
        Ok(()) => {
            debug!("Ambiente já está limpo, prosseguindo com teste");
            Ok(())
        }
        Err(_) => {
            warn!("Ambiente não está limpo, executando cleanup automático");
            robust_cleanup_and_verify()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_port_available_localhost() {
        // Testar uma porta que provavelmente está livre
        let result = is_port_available(65432);
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_test_containers() {
        let result = list_test_containers();
        assert!(result.is_ok());
        // O resultado pode ser vazio se não há containers, mas não deve ser erro
    }

    #[test]
    #[ignore] // Ignorar por padrão pois faz limpeza real
    fn test_cleanup_orphaned_containers() {
        let result = cleanup_orphaned_test_containers(true);
        assert!(result.is_ok());
    }
}
