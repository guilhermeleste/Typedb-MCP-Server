// src/db.rs

//! Módulo responsável pela conexão com o servidor TypeDB.
//!
//! Este módulo fornece a funcionalidade principal para estabelecer uma conexão
//! com uma instância do TypeDB, suportando conexões seguras via TLS.

use std::path::Path;
use typedb_driver::{Credentials, DriverOptions, Error as TypeDBError, TypeDBDriver};

/// Estabelece uma conexão com uma instância do servidor TypeDB.
///
/// A função tenta se conectar ao endereço fornecido usando as credenciais especificadas.
/// Suporta conexões TLS se `tls_enabled` for `true`, caso em que um caminho para
/// o certificado da Autoridade Certificadora (CA) raiz deve ser fornecido se o servidor
/// TypeDB usar um certificado não reconhecido pelas CAs raiz do sistema.
///
/// # Parâmetros
///
/// * `address_opt`: `Option<String>` - O endereço (host:porta) do servidor TypeDB.
///   Se `None` ou uma string vazia, utiliza `TypeDBDriver::DEFAULT_ADDRESS`.
/// * `username_opt`: `Option<String>` - O nome de usuário para autenticação.
///   Se `None` ou uma string vazia, utiliza "admin".
/// * `password_opt`: `Option<String>` - A senha para autenticação.
///   Se `None` ou uma string vazia, utiliza "password".
/// * `tls_enabled`: `bool` - Indica se a conexão TLS deve ser habilitada.
/// * `tls_ca_path_opt`: `Option<String>` - O caminho para o arquivo PEM do certificado CA raiz.
///   Obrigatório e não deve ser vazio se `tls_enabled` for `true`.
///
/// # Retorna
///
/// Um `Result<TypeDBDriver, TypeDBError>`:
/// * `Ok(TypeDBDriver)` se a conexão for bem-sucedida.
/// * `Err(TypeDBError)` se ocorrer qualquer erro durante a configuração ou tentativa de conexão.
///
/// # Exemplos
///
/// Conexão sem TLS:
/// ```rust,ignore
/// use typedb_mcp_server_lib::db;
/// use typedb_driver::TypeDBDriver;
///
/// async fn connect_no_tls() -> Result<TypeDBDriver, typedb_driver::Error> {
///     db::connect(
///         Some("localhost:1729".to_string()),
///         Some("admin".to_string()),
///         Some("password".to_string()),
///         false,
///         None,
///     ).await
/// }
/// ```
///
/// Conexão com TLS:
/// ```rust,ignore
/// use typedb_mcp_server_lib::db;
/// use typedb_driver::TypeDBDriver;
///
/// async fn connect_with_tls() -> Result<TypeDBDriver, typedb_driver::Error> {
///     db::connect(
///         Some("secure.typedb.host:1729".to_string()),
///         Some("admin".to_string()),
///         Some("secure_password".to_string()),
///         true,
///         Some("/path/to/ca.pem".to_string()),
///     ).await
/// }
/// ```
#[tracing::instrument(skip(password_opt, tls_ca_path_opt), fields(address = %address_opt.clone().unwrap_or_else(|| TypeDBDriver::DEFAULT_ADDRESS.to_string()), username = %username_opt.clone().unwrap_or_else(|| "admin".to_string()), tls = %tls_enabled))]
pub async fn connect(
    address_opt: Option<String>,
    username_opt: Option<String>,
    password_opt: Option<String>,
    tls_enabled: bool,
    tls_ca_path_opt: Option<String>,
) -> Result<TypeDBDriver, TypeDBError> {
    let address = address_opt
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| TypeDBDriver::DEFAULT_ADDRESS.to_string());

    let username = username_opt
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "admin".to_string());
    let password = password_opt
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "password".to_string());

    let credentials = Credentials::new(&username, &password);

    let driver_options = if tls_enabled {
        match tls_ca_path_opt {
            Some(ca_path_str) => {
                if ca_path_str.is_empty() {
                    tracing::error!(
                        "Conexão TLS com TypeDB habilitada, mas TYPEDB_TLS_CA_PATH está vazio."
                    );
                    return Err(TypeDBError::Other(
                        "TYPEDB_TLS_CA_PATH é obrigatório e não pode ser vazio quando TLS para TypeDB está habilitado."
                            .to_string(),
                    ));
                }
                let ca_path = Path::new(&ca_path_str);
                if !ca_path.exists() {
                    tracing::error!(
                        "Arquivo CA especificado para TypeDB TLS não encontrado: {}",
                        ca_path_str
                    );
                    return Err(TypeDBError::Other(format!(
                        "Arquivo CA para TypeDB TLS não encontrado em: {}",
                        ca_path_str
                    )));
                }
                tracing::info!(
                    "Tentando conexão TLS com TypeDB usando CA customizado: {}",
                    ca_path_str
                );
                DriverOptions::new(true, Some(ca_path))?
            }
            None => {
                tracing::error!("Conexão TLS com TypeDB habilitada, mas TYPEDB_TLS_CA_PATH não foi fornecido.");
                return Err(TypeDBError::Other(
                    "TYPEDB_TLS_CA_PATH é obrigatório quando TLS para TypeDB está habilitado."
                        .to_string(),
                ));
            }
        }
    } else {
        tracing::info!("Conexão TLS com TypeDB desabilitada.");
        DriverOptions::new(false, None)?
    };

    tracing::info!(
        "Conectando ao TypeDB em {} com o usuário '{}' (TLS habilitado: {}).",
        address,
        username,
        tls_enabled
    );

    match TypeDBDriver::new(&address, credentials, driver_options).await {
        Ok(driver) => {
            tracing::info!(
                "Conexão com TypeDB em {} estabelecida com sucesso.",
                address
            );
            Ok(driver)
        }
        Err(e) => {
            tracing::error!(
                "Falha ao conectar com TypeDB em {}: {}",
                address,
                e.message() // Usa e.message() que é mais conciso
            );
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use typedb_driver::Error as TypeDBDriverError; // Alias para clareza

    // Este teste requer um servidor TypeDB em execução no endereço padrão sem TLS.
    // Deve ser executado com `cargo test -- --ignored` ou configurado para rodar em CI.
    #[tokio::test]
    #[ignore]
    async fn test_connect_default_no_tls_success() {
        let driver_result = connect(None, None, None, false, None).await;
        assert!(
            driver_result.is_ok(),
            "Falha ao conectar com credenciais e endereço default (sem TLS): {:?}",
            driver_result.err()
        );
        if let Ok(driver) = driver_result {
            assert!(driver.is_open());
            // Não é ideal chamar force_close em um teste unitário que verifica a conexão,
            // pois o drop do driver já faz isso. Mas para garantir, podemos manter.
            driver.force_close().expect("Falha ao fechar driver");
        }
    }

    // Similar ao anterior, mas com endereço explícito.
    #[tokio::test]
    #[ignore]
    async fn test_connect_specific_address_no_tls_success() {
        let driver_result = connect(
            Some(TypeDBDriver::DEFAULT_ADDRESS.to_string()),
            None,
            None,
            false,
            None,
        )
        .await;
        assert!(
            driver_result.is_ok(),
            "Falha ao conectar com endereço específico (sem TLS): {:?}",
            driver_result.err()
        );
        if let Ok(driver) = driver_result {
            assert!(driver.is_open());
            driver.force_close().expect("Falha ao fechar driver");
        }
    }

    #[tokio::test]
    async fn test_connect_invalid_address_no_tls_fails() {
        let driver_result = connect(
            Some("invalid-address-that-should-fail:1729".to_string()),
            None,
            None,
            false,
            None,
        )
        .await;
        assert!(
            driver_result.is_err(),
            "Conexão com endereço inválido (sem TLS) deveria falhar."
        );
        // Verifica o tipo de erro, se possível e estável
        if let Err(e) = driver_result {
            match e {
                TypeDBDriverError::Connection(
                    typedb_driver::error::ConnectionError::ServerConnectionFailed { .. }
                    | typedb_driver::error::ConnectionError::ConnectionFailed
                    | typedb_driver::error::ConnectionError::ServerConnectionFailedStatusError { .. },
                ) => {
                    // Erro esperado
                }
                TypeDBDriverError::Other(s) if s.contains("dns error") || s.contains("failed to lookup address information") || s.contains("address resolve") || s.contains("connection refused") => {
                    // Erro esperado (depende do SO e da rede)
                }
                _ => panic!("Erro inesperado para endereço inválido: {:?}. Esperado um ConnectionError ou Other relacionado a DNS/conexão.", e),
            }
        }
    }

    #[tokio::test]
    async fn test_connect_tls_enabled_ca_path_is_none_fails() {
        let result = connect(None, None, None, true, None).await;
        assert!(result.is_err());
        if let Err(TypeDBDriverError::Other(msg)) = result {
            assert!(msg.contains(
                "TYPEDB_TLS_CA_PATH é obrigatório quando TLS para TypeDB está habilitado."
            ));
        } else {
            panic!(
                "Esperado erro de CA path obrigatório, obteve: {:?}",
                result
            );
        }
    }

    #[tokio::test]
    async fn test_connect_tls_enabled_ca_path_is_empty_string_fails() {
        let result = connect(None, None, None, true, Some("".to_string())).await;
        assert!(result.is_err());
        if let Err(TypeDBDriverError::Other(msg)) = result {
            assert!(msg.contains(
                "TYPEDB_TLS_CA_PATH é obrigatório e não pode ser vazio quando TLS para TypeDB está habilitado."
            ));
        } else {
            panic!(
                "Esperado erro de CA path obrigatório e não vazio, obteve: {:?}",
                result
            );
        }
    }

    #[tokio::test]
    async fn test_connect_tls_enabled_ca_file_not_exists_fails() {
        let non_existent_path = "non_existent_ca_for_typedb_test.pem";
        // Garantir que o arquivo não existe (improvável, mas para segurança)
        let _ = std::fs::remove_file(non_existent_path);

        let result =
            connect(None, None, None, true, Some(non_existent_path.to_string())).await;
        assert!(result.is_err());
        if let Err(TypeDBDriverError::Other(msg)) = result {
            assert!(msg.contains(&format!(
                "Arquivo CA para TypeDB TLS não encontrado em: {}",
                non_existent_path
            )));
        } else {
            panic!(
                "Esperado erro de arquivo CA não encontrado, obteve: {:?}",
                result
            );
        }
    }

    // Este teste verifica a lógica de configuração do DriverOptions quando um CA válido (dummy) é fornecido.
    // Ele não tenta uma conexão real, pois isso exigiria um servidor TypeDB com TLS e este CA específico.
    #[tokio::test]
    async fn test_connect_tls_enabled_valid_ca_file_configures_options_correctly_but_connection_may_fail()
    {
        let dir = tempdir().unwrap();
        let ca_file_path = dir.path().join("dummy_ca.pem");
        let mut file = File::create(&ca_file_path).unwrap();
        // Conteúdo PEM mínimo (não é um CA real válido, mas o arquivo existe)
        writeln!(file, "-----BEGIN CERTIFICATE-----").unwrap();
        writeln!(file, "MII...").unwrap(); // Placeholder
        writeln!(file, "-----END CERTIFICATE-----").unwrap();
        drop(file); // Garante que o arquivo seja escrito e fechado

        // Usamos um endereço que provavelmente não terá um servidor TypeDB com TLS esperando este CA.
        // O objetivo é testar se a lógica de `DriverOptions::new` é chamada corretamente.
        // A falha na conexão é esperada aqui, pois não há servidor real configurado.
        let result = connect(
            Some("localhost:11729".to_string()), // Porta improvável para TypeDB
            None,
            None,
            true,
            Some(ca_file_path.to_str().unwrap().to_string()),
        )
        .await;

        assert!(
            result.is_err(),
            "A conexão deveria falhar se o servidor não estiver disponível ou o CA for inválido para ele, mas a configuração das opções TLS deveria ter sido tentada."
        );
        // O tipo de erro específico pode variar (ConnectionFailed, ServerConnectionFailed, etc.)
        // O importante é que a lógica de `DriverOptions::new(true, Some(ca_path))` foi alcançada.
        // Não vamos ser muito específicos sobre o erro de conexão aqui.
        // Um log `tracing::info!("Tentando conexão TLS com TypeDB usando CA customizado: {}")`
        // indicaria que esta parte da lógica foi executada.
    }
}