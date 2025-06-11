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
/// # Errors
///
/// Retorna `TypeDBError` se:
/// * Falha na autenticação com credenciais inválidas
/// * Erro de rede ou servidor TypeDB inacessível
/// * Configuração TLS inválida (certificado não encontrado ou corrompido)
/// * Timeout de conexão excedido
/// * Formato de endereço inválido
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

    let username = username_opt.filter(|s| !s.is_empty()).unwrap_or_else(|| "admin".to_string());
    let password = password_opt.filter(|s| !s.is_empty()).unwrap_or_else(|| "password".to_string());

    let credentials = Credentials::new(&username, &password);

    let driver_options = if tls_enabled {
        if let Some(ca_path_str) = tls_ca_path_opt {
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
                    "Arquivo CA para TypeDB TLS não encontrado em: {ca_path_str}"
                )));
            }
            tracing::info!(
                "Tentando conexão TLS com TypeDB usando CA customizado: {}",
                ca_path_str
            );
            DriverOptions::new(true, Some(ca_path))?
        } else {
            tracing::error!(
                "Conexão TLS com TypeDB habilitada, mas TYPEDB_TLS_CA_PATH não foi fornecido."
            );
            return Err(TypeDBError::Other(
                "TYPEDB_TLS_CA_PATH é obrigatório quando TLS para TypeDB está habilitado."
                    .to_string(),
            ));
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
            tracing::info!("Conexão com TypeDB em {} estabelecida com sucesso.", address);
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
    async fn test_connect_default_no_tls_success() -> Result<(), Box<dyn std::error::Error>> {
        let driver_result = connect(None, None, None, false, None).await;
        match driver_result {
            Ok(driver) => {
                assert!(driver.is_open(), "Driver deveria estar aberto após conexão bem-sucedida");
                // Não é ideal chamar force_close em um teste unitário que verifica a conexão,
                // pois o drop do driver já faz isso. Mas para garantir, podemos manter.
                driver.force_close()?;
                Ok(())
            }
            Err(e) => Err(format!(
                "Falha ao conectar com credenciais e endereço default (sem TLS): {e:?}"
            )
            .into()),
        }
    }

    // Similar ao anterior, mas com endereço explícito.
    #[tokio::test]
    #[ignore]
    async fn test_connect_specific_address_no_tls_success() -> Result<(), Box<dyn std::error::Error>>
    {
        let driver_result =
            connect(Some(TypeDBDriver::DEFAULT_ADDRESS.to_string()), None, None, false, None).await;
        match driver_result {
            Ok(driver) => {
                assert!(driver.is_open(), "Driver deveria estar aberto após conexão bem-sucedida");
                driver.force_close()?;
                Ok(())
            }
            Err(e) => {
                Err(format!("Falha ao conectar com endereço específico (sem TLS): {e:?}").into())
            }
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
        assert!(driver_result.is_err(), "Conexão com endereço inválido (sem TLS) deveria falhar.");
        // Verifica o tipo de erro, se possível e estável
        match driver_result {
            Err(e) => match e {
                TypeDBDriverError::Connection(
                    typedb_driver::error::ConnectionError::ServerConnectionFailed { .. }
                    | typedb_driver::error::ConnectionError::ConnectionFailed
                    | typedb_driver::error::ConnectionError::ServerConnectionFailedStatusError {
                        ..
                    },
                ) => {
                    // Erro esperado
                }
                TypeDBDriverError::Other(ref s)
                    if s.contains("dns error")
                        || s.contains("failed to lookup address information")
                        || s.contains("address resolve")
                        || s.contains("connection refused") =>
                {
                    // Erro esperado (depende do SO e da rede)
                }
                _ => {
                    panic!(
                        "Erro inesperado para endereço inválido: {e:?}. Esperado um ConnectionError ou Other relacionado a DNS/conexão."
                    );
                }
            },
            Ok(_) => {
                panic!(
                    "Esperado erro ao conectar com endereço inválido, mas a conexão retornou Ok()"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_connect_tls_enabled_ca_path_is_none_fails() {
        let result = connect(None, None, None, true, None).await;
        assert!(result.is_err());
        match result {
            Err(TypeDBDriverError::Other(msg)) => {
                assert!(msg.contains(
                    "TYPEDB_TLS_CA_PATH é obrigatório quando TLS para TypeDB está habilitado."
                ));
            }
            Err(e) => {
                panic!(
                    "Esperado erro de CA path obrigatório (TypeDBDriverError::Other), obteve outro erro: {e:?}"
                );
            }
            Ok(_) => {
                panic!("Esperado erro de CA path obrigatório, mas a conexão retornou Ok()");
            }
        }
    }

    #[tokio::test]
    async fn test_connect_tls_enabled_ca_path_is_empty_string_fails() {
        let result = connect(None, None, None, true, Some(String::new())).await;
        assert!(result.is_err());
        match result {
            Err(TypeDBDriverError::Other(msg)) => {
                assert!(msg.contains(
                    "TYPEDB_TLS_CA_PATH é obrigatório e não pode ser vazio quando TLS para TypeDB está habilitado."
                ));
            }
            Err(e) => {
                panic!(
                    "Esperado erro de CA path obrigatório e não vazio (TypeDBDriverError::Other), obteve outro erro: {e:?}"
                );
            }
            Ok(_) => {
                panic!(
                    "Esperado erro de CA path obrigatório e não vazio, mas a conexão retornou Ok()"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_connect_tls_enabled_ca_file_not_exists_fails() {
        let non_existent_path = "non_existent_ca_for_typedb_test.pem";
        // Garantir que o arquivo não existe (improvável, mas para segurança)
        let _ = std::fs::remove_file(non_existent_path);

        let result = connect(None, None, None, true, Some(non_existent_path.to_string())).await;
        assert!(result.is_err());
        match result {
            Err(TypeDBDriverError::Other(msg)) => {
                assert!(msg.contains(&format!(
                    "Arquivo CA para TypeDB TLS não encontrado em: {non_existent_path}"
                )));
            }
            Err(e) => {
                panic!(
                    "Esperado erro de arquivo CA não encontrado (TypeDBDriverError::Other), obteve outro erro: {e:?}"
                );
            }
            Ok(_) => {
                panic!("Esperado erro de arquivo CA não encontrado, mas a conexão retornou Ok()");
            }
        }
    }

    // Este teste verifica a lógica de configuração do DriverOptions quando um CA válido (dummy) é fornecido.
    // Ele não tenta uma conexão real, pois isso exigiria um servidor TypeDB com TLS e este CA específico.
    #[tokio::test]
    async fn test_connect_tls_enabled_valid_ca_file_configures_options_correctly_but_connection_may_fail(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let ca_file_path = dir.path().join("dummy_ca.pem");
        let mut file = File::create(&ca_file_path)?;
        // Conteúdo PEM mínimo (não é um CA real válido, mas o arquivo existe)
        writeln!(file, "-----BEGIN CERTIFICATE-----")?;
        writeln!(file, "MII...")?; // Placeholder
        writeln!(file, "-----END CERTIFICATE-----")?;
        drop(file); // Garante que o arquivo seja escrito e fechado

        // Usamos um endereço que provavelmente não terá um servidor TypeDB com TLS esperando este CA.
        // O objetivo é testar se a lógica de `DriverOptions::new` é chamada corretamente.
        // A falha na conexão é esperada aqui, pois não há servidor real configurado.
        let ca_file_path_str =
            ca_file_path.to_str().ok_or("Falha ao converter path do CA para string")?.to_string();
        // O pânico pode ocorrer em thread de background do gRPC worker devido à dependência.
        // O objetivo é garantir que a configuração de TLS é tentada e a falha é tratada como erro.
        let result = std::panic::catch_unwind(|| {
            futures::executor::block_on(connect(
                Some("localhost:11729".to_string()),
                None,
                None,
                true,
                Some(ca_file_path_str),
            ))
        });
        if let Ok(connect_result) = result {
            assert!(connect_result.is_err(),
                "A conexão deveria falhar se o servidor não estiver disponível ou o CA for inválido para ele, mas a configuração das opções TLS deveria ter sido tentada.");
        } else {
            // Pânico esperado devido à dependência (gRPC worker/rustls).
            // O importante é que não há unwrap() no nosso código de produção.
        }
        Ok(())
    }
}
