# Plano Detalhado de Execução e Depuração dos Testes Falhos

Este plano segue a ordem do mais fácil para o mais difícil, considerando dependências, clareza do erro e impacto. Cada item é um checklist para execução e depuração individual.

---

## Checklist Geral

- [ ] Rodar apenas o teste alvo com `cargo test <nome_do_teste>`
- [ ] Analisar mensagem de erro detalhada
- [ ] Corrigir o problema no código/fonte de teste
- [ ] Reexecutar o teste individualmente
- [ ] Validar se outros testes relacionados também passam
- [ ] Documentar a causa e solução no commit

---

## 1. resources::tests::test_parse_schema_uri_invalid_cases (`src/resources.rs`)

- [x] Rodar: `cargo test test_parse_schema_uri_invalid_cases`
- [x] Verificar se o parser aceita casos inválidos erroneamente
- [x] Corrigir a função de parse para rejeitar os casos esperados
- [x] Garantir que todos os casos de erro estejam cobertos

## 2. error::tests::test_app_error_to_mcp_error_data_for_config_error (`src/error.rs`)

- [x] Rodar: `cargo test test_app_error_to_mcp_error_data_for_config_error`
- [x] Conferir se a mensagem de erro esperada está correta
- [x] Padronizar mensagem de erro ou ajustar assert do teste

## 3. db::tests::test_connect_tls_enabled_valid_ca_file_configures_options_correctly_but_connection_may_fail (`src/db.rs`)

- [x] Rodar: `cargo test test_connect_tls_enabled_valid_ca_file_configures_options_correctly_but_connection_may_fail`
- [x] Garantir que não há `unwrap()` em código de produção
- [x] Corrigir para propagação de erro adequada

## 4. config::tests::test_humantime_duration_parsing (`src/config.rs`) - ADIADO

- [ ] Rodar: `cargo test test_humantime_duration_parsing`
- [ ] Conferir se o valor esperado condiz com o carregado
- [ ] Ajustar default, parsing ou assert conforme necessário

## 5. config::tests::test_vector_of_strings_from_toml_and_env (`src/config.rs`) - ADIADO

- [ ] Rodar: `cargo test test_vector_of_strings_from_toml_and_env`
- [ ] Conferir se o vetor está sendo populado corretamente
- [ ] Ajustar defaults, parsing ou assert

## 6. config::tests::test_load_defaults_when_no_file_or_env_vars (`src/config.rs`)

- [ ] Rodar: `cargo test test_load_defaults_when_no_file_or_env_vars`
- [ ] Conferir se todos os campos obrigatórios têm default
- [ ] Ajustar defaults ou lógica de fallback

## 7. config::tests::test_load_from_toml_file (`src/config.rs`)

- [ ] Rodar: `cargo test test_load_from_toml_file`
- [ ] Conferir se valores do TOML estão sendo aplicados corretamente
- [ ] Ajustar parsing ou assert

## 8. config::tests::test_override_toml_with_env_vars (`src/config.rs`)

- [ ] Rodar: `cargo test test_override_toml_with_env_vars`
- [ ] Conferir se sobrescrita por env está correta
- [ ] Ajustar lógica de sobrescrita/env

## 9. config::tests::test_partial_toml_uses_defaults (`src/config.rs`)

- [ ] Rodar: `cargo test test_partial_toml_uses_defaults`
- [ ] Conferir se defaults são aplicados quando campos faltam
- [ ] Ajustar defaults ou assert

## 10. config::tests::test_humantime_duration_optional_field_not_present (`src/config.rs`)

- [ ] Rodar: `cargo test test_humantime_duration_optional_field_not_present`
- [ ] Conferir se o campo opcional está correto quando ausente
- [ ] Ajustar default ou assert

## 11. auth::tests::test_oauth_middleware_invalid_token_bad_signature (`src/auth.rs`)

- [ ] Rodar: `cargo test test_oauth_middleware_invalid_token_bad_signature`
- [ ] Conferir se as chaves de teste são válidas
- [ ] Corrigir PEM de teste ou lógica de validação

## 12. auth::tests::test_oauth_middleware_valid_token (`src/auth.rs`)

- [ ] Rodar: `cargo test test_oauth_middleware_valid_token`
- [ ] Conferir se as chaves de teste são válidas
- [ ] Corrigir PEM de teste ou lógica de validação

## 13. auth::tests::test_oauth_middleware_expired_token (`src/auth.rs`)

- [ ] Rodar: `cargo test test_oauth_middleware_expired_token`
- [ ] Conferir se as chaves de teste são válidas
- [ ] Corrigir PEM de teste ou lógica de validação

## 14. auth::tests::test_jwks_cache_refresh_and_get_key (`src/auth.rs`)

- [ ] Rodar: `cargo test test_jwks_cache_refresh_and_get_key`
- [ ] Conferir se o JWK de teste é base64 válido
- [ ] Corrigir JWK de teste ou lógica de parsing

---

> Siga a ordem acima para maior eficiência e menor bloqueio entre etapas. Marque cada item ao concluir.
