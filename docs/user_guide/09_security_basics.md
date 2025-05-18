# Guia do Usuário: Considerações Básicas de Segurança

Garantir a segurança do seu Typedb-MCP-Server e dos dados que ele acessa é de suma importância. Esta seção aborda as considerações básicas de segurança que você deve levar em conta ao configurar e operar o servidor.

Para uma discussão mais aprofundada sobre tópicos de segurança, consulte a seção [Segurança Aprofundada](../advanced_topics/security_deep_dive.md) (quando disponível).

## 1. Protegendo a Comunicação com TLS (HTTPS/WSS)

A comunicação entre os clientes MCP e o Typedb-MCP-Server, bem como entre o Typedb-MCP-Server e o TypeDB, deve ser protegida usando TLS (Transport Layer Security) em ambientes de produção.

### a. TLS para o Typedb-MCP-Server (Clientes <-> Servidor MCP)

Habilitar TLS no Typedb-MCP-Server garante que a comunicação entre seus clientes MCP e o servidor seja criptografada (HTTPS para health/metrics, WSS para WebSocket).

* **Como Habilitar:**
  * No seu arquivo de configuração (`typedb_mcp_server_config.toml`), defina `server.tls_enabled = true`.
  * Forneça os caminhos para o seu arquivo de certificado (fullchain) e chave privada:

        ```toml
        [server]
        tls_enabled = true
        tls_cert_path = "/caminho/para/seu/mcp-server.crt" # Certificado do servidor
        tls_key_path = "/caminho/para/sua/mcp-server.key"  # Chave privada do servidor
        ```

* **Certificados:**
  * **Produção:** Use certificados emitidos por uma Autoridade Certificadora (CA) confiável (ex: Let's Encrypt, DigiCert, etc.).
  * **Desenvolvimento/Teste:** Para ambientes locais, você pode gerar certificados autoassinados. O script [`scripts/generate-dev-certs.sh`](../../scripts/generate-dev-certs.sh) (usando `mkcert`) pode ajudar a criar certificados para desenvolvimento. Lembre-se que clientes podem precisar ser configurados para confiar em CAs autoassinadas.
* **Impacto:** Uma vez habilitado, os clientes precisarão se conectar usando `wss://` em vez de `ws://`.

### b. TLS para a Conexão com TypeDB (Servidor MCP <-> TypeDB)

Se o seu servidor TypeDB estiver configurado para usar TLS (o que é recomendado em produção), o Typedb-MCP-Server também deve ser configurado para se conectar a ele via TLS.

* **Como Habilitar:**
  * No seu arquivo de configuração, defina `typedb.tls_enabled = true`.
  * Se o seu TypeDB usa um certificado de uma CA que não é publicamente confiável pelo sistema (ex: CA interna ou certificado autoassinado do TypeDB), você **DEVE** fornecer o caminho para o arquivo PEM da CA raiz em `typedb.tls_ca_path`.

        ```toml
        [typedb]
        tls_enabled = true
        # Obrigatório se o TypeDB usar uma CA customizada/autoassinada
        tls_ca_path = "/caminho/para/sua/typedb-ca.pem"
        ```

* **Importância:** Protege os dados e credenciais em trânsito entre o gateway MCP e o banco de dados TypeDB.

## 2. Autenticação de Clientes com OAuth2/JWT

Para controlar quem pode acessar o Typedb-MCP-Server e quais operações eles podem realizar, você pode habilitar a autenticação OAuth2.

* **Como Habilitar:**
  * Defina `oauth.enabled = true` na sua configuração.
  * Configure `oauth.jwks_uri` para apontar para o endpoint JWKS (JSON Web Key Set) do seu Provedor de Identidade (Authorization Server).
  * **Recomendado:** Configure `oauth.issuer` e `oauth.audience` para validar os claims correspondentes no token JWT.

        ```toml
        [oauth]
        enabled = true
        jwks_uri = "https://seu-auth-server.com/.well-known/jwks.json"
        issuer = ["https://seu-auth-server.com"]
        audience = ["identificador-do-seu-mcp-server"]
        ```

* **Funcionamento:**
  * Clientes MCP devem obter um token JWT de um provedor de identidade confiável.
  * O token deve ser enviado no header `Authorization` (esquema `Bearer`) ao estabelecer a conexão WebSocket.
  * O servidor valida a assinatura, expiração, emissor e público do token.
* **Escopos:**
  * Você pode definir `oauth.required_scopes` para exigir certos escopos para acesso geral ao servidor.
  * Além disso, cada ferramenta MCP pode ter seus próprios requisitos de escopo, que são verificados antes da execução da ferramenta. Se o token do cliente não possuir os escopos necessários, a operação será negada. Consulte a [Referência da API](../reference/api.md) para os escopos por ferramenta.

## 3. Gerenciamento de Credenciais

* **Senha do TypeDB (`TYPEDB_PASSWORD`):**
  * **SEMPRE** forneça a senha do TypeDB através da variável de ambiente `TYPEDB_PASSWORD`.
  * **NUNCA** coloque a senha do TypeDB diretamente no arquivo de configuração TOML, especialmente se este arquivo for versionado no Git.
  * Em ambientes de contêiner, use segredos do Docker/Kubernetes ou mecanismos similares para injetar esta variável de ambiente de forma segura.
* **Chaves Privadas TLS:** Proteja o acesso aos arquivos de chave privada (`tls_key_path`) do seu servidor MCP. Eles devem ter permissões restritas no sistema de arquivos.
* **Segredos OAuth2 (se aplicável ao seu Provedor de Identidade):** Se o seu fluxo de obtenção de token para clientes MCP envolve segredos de cliente OAuth2, esses segredos devem ser gerenciados com segurança pelos clientes e não são uma preocupação direta do Typedb-MCP-Server (que apenas valida os tokens JWT resultantes).

## 4. Limitação de Taxa (Rate Limiting)

O servidor possui um mecanismo de limitação de taxa configurável (seção `[rate_limit]`) para ajudar a mitigar ataques de negação de serviço (DoS) ou abuso por parte de clientes que fazem um número excessivo de requisições.

* **`enabled`**: Por padrão, está habilitado (`true`).
* **`requests_per_second`** e **`burst_size`**: Ajuste esses valores com base na carga esperada e nos padrões de uso dos seus clientes.

## 5. Exposição de Rede

* **Restrinja o acesso:** Exponha o `server.bind_address` e `server.metrics_bind_address` apenas para as redes e hosts que precisam acessá-los. Use firewalls de sistema ou de rede.
* **Interface de Bind:** Usar `0.0.0.0` como endereço de bind fará o servidor escutar em todas as interfaces de rede disponíveis. Se você deseja restringir a uma interface específica (ex: apenas localhost para testes, ou uma interface de rede interna), especifique o IP dessa interface.

## 6. Manutenção e Atualizações

* **Mantenha o Servidor Atualizado:** Aplique atualizações do Typedb-MCP-Server à medida que forem lançadas, pois podem conter correções de segurança.
* **Mantenha as Dependências Atualizadas:** Monitore as dependências do Rust (incluindo o próprio Rust, OpenSSL/Rustls, Axum, Tokio) e do sistema operacional para vulnerabilidades conhecidas e aplique patches. O `cargo audit` pode ser usado para verificar vulnerabilidades em dependências Rust (mais relevante para desenvolvedores).
* **Monitore Logs:** Revise os logs do servidor regularmente para atividades suspeitas ou erros inesperados.

## 7. Configuração de CORS (`[cors]`)

* Se seus clientes MCP são baseados em navegador e hospedados em um domínio diferente do Typedb-MCP-Server, você precisará configurar o CORS.
* **`allowed_origins`**: Seja o mais restritivo possível. Evite usar `["*"]` em produção, a menos que seja absolutamente necessário e você entenda as implicações de segurança. Especifique os domínios exatos que têm permissão para fazer requisições.

## Próximos Passos

* Consulte a [Referência Completa de Configuração](../reference/configuration.md) para detalhes sobre como ajustar cada uma dessas opções.
* Para um mergulho mais profundo em considerações de segurança, veja [Segurança Aprofundada](../advanced_topics/security_deep_dive.md) (quando disponível).
