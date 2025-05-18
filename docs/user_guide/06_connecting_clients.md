
# Guia do Usuário: Conectando Clientes MCP

Após [instalar](./03_installation.md), [configurar](./04_configuration.md) e [executar](./05_running_the_server.md) o Typedb-MCP-Server, o próximo passo é conectar seus clientes que utilizam o Model Context Protocol (MCP).

## Endpoint de Conexão WebSocket

O Typedb-MCP-Server expõe um único endpoint WebSocket para todas as interações MCP.

* **URL Padrão (Sem TLS):** `ws://<host_do_servidor>:<porta_do_servidor>/mcp/ws`
* **URL Padrão (Com TLS Habilitado):** `wss://<host_do_servidor>:<porta_do_servidor>/mcp/ws`

**Detalhes:**

* `<host_do_servidor>`: É o endereço IP ou nome de host onde o Typedb-MCP-Server está escutando, conforme definido em `server.bind_address` na sua configuração (ex: `localhost`, `0.0.0.0` se acessando localmente, ou o IP público/DNS do servidor).
* `<porta_do_servidor>`: É a porta especificada em `server.bind_address` (ex: `8787`).
* `/mcp/ws`: É o path padrão para o endpoint WebSocket. Este path pode ser customizado através da opção `server.mcp_websocket_path` no arquivo de configuração. Se você alterou este valor, ajuste a URL de conexão de acordo.

**Exemplo:**
Se o servidor está configurado com `server.bind_address = "0.0.0.0:8080"` e `server.mcp_websocket_path = "/api/mcp"`, e TLS está desabilitado, a URL de conexão será:
`ws://localhost:8080/api/mcp` (se acessando da mesma máquina)

## Autenticação de Clientes

O Typedb-MCP-Server suporta autenticação opcional de clientes via OAuth2/JWT.

### Cenário 1: OAuth2 Desabilitado

Se a opção `oauth.enabled` estiver definida como `false` (que é o padrão) no arquivo de configuração do servidor, nenhuma autenticação especial é necessária para estabelecer a conexão WebSocket. O cliente pode se conectar diretamente ao endpoint.

### Cenário 2: OAuth2 Habilitado

Se `oauth.enabled = true`, o servidor exigirá que o cliente se autentique usando um Bearer Token JWT.

**Como o Cliente se Autentica:**

1. **Obtenção do Token:** O cliente MCP é responsável por obter um token JWT válido de um Provedor de Identidade (Authorization Server) configurado e confiável pelo Typedb-MCP-Server. O processo de obtenção do token (ex: fluxo Authorization Code, Client Credentials) está fora do escopo do Typedb-MCP-Server e depende da implementação do cliente e do provedor de identidade.
2. **Envio do Token:** Ao iniciar a conexão WebSocket, o cliente DEVE incluir o token JWT no header `Authorization` da requisição HTTP de upgrade para WebSocket. O esquema de autenticação deve ser `Bearer`.

    **Exemplo de Header HTTP (na requisição de upgrade WebSocket):**

    ```http
    GET /mcp/ws HTTP/1.1
    Host: <host_do_servidor>:<porta_do_servidor>
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
    Sec-WebSocket-Version: 13
    Authorization: Bearer <SEU_TOKEN_JWT_AQUI>
    ```

**Validação do Token pelo Servidor:**

Quando o Typedb-MCP-Server recebe uma tentativa de conexão com OAuth2 habilitado, ele realiza as seguintes validações no token JWT fornecido:

* **Assinatura:** Verifica a assinatura do token usando as chaves públicas obtidas do `jwks_uri` configurado.
* **Expiração (exp):** Garante que o token não expirou.
* **Não Antes De (nbf):** Garante que o token já é válido (se o claim estiver presente).
* **Emissor (iss):** Se `oauth.issuer` estiver configurado, verifica se o emissor do token corresponde a um dos emissores esperados.
* **Público (aud):** Se `oauth.audience` estiver configurado, verifica se o público do token corresponde a um dos públicos esperados (geralmente, um identificador para este servidor MCP).
* **Escopos Gerais (required_scopes):** Se `oauth.required_scopes` estiver configurado, verifica se o token contém todos os escopos listados como necessários para acesso geral ao servidor.

**Falha na Autenticação:**
Se a autenticação falhar por qualquer um dos motivos acima (token ausente, inválido, expirado, issuer/audience incorreto, escopos gerais ausentes), a conexão WebSocket **não será estabelecida** e o servidor normalmente responderá com um código de erro HTTP (como `401 Unauthorized` ou `403 Forbidden`) à tentativa de upgrade.

### Escopos OAuth2 e Ferramentas MCP

Mesmo que a autenticação inicial seja bem-sucedida, algumas ferramentas MCP específicas podem exigir escopos OAuth2 adicionais no token JWT do cliente.

* **Escopos Gerais:** Como mencionado acima, a configuração `oauth.required_scopes` pode definir escopos necessários para qualquer interação básica com o servidor.
* **Escopos por Ferramenta:** Cada ferramenta MCP (ex: `query_read`, `create_database`) tem uma lista associada de escopos que o token do cliente deve possuir para que a ferramenta seja executada. Se um cliente autenticado tentar chamar uma ferramenta para a qual não possui os escopos necessários, a chamada da ferramenta resultará em um erro MCP de autorização.

Consulte a [Referência da API (Ferramentas MCP)](../reference/api.md) para ver os escopos necessários para cada ferramenta.

## Exemplo de Conexão com `wscat` (sem OAuth2)

`wscat` é uma ferramenta de linha de comando útil para interagir com WebSockets.

```bash
# Instalar wscat (se ainda não tiver): npm install -g wscat
wscat -c ws://localhost:8787/mcp/ws
```

Após conectar, você pode enviar mensagens JSON-RPC MCP manualmente.

## Exemplo de Conexão com `wscat` (com OAuth2)

```bash
# Obtenha seu token JWT primeiro
TOKEN="SEU_TOKEN_JWT_AQUI"

wscat -c ws://localhost:8787/mcp/ws -H "Authorization: Bearer $TOKEN"
```

## Considerações para Clientes

* **Implementação MCP:** O cliente deve ser capaz de enviar e receber mensagens JSON-RPC conforme a especificação do Model Context Protocol.
* **Gerenciamento de Token (OAuth2):** Se OAuth2 estiver habilitado, o cliente é responsável por adquirir e renovar tokens JWT.
* **Tratamento de Erros:** O cliente deve estar preparado para tratar erros de conexão, autenticação e erros retornados pelas ferramentas MCP.
* **TLS:** Se o servidor estiver usando `wss://`, o cliente WebSocket deve suportar TLS e, idealmente, validar o certificado do servidor. Para ambientes de desenvolvimento com certificados autoassinados, o cliente pode precisar ser configurado para confiar na CA local ou ignorar a validação do certificado (não recomendado para produção).

## Próximos Passos

* Entenda quais [Ferramentas MCP](./07_mcp_tools_overview.md) estão disponíveis.
* Consulte a [Referência da API](../reference/api.md) para detalhes sobre cada ferramenta e seus parâmetros.
