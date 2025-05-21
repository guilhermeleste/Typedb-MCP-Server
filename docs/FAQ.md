
# Perguntas Frequentes (FAQ) - Typedb-MCP-Server

Esta seção contém respostas para perguntas frequentes sobre o Typedb-MCP-Server.

## Perguntas Gerais

**P1: O que é o Typedb-MCP-Server?**
R: O Typedb-MCP-Server é um servidor gateway implementado em Rust. Ele usa o Model Context Protocol (MCP) para permitir que aplicações clientes interajam com um banco de dados TypeDB. Ele facilita a execução de consultas TypeQL, operações de esquema e gerenciamento de banco de dados através de uma interface padronizada.

**P2: Para que serve o Model Context Protocol (MCP)?**
R: O Model Context Protocol é um protocolo projetado para permitir que modelos de IA (como LLMs) e outras aplicações interajam com diversas ferramentas e fontes de dados de forma padronizada. No contexto deste servidor, ele define como os clientes solicitam operações (ferramentas) ao TypeDB.

**P3: Preciso conhecer Rust para usar o Typedb-MCP-Server?**
R: Não. Para usar o servidor como um gateway (ou seja, conectar um cliente MCP a ele para interagir com o TypeDB), você não precisa conhecer Rust. Você só precisa saber como instalar, configurar e executar o servidor, e como seu cliente MCP se comunica via WebSocket e JSON-RPC. Conhecimento de Rust é necessário apenas se você pretende contribuir com o desenvolvimento do próprio servidor.

## Instalação e Configuração

**P4: Qual a maneira mais fácil de executar o Typedb-MCP-Server?**
R: Para desenvolvimento e testes, a maneira mais fácil é geralmente usando Docker Compose com o arquivo `docker-compose.yml` fornecido no projeto. Ele orquestra tanto o Typedb-MCP-Server quanto uma instância do TypeDB. Veja o [Guia de Instalação (Docker)](./user_guide/03_installation.md#2-usando-docker).

**P5: Onde devo colocar a senha do meu TypeDB?**
R: A senha do TypeDB **NUNCA** deve ser colocada diretamente no arquivo de configuração TOML. Ela **DEVE** ser fornecida através da variável de ambiente `TYPEDB_PASSWORD`.

   ```bash
   export TYPEDB_PASSWORD="sua_senha_typedb"
   ```

**P6: Como sei qual versão do Rust é necessária para compilar o servidor?**
R: A versão exata da toolchain Rust (incluindo a versão do compilador) está especificada no arquivo [`rust-toolchain.toml`](../rust-toolchain.toml) na raiz do projeto.

**P7: O servidor não inicia e mostra um erro "Address already in use". O que fazer?**
R: Este erro significa que a porta que o Typedb-MCP-Server está tentando usar (para o endpoint MCP ou para o endpoint de métricas) já está sendo usada por outro processo em sua máquina.
    *Verifique a configuração `server.bind_address` e `server.metrics_bind_address`.
    *   Use ferramentas como `netstat -tulnp | grep <porta>` (Linux) ou `lsof -i :<porta>` (macOS) para descobrir qual processo está usando a porta.
    *   Você pode parar o outro processo ou alterar a porta na configuração do Typedb-MCP-Server para uma que esteja livre. Veja mais em [Troubleshooting](./user_guide/10_troubleshooting.md#1-o-servidor-não-inicia).

**P8: Preciso configurar TLS?**
R: Para ambientes de desenvolvimento local, o TLS pode ser opcional. No entanto, para **ambientes de produção, é altamente recomendável habilitar TLS** tanto para o Typedb-MCP-Server (`server.tls_enabled = true`) quanto para a conexão com o TypeDB (`typedb.tls_enabled = true`) para proteger os dados em trânsito. Consulte a [Referência de Configuração](../reference/configuration.md) e [Segurança Básica](./user_guide/09_security_basics.md).

## Conexão e Autenticação

**P9: Como meu cliente MCP se conecta ao servidor?**
R: Seu cliente deve se conectar ao endpoint WebSocket exposto pelo servidor. O URL padrão é `ws://<host>:<porta>/mcp/ws` (ou `wss://` se o TLS do servidor estiver habilitado). Consulte [Conectando Clientes MCP](./user_guide/06_connecting_clients.md).

**P10: Preciso de autenticação para usar o servidor?**
R: Por padrão, a autenticação OAuth2 está desabilitada. Se `oauth.enabled = false` na configuração, clientes podem se conectar sem um token. Se `oauth.enabled = true`, os clientes devem apresentar um Bearer Token JWT válido no header `Authorization` da requisição de upgrade WebSocket.

**P11: Como funciona a autenticação OAuth2 com o Typedb-MCP-Server?**
R: Quando habilitado, o servidor espera um token JWT. Ele valida a assinatura do token usando chaves públicas de um `jwks_uri` configurado, e também verifica claims como `exp` (expiração), `iss` (emissor) e `aud` (público). Algumas ferramentas MCP também podem exigir escopos específicos no token. Consulte [Conectando Clientes MCP](./user_guide/06_connecting_clients.md) e a [Referência da API](../reference/api.md).

**P12: Meu cliente está recebendo erros 401 Unauthorized ou 403 Forbidden ao tentar conectar ao WebSocket. Por quê?**
R: Se o OAuth2 estiver habilitado:
    *Certifique-se de que seu cliente está enviando o token JWT corretamente no header `Authorization: Bearer <token>`.
    *   Verifique se o token não está expirado.
    *Confirme se o `issuer` e `audience` no token correspondem à configuração do servidor.
    *   Verifique se o token possui os `oauth.required_scopes` gerais, se definidos no servidor.
    *   Consulte os logs do servidor para mensagens de erro de autenticação mais detalhadas.

## Uso das Ferramentas MCP

**P13: Quais ferramentas MCP estão disponíveis?**
R: O servidor oferece ferramentas para consulta de dados, operações de esquema e administração de banco de dados. Para uma lista completa, suas descrições, parâmetros e escopos OAuth2 necessários, consulte a [Referência da API (Ferramentas MCP)](../reference/api.md).

**P14: Como meu cliente sabe quais ferramentas e parâmetros usar?**
R: Um cliente MCP pode usar a requisição `tools/list` do protocolo MCP para descobrir as ferramentas disponíveis no servidor e o schema de entrada (JSON Schema) para os argumentos de cada ferramenta.

**P15: Recebi um erro `PERMISSION_DENIED` ou um erro de autorização ao chamar uma ferramenta. O que isso significa?**
R: Se o OAuth2 estiver habilitado, isso geralmente significa que o token JWT fornecido pelo seu cliente não possui os escopos OAuth2 necessários para executar aquela ferramenta específica. Verifique os escopos do seu token e os escopos requeridos pela ferramenta na [Referência da API](../reference/api.md).

## Observabilidade

**P16: Como posso monitorar a saúde do servidor?**
R: O servidor expõe dois endpoints de health check:
    *`livez`: Indica se o processo do servidor está em execução.
    *   `/readyz`: Indica se o servidor e suas dependências (TypeDB, JWKS se OAuth2 habilitado) estão prontos para aceitar tráfego.
    Consulte [Observabilidade](./user_guide/08_observability.md) para mais detalhes.

**P17: Onde posso encontrar as métricas do servidor?**
R: As métricas no formato Prometheus são expostas por padrão em `http://<host>:9090/metrics`. O endereço e o path são configuráveis. Veja a [Lista de Métricas](../reference/metrics_list.md) para detalhes.

**P18: Como configuro o nível de log?**
R: Você pode configurar os níveis de log através da variável de ambiente `RUST_LOG` ou da chave `logging.rust_log` no seu arquivo de configuração. O formato é `info,meu_crate=debug`. Veja [Observabilidade](./user_guide/08_observability.md).

## Docker

**P19: Posso executar o Typedb-MCP-Server com uma versão diferente do TypeDB no Docker Compose?**
R: Sim. O arquivo `docker-compose.yml` especifica uma imagem para `typedb-server-dev` (ex: `typedb/typedb:3.2.0`). Você pode alterar a tag dessa imagem para a versão desejada do TypeDB, mas certifique-se de que seja compatível com o `typedb-driver-rust` usado pelo servidor.

**P20: Como faço para persistir os dados do TypeDB ao usar `docker-compose`?**
R: O `docker-compose.yml` fornecido já define um volume nomeado (`typedb-dev-data`) para o serviço `typedb-server-dev`, que persiste os dados do TypeDB entre as execuções de `docker-compose up` e `down`. Se você usar `docker-compose down -v`, esse volume será removido.

## Desenvolvimento e Contribuição

**P21: Como posso contribuir para o projeto?**
R: Ótimo! Por favor, consulte nosso [Guia de Contribuição](../CONTRIBUTING.md) para começar.

**P22: Onde posso encontrar mais detalhes sobre a arquitetura interna?**
R: Para desenvolvedores, o [Guia do Desenvolvedor](../developer_guide/01_introduction.md) e o documento de [Arquitetura](./architecture.md) (ou [Mergulho Profundo na Arquitetura](../developer_guide/03_architecture_deep_dive.md)) são os melhores lugares para começar.

---

Se sua pergunta não foi respondida aqui, por favor, verifique o restante da documentação ou [abra uma issue no GitHub](https://github.com/guilhermeleste/Typedb-MCP-Server/issues).
