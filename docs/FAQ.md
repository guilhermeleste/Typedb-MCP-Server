# Perguntas Frequentes (FAQ) - Typedb-MCP-Server

Esta seção contém respostas para perguntas frequentes sobre o Typedb-MCP-Server.

## Perguntas Gerais

**P1: O que é o Typedb-MCP-Server?**
R: O Typedb-MCP-Server é um servidor gateway implementado em Rust. Ele usa o Model Context Protocol (MCP) para permitir que aplicações clientes (como LLMs, ferramentas de desenvolvimento, ou outros microsserviços) interajam com um banco de dados TypeDB. Ele facilita a execução de consultas TypeQL, operações de esquema e gerenciamento de banco de dados através de uma interface padronizada via WebSocket.

**P2: Para que serve o Model Context Protocol (MCP)?**
R: O Model Context Protocol é um protocolo projetado para permitir que modelos de IA e outras aplicações interajam com diversas ferramentas e fontes de dados de forma padronizada. No contexto deste servidor, ele define como os clientes solicitam operações (chamadas de "ferramentas" MCP) ao TypeDB e como recebem os resultados.

**P3: Preciso conhecer Rust para usar o Typedb-MCP-Server?**
R: Não. Para usar o servidor como um gateway (ou seja, conectar um cliente MCP a ele para interagir com o TypeDB), você não precisa conhecer Rust. Você só precisa saber como instalar, configurar e executar o servidor, e como seu cliente MCP se comunica (via WebSocket e JSON-RPC, conforme a especificação MCP). Conhecimento de Rust é necessário apenas se você pretende contribuir com o desenvolvimento do próprio servidor.

## Instalação e Configuração

**P4: Qual a maneira mais fácil de executar o Typedb-MCP-Server para desenvolvimento ou teste rápido?**
R: Para desenvolvimento e testes, a maneira mais fácil é geralmente usando Docker Compose.
    *Para desenvolvimento interativo, use o arquivo `docker-compose.yml`. Ele orquestra o Typedb-MCP-Server (usando `config.dev.toml`) e uma instância do TypeDB (`typedb-server-dev`).
    *   Para executar a suíte de testes de integração, os testes utilizam o `docker-compose.test.yml` internamente, que é gerenciado pelos helpers de teste.
    Consulte o [Guia de Instalação (Docker)](./user_guide/03_installation.md#2-usando-docker).

**P5: Onde devo colocar a senha do meu TypeDB?**
R: A senha do TypeDB **NUNCA** deve ser colocada diretamente no arquivo de configuração TOML.
    *Para o servidor principal (executado via `cargo run` ou binário direto, ou `docker-compose.yml`), ela **DEVE** ser fornecida através da variável de ambiente `TYPEDB_PASSWORD`.
    *   Para os testes de integração (que usam `docker-compose.test.yml`), a senha do TypeDB de teste é controlada pela variável de ambiente `TYPEDB_PASSWORD_TEST` (que tem "password" como default se não definida).

    Exemplo para desenvolvimento:
    ```bash
    export TYPEDB_PASSWORD="sua_senha_typedb"
    ```
    Consulte o arquivo `.env.example` para mais detalhes.

**P6: Como sei qual versão do Rust é necessária para compilar o servidor?**
R: A versão exata da toolchain Rust (incluindo a versão do compilador e componentes como `rustfmt` e `clippy`) está especificada no arquivo [`rust-toolchain.toml`](../../rust-toolchain.toml) na raiz do projeto.

**P7: O servidor não inicia e mostra um erro "Address already in use". O que fazer?**
R: Este erro significa que a porta que o Typedb-MCP-Server está tentando usar (para o endpoint MCP em `server.bind_address` ou para o endpoint de métricas em `server.metrics_bind_address`) já está sendo usada por outro processo em sua máquina.
    *Verifique os valores nos seus arquivos de configuração (ex: `config.dev.toml` para desenvolvimento, ou os arquivos em `tests/test_configs/` se estiver relacionado a um teste específico).
    *   Use ferramentas como `netstat -tulnp | grep <porta>` (Linux) ou `lsof -i :<porta>` (macOS) para descobrir qual processo está usando a porta.
    *Você pode parar o outro processo ou alterar a porta na configuração do Typedb-MCP-Server para uma que esteja livre.
    *   Se estiver rodando testes de integração localmente e encontrar este erro, certifique-se de que não haja outros testes ou instâncias do `docker-compose.test.yml` rodando e usando as mesmas portas de *host* (ex: 8788, 9091). Os testes de integração usam `#[serial_test::serial]` para mitigar isso.
    Veja mais em [Troubleshooting](./user_guide/10_troubleshooting.md#1-o-servidor-não-inicia).

**P8: Preciso configurar TLS?**
R:
    ***Desenvolvimento Local:** O TLS pode ser opcional. Você pode usar os scripts fornecidos (ex: `scripts/generate-test-certs.sh` que usa `mkcert`) para gerar certificados de desenvolvimento e testar a funcionalidade TLS.
    *   **Produção:** É **altamente recomendável habilitar TLS** para proteger a comunicação:
        *Entre clientes MCP e o Typedb-MCP-Server (configurando `server.tls_enabled = true` e fornecendo `server.tls_cert_path` e `server.tls_key_path`).
        *   Entre o Typedb-MCP-Server e seu TypeDB Server (configurando `typedb.tls_enabled = true` e, se necessário, `typedb.tls_ca_path`).
    Consulte a [Referência de Configuração](../reference/configuration.md) e [Segurança Básica](./user_guide/09_security_basics.md).

## Conexão e Autenticação

**P9: Como meu cliente MCP se conecta ao servidor?**
R: Seu cliente deve estabelecer uma conexão WebSocket com o endpoint exposto pelo Typedb-MCP-Server.
    ***URL Padrão (sem TLS no servidor MCP):** `ws://<host_do_servidor_mcp>:<porta_do_servidor_mcp>/mcp/ws`
    *   **URL Padrão (com TLS no servidor MCP):** `wss://<host_do_servidor_mcp>:<porta_do_servidor_mcp>/mcp/ws`
    *O host e a porta são definidos em `server.bind_address` na configuração do servidor. O path (`/mcp/ws`) é o default e pode ser mudado via `server.mcp_websocket_path`.
    *   Para testes de integração, as portas de *host* mapeadas no `docker-compose.test.yml` são usadas (ex: `ws://localhost:8788/mcp/ws`).
    Consulte [Conectando Clientes MCP](./user_guide/06_connecting_clients.md).

**P10: O servidor MCP requer autenticação?**
R: A autenticação é opcional e controlada pela seção `[oauth]` na configuração do servidor.
    *Se `oauth.enabled = false` (padrão), clientes podem se conectar sem um token.
    *   Se `oauth.enabled = true`, os clientes devem apresentar um Bearer Token JWT válido no header `Authorization` da requisição de upgrade WebSocket para estabelecer a conexão.

**P11: Como funciona a autenticação OAuth2 com o Typedb-MCP-Server?**
R: Quando habilitado (`oauth.enabled = true`):
    1.  O cliente obtém um token JWT de um Provedor de Identidade.
    2.  O cliente envia este token no header `Authorization: Bearer <token>` ao tentar conectar ao WebSocket.
    3.  O Typedb-MCP-Server valida o token:
        *Verifica a assinatura usando chaves públicas do `jwks_uri` configurado.
        *   Valida claims padrão como `exp` (expiração), `nbf` (não antes de).
        *Valida `iss` (emissor) e `aud` (público) se `oauth.issuer` e `oauth.audience` estiverem definidos na configuração do servidor.
        *   Verifica se o token possui os escopos globais definidos em `oauth.required_scopes` (se houver).
    4.  Se a validação falhar, a conexão WebSocket é rejeitada (geralmente com HTTP 401 ou 403).
    5.  Mesmo após uma conexão autenticada, ferramentas MCP individuais podem requerer escopos específicos no token para serem executadas.
    Consulte a [Referência de Configuração (OAuth)](../reference/configuration.md#seção-oauth) e a [Referência da API (Escopos por Ferramenta)](../reference/api.md).

**P12: Meu cliente está recebendo erros 401 Unauthorized ou 403 Forbidden ao tentar conectar ao WebSocket. Por quê?**
R: Se o OAuth2 estiver habilitado no servidor:
    ***Token Ausente/Malformado:** Certifique-se de que seu cliente está enviando o token JWT corretamente no header `Authorization: Bearer <token>`.
    *   **Token Inválido:**
        *Verifique se o token não está expirado.
        *   Confirme se a assinatura do token é válida (o servidor MCP deve conseguir obter a chave pública correta do `jwks_uri` para verificá-la).
        *Confirme se o `issuer` e `audience` no token correspondem aos configurados e esperados pelo servidor MCP.
    *   **Escopos Insuficientes:** Verifique se o token possui os `oauth.required_scopes` gerais, se definidos na configuração do servidor. (Escopos específicos de ferramentas são verificados *após* a conexão ser estabelecida).
    *   **Logs do Servidor:** Consulte os logs do Typedb-MCP-Server (idealmente com `typedb_mcp_server_lib::auth=trace`) para mensagens de erro de autenticação mais detalhadas.

## Uso das Ferramentas MCP

**P13: Quais ferramentas MCP estão disponíveis?**
R: O servidor oferece ferramentas para consulta de dados (leitura, escrita, deleção, atualização), operações de esquema (definir, remover, obter) e administração de banco de dados (criar, listar, verificar existência, deletar). Para uma lista completa, suas descrições, parâmetros JSON Schema de entrada, formato de saída e escopos OAuth2 necessários para cada uma, consulte a **[Referência da API (Ferramentas MCP)](../reference/api.md)**.

**P14: Como meu cliente sabe quais ferramentas e parâmetros usar?**
R: Um cliente MCP compatível pode usar a requisição `tools/list` do protocolo MCP para descobrir as ferramentas disponíveis no servidor. A resposta a esta requisição inclui o nome, descrição e o JSON Schema dos parâmetros de entrada (`inputSchema`) para cada ferramenta.

**P15: Recebi um erro `PERMISSION_DENIED` ou um erro de autorização (ex: código -32001) ao chamar uma ferramenta. O que isso significa?**
R: Se o OAuth2 estiver habilitado, isso geralmente significa que o token JWT fornecido pelo seu cliente, embora válido para estabelecer a conexão, não possui os escopos OAuth2 específicos necessários para executar *aquela ferramenta em particular*. Verifique os escopos do seu token e os escopos requeridos pela ferramenta na [Referência da API](../reference/api.md).

## Observabilidade

**P16: Como posso monitorar a saúde do servidor?**
R: O servidor expõe dois endpoints de health check HTTP:
    *`livez` (geralmente em `<base_url>/livez`): Indica se o processo do servidor está em execução e o servidor HTTP base está respondendo. Uma falha aqui é crítica.
    *   `/readyz` (geralmente em `<base_url>/readyz`): Indica se o servidor está pronto para aceitar tráfego e se suas dependências críticas (TypeDB e, se OAuth2 habilitado, o JWKS URI) estão saudáveis. Retorna um JSON com o status geral e o status de cada componente.
    Consulte [Observabilidade](./user_guide/08_observability.md) para mais detalhes.

**P17: Onde posso encontrar as métricas do servidor?**
R: As métricas no formato Prometheus são expostas por padrão em `http://<host_metricas>:<porta_metricas>/metrics`. O endereço (`server.metrics_bind_address`) e o path (`server.metrics_path`) são configuráveis. Para testes de integração, a porta do host mapeada é `9091` por padrão. Veja a [Lista de Métricas](../reference/metrics_list.md) para detalhes sobre as métricas expostas.

**P18: Como configuro o nível de log?**
R: Você pode configurar os níveis de log através da variável de ambiente `RUST_LOG` ou da chave `logging.rust_log` no seu arquivo de configuração TOML. O formato é `info,meu_crate=debug,outro_crate=trace`. Para depuração, aumentar o nível para `typedb_mcp_server_lib` ou `typedb_mcp_server` para `debug` ou `trace` é útil. Veja [Observabilidade](./user_guide/08_observability.md).

## Docker e Testes

**P19: Posso executar o Typedb-MCP-Server com uma versão diferente do TypeDB no Docker Compose?**
R: Sim. O arquivo `docker-compose.yml` (para desenvolvimento) e `docker-compose.test.yml` (para testes) especificam uma imagem para os serviços TypeDB (ex: `typedb/typedb:3.2.0`). Você pode alterar a tag dessa imagem para a versão desejada do TypeDB, mas certifique-se de que seja compatível com a versão do `typedb-driver` Rust usada pelo servidor (atualmente `typedb-driver = "3.2.0"`).

**P20: Como faço para persistir os dados do TypeDB ao usar `docker-compose`?**
R:
    *O `docker-compose.yml` (desenvolvimento) define um volume nomeado (`typedb-dev-data`) para o serviço `typedb-server-dev`, que persiste os dados do TypeDB entre as execuções de `docker compose up` e `down`.
    *   O `docker-compose.test.yml` (testes) também usa volumes nomeados (ex: `typedb_data_it`, `typedb_tls_data_it`), que são automaticamente prefixados com o nome do projeto Docker Compose (gerado unicamente para cada execução de `TestEnvironment`).
    Se você usar `docker compose down -v`, esses volumes de dados serão removidos.

**P21: Por que meus testes de integração estão falhando com erros de 'porta já em uso' ou se comportando de forma estranha quando rodo vários ao mesmo tempo localmente?**
R: Os testes de integração usam portas de host fixas (ex: 8788 para MCP HTTP, 9091 para métricas) definidas no `docker-compose.test.yml` para expor os serviços Docker. Para evitar conflitos, cada função de teste de integração é marcada com `#[serial_test::serial]`, o que garante que apenas um ambiente de teste Docker Compose (e, portanto, um conjunto de mapeamentos de porta) esteja ativo por vez. Se você estiver executando `cargo test` com múltiplos jobs paralelos (`-jN` com N > 1) ou tentando rodar testes individuais em paralelo manualmente, podem ocorrer conflitos. A execução padrão de `cargo test --test integration` deve respeitar a serialização imposta.

## Desenvolvimento e Contribuição

**P22: Como posso contribuir para o projeto?**
R: Ótimo! Por favor, consulte nosso [Guia de Contribuição](../../CONTRIBUTING.md) para começar. Ele detalha o processo de fork, setup do ambiente de desenvolvimento (incluindo Docker, `mkcert`), e o fluxo de PR.

**P23: Onde posso encontrar mais detalhes sobre a arquitetura interna?**
R: Para desenvolvedores que desejam entender a fundo o servidor, o [Guia do Desenvolvedor](../../docs/developer_guide/01_introduction.md) e o documento de [Arquitetura Detalhada](../../docs/developer_guide/03_architecture_deep_dive.md) são os melhores lugares para começar.

---

Se sua pergunta não foi respondida aqui, por favor, verifique o restante da documentação ou [abra uma issue no GitHub](https://github.com/guilhermeleste/Typedb-MCP-Server/issues).
