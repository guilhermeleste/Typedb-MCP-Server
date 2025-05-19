
# Guia do Usuário: Solução de Problemas Comuns (Troubleshooting)

Esta seção aborda alguns problemas comuns que você pode encontrar ao instalar, configurar ou executar o Typedb-MCP-Server, juntamente com sugestões para resolvê-los.

## 1. O Servidor Não Inicia

### Sintomas Comuns ao Iniciar

* O processo do servidor encerra imediatamente após a execução.
* Você vê mensagens de erro no console logo após tentar iniciar.

### Causas e Soluções para Falha na Inicialização

* **Configuração Inválida ou Ausente:**
  * **Verifique os Logs:** Os primeiros logs do servidor geralmente indicam se houve um problema ao carregar a configuração. Procure por mensagens como "Erro fatal ao carregar a configuração".
  * **Caminho do Arquivo de Configuração:** Certifique-se de que o arquivo `typedb_mcp_server_config.toml` está no local esperado (diretório de trabalho) ou que a variável de ambiente `MCP_CONFIG_PATH` está apontando para o local correto.
  * **Sintaxe TOML:** Verifique se o seu arquivo TOML está sintaticamente correto. Validadores TOML online podem ajudar.
  * **Opções Obrigatórias:** Certifique-se de que opções obrigatórias (como `typedb.address` e `server.bind_address`) estão presentes e válidas. Consulte a [Referência de Configuração](../reference/configuration.md).

* **Porta já em Uso:**
  * **Mensagem de Erro:** Procure por erros como "Address already in use" (ou similar, dependendo do sistema operacional) nos logs para `server.bind_address` ou `server.metrics_bind_address`.
  * **Solução:** Altere a porta na configuração para uma que esteja livre ou pare o processo que está usando a porta conflitante. Ferramentas como `netstat` (Linux/Windows) ou `lsof` (macOS/Linux) podem ajudar a identificar qual processo está usando a porta.

        ```bash
        # Linux/macOS
        sudo netstat -tulnp | grep <numero_da_porta>
        sudo lsof -i :<numero_da_porta>
        # Windows
        netstat -ano | findstr "<numero_da_porta>"
        ```

* **Falha na Conexão com TypeDB na Inicialização:**
  * **Mensagem de Erro:** Logs como "Falha fatal ao conectar com TypeDB" ou erros do `typedb_driver`.
  * **Causas:**
    * TypeDB Server não está em execução ou não está acessível no `typedb.address` configurado.
    * Firewall bloqueando a conexão.
    * Credenciais TypeDB incorretas (verifique `typedb.username` e a variável de ambiente `TYPEDB_PASSWORD`).
    * Problemas de TLS se `typedb.tls_enabled = true` (certificado CA inválido, nome do host não corresponde, etc.).
  * **Solução:** Verifique a conectividade com o TypeDB, as credenciais e as configurações de TLS.

* **Problemas com Certificados TLS (Se TLS do servidor habilitado):**
  * **Mensagem de Erro:** Erros relacionados a "permission denied" ao ler os arquivos de certificado/chave, ou "failed to load certificate".
  * **Causas:**
    * Caminhos para `server.tls_cert_path` ou `server.tls_key_path` estão incorretos.
    * Os arquivos de certificado/chave não existem ou não são legíveis pelo usuário que executa o servidor.
    * Formato de certificado/chave inválido.
  * **Solução:** Verifique os caminhos, permissões e a validade dos arquivos de certificado.

## 2. Clientes Não Conseguem se Conectar ao WebSocket MCP

### Sintomas de Falha na Conexão WebSocket

* O cliente WebSocket recebe um erro de conexão imediato (ex: "Connection refused", erro HTTP 4xx/5xx durante o handshake).
* A conexão WebSocket é estabelecida, mas depois cai ou as mensagens MCP não funcionam.

### Causas e Soluções para Falha na Conexão WebSocket

* **URL Incorreta:**
  * Verifique se o cliente está usando a URL correta: `ws://<host>:<porta>/<path>` ou `wss://...` se TLS estiver habilitado.
  * Confirme o host, porta (de `server.bind_address`) e o path (de `server.mcp_websocket_path`).

* **Firewall:** Um firewall no servidor ou entre o cliente e o servidor pode estar bloqueando a porta.

* **TLS Desabilitado no Cliente para Servidor com TLS (ou vice-versa):**
  * Se `server.tls_enabled = true`, o cliente DEVE usar `wss://`.
  * Se `server.tls_enabled = false`, o cliente DEVE usar `ws://`.

* **Problemas com Certificado TLS do Servidor (se usando WSS):**
  * Se você estiver usando certificados autoassinados para desenvolvimento, o cliente WebSocket pode precisar ser configurado para confiar na sua CA local ou para ignorar a validação de certificado (não recomendado para produção).
  * Verifique se o nome do host na URL do cliente corresponde ao nome comum (CN) ou aos Nomes Alternativos de Requerente (SANs) no certificado do servidor.

* **OAuth2 Habilitado e Token Ausente/Inválido:**
  * Se `oauth.enabled = true`:
    * O cliente DEVE enviar um header `Authorization: Bearer <token_jwt>` na requisição de upgrade do WebSocket.
    * Se o token estiver ausente, malformado, expirado, com assinatura inválida, ou com issuer/audience/escopos gerais incorretos, o servidor rejeitará a conexão (geralmente com HTTP 401 ou 403).
    * Verifique os logs do servidor MCP para mensagens de erro de autenticação.

* **Problemas de CORS (para clientes baseados em navegador):**
  * Se o cliente é uma aplicação web rodando em um domínio diferente do servidor MCP, você precisará configurar `cors.allowed_origins` corretamente.
  * Verifique o console do navegador por erros CORS.

## 3. Chamadas de Ferramentas MCP Falham

### Sintomas de Falha nas Chamadas de Ferramentas

* O cliente recebe uma resposta de erro JSON-RPC do servidor após chamar uma ferramenta.

### Causas e Soluções para Falhas em Chamadas de Ferramentas

* **Erro de Autenticação/Autorização:**
  * **Mensagem de Erro MCP:** Verifique o `code` e `message` no objeto `error` da resposta JSON-RPC. Códigos como `-32000` (Authentication Failed) ou `-32001` (Authorization Failed) são comuns.
  * **Causas:**
    * OAuth2 habilitado, mas o token expirou durante a sessão.
    * O token não possui os escopos OAuth2 necessários para a ferramenta específica. Verifique os [escopos requeridos na Referência da API](../reference/api.md).
  * **Solução:** O cliente pode precisar reautenticar ou solicitar um token com os escopos corretos.

* **Parâmetros Inválidos para a Ferramenta:**
  * **Mensagem de Erro MCP:** Código `-32602` (Invalid Params) ou uma mensagem indicando que os argumentos são inválidos.
  * **Solução:** Verifique se os `arguments` enviados na chamada `tools/call` correspondem ao schema de entrada esperado pela ferramenta (definido em `src/tools/params.rs` e documentado na [Referência da API](../reference/api.md)).

* **Erro Interno do Servidor ou Erro do TypeDB:**
  * **Mensagem de Erro MCP:** Código `-32603` (Internal Error) ou outros códigos específicos. A mensagem pode conter detalhes do erro original do TypeDB.
  * **Solução:**
    * Verifique os logs do Typedb-MCP-Server (com nível `DEBUG` ou `TRACE` para `typedb_mcp_server_lib` e `typedb_driver`) para obter mais detalhes sobre o erro.
    * Verifique os logs do servidor TypeDB.
    * Pode ser um problema com a consulta TypeQL enviada, o estado do banco de dados, ou um bug no servidor.

* **Banco de Dados Não Encontrado ou Esquema Incompatível:**
  * Muitas ferramentas requerem um `databaseName`. Certifique-se de que o banco existe e que o esquema é compatível com a operação que você está tentando realizar.

## 4. Problemas de Performance

### Sintomas de Problemas de Performance

* Latência alta nas respostas das ferramentas MCP.
* Consumo excessivo de CPU ou memória pelo servidor.

### Causas e Soluções para Problemas de Performance

* **Consultas TypeQL Ineficientes:** Consultas complexas ou mal otimizadas podem sobrecarregar o TypeDB. Analise e otimize suas consultas.
* **Carga Elevada no TypeDB:** O próprio servidor TypeDB pode estar sob alta carga. Monitore os recursos do TypeDB.
* **Carga Elevada no Typedb-MCP-Server:**
  * Muitas conexões WebSocket ativas.
  * Volume alto de chamadas de ferramentas.
  * Monitore as métricas Prometheus do servidor, especialmente `tool_call_duration_seconds` e `typedb_request_duration_seconds` para identificar gargalos.
  * Considere aumentar o número de `server.worker_threads` se o servidor estiver limitado por CPU em tarefas de processamento (mas observe que a maior parte do trabalho é I/O bound).
* **Rede:** Latência de rede entre o cliente e o servidor MCP, ou entre o servidor MCP e o TypeDB.

## 5. Coletando Informações para Suporte

Se você precisar reportar um problema ou pedir ajuda, fornecer as seguintes informações pode ser muito útil:

* **Versão do Typedb-MCP-Server:** (Obtida do `Cargo.toml` ou logs de inicialização).
* **Versão do TypeDB Server.**
* **Configuração relevante do Typedb-MCP-Server:** (O conteúdo do seu arquivo TOML, omitindo segredos, e quaisquer variáveis de ambiente relevantes).
* **Logs Completos:** Logs do Typedb-MCP-Server, idealmente com um nível de depuração aumentado (`RUST_LOG=trace` ou `RUST_LOG=debug,typedb_mcp_server_lib=trace,typedb_driver=trace`).
* **Logs do TypeDB Server:** Se o problema parecer relacionado ao banco.
* **Passos para Reproduzir o Problema:** De forma clara e concisa.
* **Comportamento Esperado vs. Comportamento Real.**
* **Mensagens de Erro Exatas:** Copie e cole as mensagens de erro completas.

---

Se o seu problema não estiver listado aqui, ou se as soluções propostas não ajudarem, por favor, considere abrir uma [issue no GitHub](https://github.com/guilhermeleste/Typedb-MCP-Server/issues) com o máximo de detalhes possível.
