
# Referência da API do Typedb-MCP-Server

Este documento fornece uma referência detalhada para a API exposta pelo Typedb-MCP-Server. Isso inclui as ferramentas disponíveis através do Model Context Protocol (MCP) via WebSocket e os endpoints HTTP para observabilidade.

## 1. API do Model Context Protocol (MCP)

O Typedb-MCP-Server expõe funcionalidades do TypeDB através de um conjunto de "ferramentas" (tools) definidas pelo Model Context Protocol. Clientes se comunicam com essas ferramentas enviando requisições JSON-RPC através de uma conexão WebSocket.

**Endpoint WebSocket Padrão:** `ws://<host>:<porta>/mcp/ws`

* Se o TLS do servidor estiver habilitado, use `wss://`.
* O host e a porta são definidos pela configuração `server.bind_address`.
* O path `/mcp/ws` é o padrão e pode ser alterado via `server.mcp_websocket_path`.

**Autenticação:**

* Se OAuth2 estiver habilitado (via `oauth.enabled = true` na configuração), todas as conexões WebSocket e, subsequentemente, as chamadas de ferramentas, requerem um Bearer Token JWT válido no header `Authorization` da requisição de upgrade do WebSocket.
* Algumas ferramentas podem exigir escopos OAuth2 específicos no token JWT para serem executadas. Se um escopo obrigatório estiver ausente, a chamada da ferramenta resultará em um erro de autorização.

### Estrutura de Chamada de Ferramenta MCP

As ferramentas são invocadas usando uma mensagem JSON-RPC com o método `tools/call`.

**Exemplo de Requisição `tools/call`:**

```json
{
  "jsonrpc": "2.0",
  "id": "request-id-123",
  "method": "tools/call",
  "params": {
    "name": "nome_da_ferramenta",
    "arguments": {
      "parametro1": "valor1",
      "parametro2": 123
    }
  }
}
```

**Exemplo de Resposta Bem-Sucedida:**

```json
{
  "jsonrpc": "2.0",
  "id": "request-id-123",
  "result": {
    "content": [
      {
        "type": "text", // ou "json", "image", etc.
        "text": "Resultado da ferramenta como string ou JSON stringificado"
      }
      // Pode haver múltiplos blocos de conteúdo
    ],
    "isError": false // Opcional, indica explicitamente sucesso
  }
}
```

**Exemplo de Resposta de Erro:**

```json
{
  "jsonrpc": "2.0",
  "id": "request-id-123",
  "error": {
    "code": -32000, // Código de erro MCP ou específico da aplicação
    "message": "Descrição do erro.",
    "data": {
      "type": "TipoDeErroInterno",
      "detalhe": "Informação adicional sobre o erro"
    }
  }
}
```

### Ferramentas MCP Disponíveis

A seguir, a lista de ferramentas MCP expostas pelo Typedb-MCP-Server.

---

#### 1. Ferramentas de Consulta de Dados (`query.*`)

Estas ferramentas são usadas para ler e modificar dados no TypeDB.

##### **`query_read`**

* **Descrição:** Executa uma consulta TypeQL de leitura (match...get, fetch, aggregate).
* **Escopos OAuth2 Necessários:** `typedb:read_data`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "databaseName": {
          "type": "string",
          "description": "O nome do banco de dados TypeDB alvo para a consulta."
        },
        "query": {
          "type": "string",
          "description": "A consulta TypeQL completa de leitura (ex: `match $x isa person; get;`, `match $p isa person; fetch $p { name, age };`, `match $p isa person; aggregate count;`)."
        }
      },
      "required": ["databaseName", "query"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Para `get`: Uma string JSON representando um array de "Concept Maps" (objetos JSON).
  * Para `fetch`: Uma string JSON representando um array de documentos JSON aninhados.
  * Para `aggregate`: Uma string JSON representando um único valor (número, string, booleano) ou `null`.
* **Exemplo de Chamada:**

    ```json
    {
      "jsonrpc": "2.0",
      "id": "qr1",
      "method": "tools/call",
      "params": {
        "name": "query_read",
        "arguments": {
          "databaseName": "meu_banco",
          "query": "match $p isa person, has name $n; get $n;"
        }
      }
    }
    ```

##### **`insert_data`**

* **Descrição:** Insere dados usando uma consulta TypeQL 'insert'.
* **Escopos OAuth2 Necessários:** `typedb:write_data`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "databaseName": {
          "type": "string",
          "description": "O nome do banco de dados TypeDB alvo para a inserção."
        },
        "query": {
          "type": "string",
          "description": "A consulta TypeQL de inserção completa (ex: `insert $x isa person, has name 'Alice';` ou `match $p isa person, has name 'Bob'; insert $p has age 30;`)."
        }
      },
      "required": ["databaseName", "query"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string JSON representando um array de "Concept Maps" para as variáveis da parte `match` (se houver), ou um objeto JSON indicando sucesso (ex: `{"status": "success", "message": "Dados inseridos..."}`).
* **Exemplo de Chamada:**

    ```json
    {
      "jsonrpc": "2.0",
      "id": "id1",
      "method": "tools/call",
      "params": {
        "name": "insert_data",
        "arguments": {
          "databaseName": "meu_banco",
          "query": "insert $p isa person, has name \"Alice\", has age 30;"
        }
      }
    }
    ```

##### **`delete_data`**

* **Descrição:** Remove dados usando uma consulta TypeQL 'match...delete'.
* **Escopos OAuth2 Necessários:** `typedb:write_data`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "databaseName": {
          "type": "string",
          "description": "O nome do banco de dados TypeDB alvo para a deleção."
        },
        "query": {
          "type": "string",
          "description": "A consulta TypeQL de deleção completa (ex: `match $p isa person, has name 'Alice'; delete $p;`)."
        }
      },
      "required": ["databaseName", "query"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string contendo "OK" em caso de sucesso.
* **Exemplo de Chamada:**

    ```json
    {
      "jsonrpc": "2.0",
      "id": "dd1",
      "method": "tools/call",
      "params": {
        "name": "delete_data",
        "arguments": {
          "databaseName": "meu_banco",
          "query": "match $p isa person, has name \"Alice\"; delete $p;"
        }
      }
    }
    ```

##### **`update_data`**

* **Descrição:** Atualiza dados atomicamente usando 'match...delete...insert'.
* **Escopos OAuth2 Necessários:** `typedb:write_data`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "databaseName": {
          "type": "string",
          "description": "O nome do banco de dados TypeDB alvo para a atualização."
        },
        "query": {
          "type": "string",
          "description": "A consulta TypeQL de atualização completa (ex: `match $p isa person, has name 'Alice', has age $a; delete $p has age $a; insert $p has age 31;`)."
        }
      },
      "required": ["databaseName", "query"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string JSON representando um array de "Concept Maps" para as variáveis da parte `match` (se houver), ou um objeto JSON indicando sucesso.
* **Exemplo de Chamada:**

    ```json
    {
      "jsonrpc": "2.0",
      "id": "ud1",
      "method": "tools/call",
      "params": {
        "name": "update_data",
        "arguments": {
          "databaseName": "meu_banco",
          "query": "match $p isa person, has name 'Alice', has age $a; delete $p has age $a; insert $p has age 31;"
        }
      }
    }
    ```

##### **`validate_query`**

* **Descrição:** Valida uma consulta TypeQL em um banco de dados existente sem executá-la para modificação de dados.
* **Escopos OAuth2 Necessários:** `typedb:validate_queries`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "databaseName": {
          "type": "string",
          "description": "O nome de um banco de dados TypeDB existente. O esquema deste banco será usado como contexto para a validação."
        },
        "query": {
          "type": "string",
          "description": "A consulta TypeQL a ser validada."
        },
        "intendedTransactionType": {
          "type": "string",
          "description": "O tipo de transação para o qual esta consulta se destina. Default: 'read'. Valores permitidos: \"read\", \"write\", \"schema\".",
          "enum": ["read", "write", "schema"]
        }
      },
      "required": ["databaseName", "query"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string contendo "valid" se a consulta for sintaticamente e semanticamente válida contra o esquema do banco.
  * Uma string contendo a mensagem de erro do TypeDB se a consulta for inválida (ex: "ERRO: ...").
* **Exemplo de Chamada:**

    ```json
    {
      "jsonrpc": "2.0",
      "id": "vq1",
      "method": "tools/call",
      "params": {
        "name": "validate_query",
        "arguments": {
          "databaseName": "meu_banco",
          "query": "match $x isa person, has name 'Test'; get $x;",
          "intendedTransactionType": "read"
        }
      }
    }
    ```

---

#### 2. Ferramentas de Operações de Esquema (`schema_ops.*`)

Estas ferramentas são usadas para gerenciar o esquema do TypeDB.

##### **`define_schema`**

* **Descrição:** Define ou estende o esquema usando TypeQL 'define'.
* **Escopos OAuth2 Necessários:** `typedb:manage_schema`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "databaseName": {
          "type": "string",
          "description": "O nome do banco de dados TypeDB cujo esquema será modificado."
        },
        "schemaDefinition": {
          "type": "string",
          "description": "Uma string contendo uma ou mais declarações TypeQL `define` válidas (ex: `define person sub entity, owns name; name sub attribute, value string;`)."
        }
      },
      "required": ["databaseName", "schemaDefinition"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string contendo "OK" em caso de sucesso.

##### **`undefine_schema`**

* **Descrição:** Remove elementos do esquema usando TypeQL 'undefine'.
* **Escopos OAuth2 Necessários:** `typedb:manage_schema`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "databaseName": {
          "type": "string",
          "description": "O nome do banco de dados TypeDB cujo esquema será modificado."
        },
        "schemaUndefinition": {
          "type": "string",
          "description": "Uma string contendo uma ou mais declarações TypeQL `undefine` válidas (ex: `undefine person plays employment;`)."
        }
      },
      "required": ["databaseName", "schemaUndefinition"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string contendo "OK" em caso de sucesso.

##### **`get_schema`**

* **Descrição:** Recupera a definição do esquema TypeQL (completo ou apenas tipos).
* **Escopos OAuth2 Necessários:** `typedb:manage_schema`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "databaseName": {
          "type": "string",
          "description": "O nome do banco de dados TypeDB do qual o esquema será recuperado."
        },
        "schemaType": {
          "type": "string",
          "description": "Especifica o tipo de esquema a ser retornado: 'full' para o esquema completo (incluindo regras) ou 'types' para apenas as definições de tipo. Default: 'full'. Valores permitidos: \"full\", \"types\".",
          "enum": ["full", "types"]
        }
      },
      "required": ["databaseName"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string contendo as declarações TypeQL do esquema.

---

#### 3. Ferramentas de Gerenciamento de Banco de Dados (`db_admin.*`)

Estas ferramentas são usadas para administrar os bancos de dados no servidor TypeDB.

##### **`create_database`**

* **Descrição:** Cria um novo banco de dados TypeDB.
* **Escopos OAuth2 Necessários:** `typedb:manage_databases`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "name": {
          "type": "string",
          "description": "O nome para o novo banco de dados a ser criado."
        }
      },
      "required": ["name"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string contendo "OK" em caso de sucesso.

##### **`database_exists`**

* **Descrição:** Verifica se um banco de dados TypeDB existe.
* **Escopos OAuth2 Necessários:** `typedb:manage_databases`
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "name": {
          "type": "string",
          "description": "O nome do banco de dados cuja existência será verificada."
        }
      },
      "required": ["name"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string contendo "true" se o banco existir, "false" caso contrário.

##### **`list_databases`**

* **Descrição:** Lista todos os bancos de dados TypeDB existentes.
* **Escopos OAuth2 Necessários:** `typedb:manage_databases`
* **Schema de Entrada (`arguments`):** Nenhum.

    ```json
    {}
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string JSON representando um array de nomes de bancos de dados. Ex: `["db1", "db2"]`.

##### **`delete_database`**

* **Descrição:** PERMANENTEMENTE remove um banco de dados TypeDB. **Use com extrema cautela.**
* **Escopos OAuth2 Necessários:** `typedb:admin_databases` (escopo mais privilegiado)
* **Schema de Entrada (`arguments`):**

    ```json
    {
      "type": "object",
      "properties": {
        "name": {
          "type": "string",
          "description": "O nome do banco de dados a ser permanentemente deletado."
        }
      },
      "required": ["name"]
    }
    ```

* **Schema de Saída (`CallToolResult.content[0].text`):**
  * Uma string contendo "OK" em caso de sucesso.

---

## 2. Endpoints HTTP

Além da API MCP via WebSocket, o servidor expõe alguns endpoints HTTP para monitoramento e observabilidade.

### `livez`

* **Método:** `GET`
* **Descrição:** Endpoint de Liveness. Indica se a aplicação está rodando e respondendo a requisições HTTP básicas.
* **Autenticação:** Nenhuma.
* **Resposta:**
  * `200 OK`: Se o servidor estiver ativo. O corpo da resposta pode conter "OK" ou uma estrutura JSON simples indicando o status.
  * Outros códigos HTTP (ex: 5xx) se o servidor não estiver funcional.

### `/readyz`

* **Método:** `GET`
* **Descrição:** Endpoint de Readiness. Indica se a aplicação está pronta para receber tráfego e se suas dependências críticas (como TypeDB e, se OAuth2 estiver habilitado, o JWKS URI) estão saudáveis.
* **Autenticação:** Nenhuma.
* **Resposta:**
  * `200 OK`: Se o servidor e todas as suas dependências críticas estiverem saudáveis. O corpo da resposta é um JSON detalhando o status de cada componente.

    ```json
    // Exemplo de resposta 200 OK
    {
      "status": "UP",
      "components": {
        "typedb": "UP", // ou "DOWN"
        "jwks": "UP"    // ou "DOWN", "NOT_CONFIGURED"
      }
    }
    ```

  * `503 Service Unavailable`: Se o servidor ou alguma de suas dependências críticas não estiverem prontas. O corpo da resposta também será um JSON similar ao acima, indicando o componente problemático.

### `/metrics`

* **Método:** `GET`
* **Path Padrão:** `/metrics` (configurável via `server.metrics_path`)
* **Endereço de Bind Padrão:** `0.0.0.0:9090` (configurável via `server.metrics_bind_address`)
* **Descrição:** Expõe métricas da aplicação no formato de texto Prometheus.
* **Autenticação:** Nenhuma por padrão.
* **Resposta:**
  * `200 OK`: Com o corpo contendo as métricas no formato Prometheus.
  * **Content-Type:** `text/plain; version=0.0.4; charset=utf-8`
* **Consulte [Lista de Métricas](./metrics_list.md) para detalhes sobre as métricas expostas.**

---

Este documento será atualizado à medida que novas ferramentas forem adicionadas ou os endpoints existentes forem modificados.
