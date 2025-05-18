
# Guia do Usuário: Visão Geral das Ferramentas MCP

O Typedb-MCP-Server expõe a funcionalidade do TypeDB através de um conjunto de "ferramentas" (tools) definidas pelo Model Context Protocol (MCP). Estas ferramentas permitem que clientes realizem diversas operações no banco de dados de forma padronizada.

Este documento oferece uma visão geral das categorias de ferramentas disponíveis. Para detalhes específicos sobre cada ferramenta, incluindo seus parâmetros de entrada, formato de saída e escopos OAuth2 necessários, consulte a **[Referência da API (Ferramentas MCP)](../reference/api.md)**.

## Como as Ferramentas MCP Funcionam?

Os clientes interagem com o servidor enviando mensagens JSON-RPC através da conexão WebSocket estabelecida. Para invocar uma ferramenta, o cliente envia uma requisição com o método `tools/call`, especificando o nome da ferramenta e seus argumentos. O servidor então processa a requisição, interage com o TypeDB conforme necessário, e retorna o resultado (ou um erro) para o cliente.

## Categorias de Ferramentas

As ferramentas expostas pelo Typedb-MCP-Server podem ser agrupadas nas seguintes categorias principais:

### 1. Ferramentas de Consulta e Manipulação de Dados

Estas ferramentas permitem que você leia, insira, atualize e delete dados no seu banco TypeDB usando consultas TypeQL.

* **`query_read`**: Para executar consultas de leitura, como `match ... get;`, `fetch ...;` ou consultas de agregação (`count`, `sum`, etc.).
* **`insert_data`**: Para adicionar novas instâncias de dados ao banco usando declarações `insert`.
* **`delete_data`**: Para remover dados existentes que correspondem a um padrão, usando `match ... delete;`.
* **`update_data`**: Para realizar modificações atômicas nos dados, geralmente combinando `match`, `delete` e `insert`.
* **`validate_query`**: Para verificar a sintaxe e a validade semântica de uma consulta TypeQL em relação ao esquema de um banco de dados existente, sem executar a modificação de dados.

**Escopos OAuth2 Comuns:** `typedb:read_data`, `typedb:write_data`, `typedb:validate_queries`.

### 2. Ferramentas de Operações de Esquema

Estas ferramentas são usadas para definir, modificar e inspecionar o esquema do seu banco de dados TypeDB.

* **`define_schema`**: Para adicionar novas definições ao esquema (como tipos de entidade, relação, atributo ou regras) usando declarações TypeQL `define`.
* **`undefine_schema`**: Para remover definições existentes do esquema usando declarações TypeQL `undefine`.
* **`get_schema`**: Para recuperar a definição completa do esquema de um banco de dados ou apenas as definições de tipo.

**Escopos OAuth2 Comuns:** `typedb:manage_schema`.

### 3. Ferramentas de Gerenciamento de Banco de Dados

Estas ferramentas permitem realizar operações administrativas nos próprios bancos de dados no servidor TypeDB.

* **`create_database`**: Para criar um novo banco de dados.
* **`database_exists`**: Para verificar se um banco de dados com um nome específico já existe.
* **`list_databases`**: Para obter uma lista de todos os bancos de dados existentes no servidor.
* **`delete_database`**: Para remover permanentemente um banco de dados, incluindo todo o seu esquema e dados. **Esta é uma operação destrutiva e deve ser usada com extrema cautela.**

**Escopos OAuth2 Comuns:** `typedb:manage_databases`, `typedb:admin_databases` (para operações destrutivas como `delete_database`).

## Listando Ferramentas Disponíveis

Um cliente MCP pode, programaticamente, solicitar a lista de todas as ferramentas disponíveis no servidor e seus respectivos schemas de entrada. Isso geralmente é feito através de uma chamada ao método `tools/list` do protocolo MCP (não confundir com a ferramenta `list_databases` mencionada acima).

**Exemplo de Requisição `tools/list`:**

```json
{
  "jsonrpc": "2.0",
  "id": "list-tools-req-1",
  "method": "tools/list",
  "params": {} // Pode aceitar parâmetros de paginação
}
```

O servidor responderá com uma lista de objetos `Tool`, cada um detalhando o nome, descrição e `inputSchema` da ferramenta.

## Segurança e Escopos

Se a autenticação OAuth2 estiver habilitada no servidor:

* Um token JWT válido é necessário para usar qualquer ferramenta.
* Cada ferramenta pode exigir que o token JWT contenha **escopos OAuth2 específicos** para autorizar sua execução. Se os escopos necessários não estiverem presentes, a chamada da ferramenta falhará com um erro de autorização.

Consulte a documentação de cada ferramenta na [Referência da API](../reference/api.md) para verificar os escopos exatos necessários.

## Próximos Passos

* Para um mergulho profundo em cada ferramenta, seus parâmetros exatos e exemplos de JSON-RPC, consulte a **[Referência da API (Ferramentas MCP)](../reference/api.md)**.
* Aprenda sobre como o servidor expõe sua saúde e métricas na seção de [Observabilidade](./08_observability.md).
