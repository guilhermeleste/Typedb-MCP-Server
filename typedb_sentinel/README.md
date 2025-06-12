# TypeDB Sentinel 🤖🛡️

**TypeDB Sentinel** é um sistema de teste autônomo e inteligente para o `typedb-mcp-server`. Construído com a biblioteca `agno` e alimentado pelo Google Gemini 2.5 Pro, este projeto utiliza uma equipe de agentes de IA para gerar, executar e analisar cenários de teste complexos de forma autônoma.

O objetivo do Sentinel é garantir a robustez, a funcionalidade e a segurança do servidor TypeDB, fornecendo relatórios detalhados e insights sobre seu comportamento.

## ✨ Funcionalidades Principais

* **Geração Dinâmica de Testes**: Um `TestPlannerAgent` cria cenários de teste abrangentes (incluindo setup, teardown e casos negativos) a partir de descrições em linguagem natural.
* **Execução Orquestrada**: Um `TestRunnerTeam` de agentes especialistas executa cada passo do plano de teste, interagindo com o servidor TypeDB via WebSocket sobre TLS.
* **Análise Inteligente com Raciocínio**: Um `ResultAnalyzerAgent` usa `ReasoningTools` para diagnosticar a causa raiz de falhas, em vez de apenas relatá-las.
* **Relatórios Automatizados**: Um `ReportGeneratorAgent` cria relatórios detalhados em formato Markdown, perfeitos para análise humana e integração com sistemas de CI/CD.
* **Testes de Segurança**: Capacidade de executar testes com tokens OAuth2 de escopo limitado para verificar se as permissões são aplicadas corretamente.
* **Resiliência**: O workflow persiste seu estado em um banco de dados local, permitindo que testes longos sejam retomados em caso de interrupção.

## 🏛️ Arquitetura

O Sentinel é construído como um `Workflow` Agno que orquestra uma equipe (`Team`) de agentes especialistas:

1. **`TestExecutionWorkflow`**: O maestro que gerencia o fluxo de ponta a ponta.
2. **`TestPlannerAgent`**: O estrategista que projeta os cenários de teste.
3. **`TestRunnerTeam`**: A equipe de execução que interage com o servidor, composta por:
    * `SchemaAgent`: Especialista em DDL.
    * `DataAgent`: Especialista em DML.
    * `QueryAgent`: Especialista em DQL.
    * `SecurityAgent`: Especialista em testes de autorização.
4. **`ResultAnalyzerAgent`**: O detetive que analisa os resultados.
5. **`ReportGeneratorAgent`**: O escritor técnico que documenta tudo.

A comunicação com o servidor é feita através de um SDK customizado, o **`TypeDBToolkit`**, que lida com a conexão segura (WSS), autenticação (OAuth2) e o protocolo MCP.

## 🚀 Começando

Siga os passos abaixo para configurar e executar o TypeDB Sentinel.

### 1. Pré-requisitos

* Python 3.10+
* `uv` (gerenciador de pacotes e ambientes virtuais)
* Acesso a um `typedb-mcp-server` em execução.
* Acesso à API do Google Gemini.

### 2. Instalação

Primeiro, clone o repositório:
```bash
git clone https://github.com/seu-usuario/typedb_sentinel.git
cd typedb_sentinel
```

Em seguida, configure o ambiente virtual e instale as dependências usando `uv`:
```bash
# Crie e ative o ambiente virtual
uv venv

# No macOS/Linux
source .venv/bin/activate

# No Windows
.venv\Scripts\activate

# Instale os pacotes necessários
uv pip install -r requirements.txt
```

### 3. Configuração

Antes de executar, você precisa configurar suas credenciais e os endpoints do servidor.

1. Copie o arquivo de exemplo `.env.example` para um novo arquivo chamado `.env`:
    ```bash
    cp .env.example .env
    ```
2. Abra o arquivo `.env` e preencha as seguintes variáveis:

    * `GEMINI_API_KEY`: Sua chave de API para o Google Gemini.
    * `TYPEDB_SERVER_URL`: A URL WebSocket do seu servidor (ex: `wss://localhost:8443/mcp/ws`).
    * `TYPEDB_ADMIN_TOKEN`: Um token JWT com permissões completas.
    * `TYPEDB_SECURITY_TOKEN` (Opcional): Um token JWT com permissões restritas (ex: apenas leitura) para os testes de segurança.
    * `TYPEDB_TLS_CA_PATH` (Opcional): O caminho para o certificado da sua CA se estiver usando certificados autoassinados.

### 4. Execução

O ponto de entrada principal é o `main.py`. Você pode executar testes fornecendo uma descrição do cenário na linha de comando.

**Exemplo de um teste de funcionalidade padrão:**
```bash
python main.py "Testar a criação de um banco de dados, a definição de um esquema simples, a inserção de um dado e a sua posterior consulta."
```

**Exemplo de um teste de segurança:**
Este comando usará o `TYPEDB_SECURITY_TOKEN` para tentar executar uma ação privilegiada.
```bash
python main.py "Tentar deletar um banco de dados usando o token de segurança." --security-test
```

**Retomando um workflow interrompido:**
Se um teste longo falhar, você pode retomá-lo usando o ID da sessão que é exibido nos logs.
```bash
python main.py "Continuar o teste de migração de dados." --session-id "TestExecutionWorkflow-xxxxxxxx"
```

### 5. Verificando os Resultados

* Os logs da execução serão exibidos no console.
* Um relatório detalhado em formato Markdown será salvo na pasta `reports/`. O nome do arquivo incluirá o ID da sessão do workflow (ex: `reports/TestReport_TestExecutionWorkflow-xxxxxxxx.md`).

## Estrutura do Projeto

```
typedb_sentinel/
├── main.py                 # Ponto de entrada da CLI
├── config.py               # Carrega configurações do .env
├── src/                    # Código-fonte da aplicação
│   ├── agents/             # Definições dos agentes
│   ├── models/             # Modelos de dados Pydantic
│   ├── toolkit/            # SDK para o servidor TypeDB
│   └── workflows/          # Lógica de orquestração
├── data/                   # Armazenamento local (ex: banco de dados SQLite)
├── reports/                # Relatórios de teste gerados
├── .env.example            # Modelo para variáveis de ambiente
└── requirements.txt        # Dependências do projeto
```

## 🤝 Contribuições

Contribuições são bem-vindas! Se você tiver ideias para novos cenários de teste, melhorias na arquitetura ou correções de bugs, sinta-se à vontade para abrir uma *issue* ou um *pull request*.