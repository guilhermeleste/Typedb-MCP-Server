# main.py

"""
Ponto de entrada principal para o TypeDB Sentinel.

Este script fornece uma interface de linha de comando (CLI) para iniciar
o workflow de teste autônomo. Ele carrega as configurações, instancia o
workflow e executa um cenário de teste com base na entrada do usuário.

Exemplos de uso:
  # Executa um teste de funcionalidade padrão
  python main.py "Testar a criação e consulta de um banco de dados."

  # Executa um teste de segurança com um token de permissões limitadas
  python main.py "Tentar deletar um banco de dados com um token de leitura." --security-test

  # Executa o workflow com um ID de sessão específico para retomar um teste anterior
  python main.py "Continuar teste de migração" --session-id "workflow-migracao-123"
"""

import asyncio
from pathlib import Path
from typing import Optional

import typer
from agno.storage.sqlite import SqliteStorage
from agno.utils.log import logger

# Importa os componentes principais da nossa aplicação
from config import settings
from src.toolkit.typedb_toolkit import TypeDBConfig
from src.workflows.test_workflow import TestExecutionWorkflow

# Cria a aplicação CLI com Typer
app = typer.Typer(
    name="TypeDB Sentinel",
    help="Um sistema de teste autônomo para o typedb-mcp-server usando Agno e Gemini.",
    add_completion=False,
)

# Cria o diretório de dados se ele não existir
data_dir = Path("./data")
data_dir.mkdir(exist_ok=True)


@app.command()
def run(
    test_description: str = typer.Argument(
        ..., help="Descrição em linguagem natural do cenário de teste a ser executado."
    ),
    security_test: bool = typer.Option(
        False,
        "--security-test",
        "-s",
        help="Executa o teste usando o token de segurança com escopo limitado.",
    ),
    session_id: Optional[str] = typer.Option(
        None,
        "--session-id",
        help="ID de uma sessão existente para retomar um workflow interrompido.",
    ),
    output_dir: Path = typer.Option(
        Path("./reports"),
        "--output-dir",
        "-o",
        help="Diretório onde o relatório de teste final será salvo.",
    ),
):
    """
    Inicia e executa o workflow de teste do TypeDB Sentinel.
    """
    logger.info("🚀 Iniciando o TypeDB Sentinel...")

    # --- Configuração dos Toolkits ---
    admin_config = TypeDBConfig(
        server_url=settings.TYPEDB_SERVER_URL,
        auth_token=settings.TYPEDB_ADMIN_TOKEN,
        tls_ca_path=settings.TYPEDB_TLS_CA_PATH,
    )
    
    security_config = None
    if security_test:
        if not settings.TYPEDB_SECURITY_TOKEN:
            logger.error("O token de segurança (TYPEDB_SECURITY_TOKEN) não está definido no ambiente. Abortando.")
            raise typer.Exit(code=1)
        security_config = TypeDBConfig(
            server_url=settings.TYPEDB_SERVER_URL,
            auth_token=settings.TYPEDB_SECURITY_TOKEN,
            tls_ca_path=settings.TYPEDB_TLS_CA_PATH,
        )

    # --- Configuração do Workflow ---
    workflow_storage = SqliteStorage(
        table_name="sentinel_workflows", db_file=str(data_dir / "sentinel_workflows.db")
    )
    
    workflow = TestExecutionWorkflow(
        admin_config=admin_config,
        security_config=security_config,
        session_id=session_id,
        storage=workflow_storage,
        debug_mode=True # Habilita logs detalhados do Agno
    )

    logger.info(f"ID da Sessão do Workflow: {workflow.session_id}")

    # --- Execução Assíncrona ---
    try:
        final_report = asyncio.run(workflow.arun(test_description))

        # --- Salvando o Relatório ---
        output_dir.mkdir(exist_ok=True)
        report_path = output_dir / f"TestReport_{workflow.session_id}.md"
        report_path.write_text(final_report.markdown_content)
        
        # CORRIGIDO: Removido f-string desnecessário
        logger.info("✅ Workflow concluído com sucesso!")
        logger.info(f"📄 Relatório salvo em: {report_path}")

    except Exception as e:
        logger.error(f"❌ O workflow falhou com um erro crítico: {e}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()