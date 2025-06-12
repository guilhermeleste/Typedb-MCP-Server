# src/workflows/test_workflow.py

"""
Define o workflow principal para o TypeDB Sentinel.

Este módulo contém o TestExecutionWorkflow, que orquestra a colaboração
entre os agentes para planejar, executar e analisar testes no `typedb-mcp-server`.
Ele gerencia o estado do processo, garantindo resiliência e um fluxo de
dados estruturado.
"""

from __future__ import annotations

import json
from typing import Optional

from agno.agent import Agent
from agno.utils.log import logger
from agno.workflow import Workflow

# Importa os componentes que o workflow orquestrará
from src.agents.analyzer import ReportGeneratorAgent, ResultAnalyzerAgent
from src.agents.planner import TestPlannerAgent
from src.agents.runner import TestRunnerTeam
from src.models.plan_models import (
    AnalysisReport,
    FinalReport,
    TestPlan,
)
from src.toolkit.typedb_toolkit import (
    AuthorizationError,
    ConnectionError,
    TypeDBConfig,
    TypeDBError,  # CORRIGIDO: TypeDBError importado
    TypeDBToolkit,
)


class TestExecutionWorkflow(Workflow):
    """
    Orquestra o processo de teste de ponta a ponta para o TypeDB MCP Server.
    """

    # --- Definição dos Agentes e Teams como atributos de classe ---
    # Estes são os "trabalhadores" que o workflow irá gerenciar.
    planner: Agent = TestPlannerAgent
    analyzer: Agent = ResultAnalyzerAgent
    reporter: Agent = ReportGeneratorAgent
    # A equipe de execução é especial, pois precisa ser inicializada com toolkits
    # que dependem da configuração do workflow, então a criamos no __init__.

    def __init__(
        self,
        admin_config: TypeDBConfig,
        security_config: Optional[TypeDBConfig] = None,
        **kwargs,
    ):
        """
        Inicializa o workflow e seus componentes.

        Args:
            admin_config: Configuração para o toolkit com permissões de administrador.
            security_config: Opcional. Configuração para o toolkit com permissões restritas.
            **kwargs: Argumentos padrão do Workflow (como session_id, storage, etc.).
        """
        super().__init__(**kwargs)
        self.admin_config = admin_config
        self.security_config = security_config
        
        # A equipe de execução é instanciada aqui, mas sem os toolkits ainda.
        # Os toolkits serão criados e passados dinamicamente no método `run`.
        self.runner_team: Optional[TestRunnerTeam] = None

    async def _initialize_toolkits(self) -> tuple[TypeDBToolkit, Optional[TypeDBToolkit]]:
        """Inicializa os toolkits necessários para a execução do teste."""
        logger.info("Inicializando toolkits de teste...")
        # Extrai server_url do admin_config. Assume-se que é o mesmo para security_config.
        server_url = self.admin_config.server_url

        admin_tk = await TypeDBToolkit.create(server_url=server_url, use_security_token=False)
        
        security_tk = None
        if self.security_config:
            logger.info("Inicializando toolkit de segurança com token restrito.")
            # server_url de security_config deve ser o mesmo, mas por consistência, pode-se usar self.security_config.server_url
            security_tk = await TypeDBToolkit.create(server_url=server_url, use_security_token=True)
            
        return admin_tk, security_tk

    async def arun(self, test_description: str) -> FinalReport:
        """
        Executa o workflow completo de forma assíncrona.

        Args:
            test_description: Uma descrição em linguagem natural do que deve ser testado.

        Returns:
            Um objeto FinalReport contendo o relatório em Markdown.
        """
        admin_toolkit = None
        security_toolkit = None
        
        try:
            # --- Etapa 0: Setup dos Toolkits ---
            # Envolve a criação dos toolkits em um try/except para lidar com
            # falhas de conexão/autenticação antes mesmo de começar o teste.
            admin_toolkit, security_toolkit = await self._initialize_toolkits()
            self.runner_team = TestRunnerTeam(admin_toolkit=admin_toolkit, security_toolkit=security_toolkit)

            # --- Etapa 1: Planejamento ---
            logger.info("Fase 1: Planejamento do Teste")
            # Usa o estado da sessão para evitar re-planejamento
            if "test_plan" not in self.session_state:
                plan_response = await self.planner.arun(test_description)
                if not isinstance(plan_response.content, TestPlan):
                    raise TypeDBError("O planejador não retornou um TestPlan válido.")
                self.session_state["test_plan"] = plan_response.content.model_dump()
                self.write_to_storage()
            test_plan = TestPlan.model_validate(self.session_state["test_plan"])
            logger.info(f"Plano gerado para o cenário: '{test_plan.scenario_name}'")

            # --- Etapa 2: Execução ---
            logger.info("Fase 2: Execução do Plano de Teste")
            if "execution_results" not in self.session_state:
                # A lógica de execução está encapsulada no método do time.
                results = self.runner_team.run_test_plan(test_plan)
                self.session_state["execution_results"] = [res.model_dump() for res in results]
                self.write_to_storage()
            # CORRIGIDO: Variável 'execution_results' removida por não ser utilizada
            logger.info("Execução do plano concluída.")

            # --- Etapa 3: Análise ---
            logger.info("Fase 3: Análise dos Resultados")
            if "analysis_report" not in self.session_state:
                analysis_input = {
                    "plan": test_plan.model_dump(),
                    "results": self.session_state["execution_results"],
                }
                analysis_response = await self.analyzer.arun(json.dumps(analysis_input))
                if not isinstance(analysis_response.content, AnalysisReport):
                    raise TypeDBError("O analisador não retornou um AnalysisReport válido.")
                self.session_state["analysis_report"] = analysis_response.content.model_dump()
                self.write_to_storage()
            analysis_report = AnalysisReport.model_validate(self.session_state["analysis_report"])
            logger.info(f"Análise concluída com status geral: {analysis_report.overall_status}")

            # --- Etapa 4: Geração do Relatório ---
            logger.info("Fase 4: Geração do Relatório Final")
            report_response = await self.reporter.arun(analysis_report.model_dump_json())
            if not isinstance(report_response.content, FinalReport):
                raise TypeDBError("O gerador de relatórios não retornou um FinalReport válido.")
            
            logger.info("Workflow concluído com sucesso.")
            return report_response.content

        except (ConnectionError, AuthorizationError) as e:
            logger.error(f"Falha crítica de conexão ou autorização: {e}")
            raise  # Re-levanta a exceção para que o chamador saiba que a infra falhou.
        except Exception as e:
            logger.error(f"Uma falha inesperada ocorreu no workflow: {e}")
            raise
        finally:
            # --- Etapa 5: Limpeza ---
            # Garante que as conexões WebSocket sejam sempre fechadas.
            logger.info("Encerrando conexões dos toolkits...")
            if admin_toolkit:
                await admin_toolkit.close()
            if security_toolkit:
                await security_toolkit.close()