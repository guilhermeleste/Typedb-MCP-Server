# src/agents/runner.py

"""
Define o TestRunnerTeam e seus agentes especialistas.

Esta equipe é responsável por executar um TestPlan, passo a passo, delegando
cada ação ao agente especialista apropriado. O líder da equipe (o próprio objeto Team)
orquestra a execução, garantindo que os passos sejam executados na ordem correta.
"""
from __future__ import annotations

import time
from typing import List, Optional

from agno.agent import Agent
from agno.models.google import Gemini
from agno.team import Team

# CORREÇÃO: A importação de 'TypeDBConfig' foi removida, pois não é usada neste módulo.
from src.toolkit.typedb_toolkit import TypeDBToolkit, ToolExecutionError
from src.models.plan_models import ExecutionResult, TestPlan, TestStep

# --- Agentes Especialistas ---

LLM_MODEL = Gemini(model="gemini-2.5-pro-exp-0525")

def create_schema_agent(tools: List[TypeDBToolkit]) -> Agent:
    """Cria um agente especialista em manipulação de esquema (DDL)."""
    return Agent(
        name="SchemaAgent",
        role="Especialista em Definição de Esquema de Dados (DDL) para TypeDB.",
        model=LLM_MODEL,
        tools=tools,
        instructions=[
            "Você SÓ executa tarefas relacionadas ao esquema: create_database, delete_database, define_schema, undefine_schema, get_schema.",
            "Siga as instruções do passo de teste precisamente.",
        ],
        show_tool_calls=True,
    )

def create_data_agent(tools: List[TypeDBToolkit]) -> Agent:
    """Cria um agente especialista em manipulação de dados (DML)."""
    return Agent(
        name="DataAgent",
        role="Especialista em Manipulação de Dados (DML) para TypeDB.",
        model=LLM_MODEL,
        tools=tools,
        instructions=[
            "Você SÓ executa tarefas de escrita de dados: insert_data, update_data, delete_data.",
            "Siga as instruções do passo de teste precisamente.",
        ],
        show_tool_calls=True,
    )

def create_query_agent(tools: List[TypeDBToolkit]) -> Agent:
    """Cria um agente especialista em consultas de leitura (DQL)."""
    return Agent(
        name="QueryAgent",
        role="Especialista em Consultas de Leitura (DQL) para TypeDB.",
        model=LLM_MODEL,
        tools=tools,
        instructions=[
            "Você SÓ executa tarefas de leitura: query_read, database_exists.",
            "Siga as instruções do passo de teste precisamente.",
        ],
        show_tool_calls=True,
    )
    
def create_security_agent(tools: List[TypeDBToolkit]) -> Agent:
    """Cria um agente para testes de segurança, usando um toolkit com permissões limitadas."""
    return Agent(
        name="SecurityAgent",
        role="Especialista em Testes de Segurança e Autorização.",
        model=LLM_MODEL,
        tools=tools,
        instructions=[
            "Você tenta executar ações que podem não ser permitidas pelo seu token de acesso.",
            "Seu objetivo é verificar se o servidor bloqueia corretamente as ações não autorizadas.",
        ],
        show_tool_calls=True,
    )

# --- Equipe de Execução de Testes ---

class TestRunnerTeam(Team):
    """
    Uma equipe de agentes coordenada para executar um TestPlan.

    O líder da equipe (este objeto Team) recebe um plano e delega cada passo
    para o agente especialista mais apropriado.
    """
    def __init__(
        self,
        admin_toolkit: TypeDBToolkit,
        security_toolkit: Optional[TypeDBToolkit] = None,
        **kwargs,
    ):
        
        schema_agent = create_schema_agent(tools=[admin_toolkit])
        data_agent = create_data_agent(tools=[admin_toolkit])
        query_agent = create_query_agent(tools=[admin_toolkit])
        
        members = [schema_agent, data_agent, query_agent]
        
        if security_toolkit:
            security_agent = create_security_agent(tools=[security_toolkit])
            members.append(security_agent)

        super().__init__(
            name="TestRunnerTeamLeader",
            model=LLM_MODEL,
            mode="coordinate",
            members=members,
            instructions=[
                "Você é o líder de uma equipe de execução de testes de TypeDB.",
                "Seu trabalho é ler um `TestPlan` e delegar cada `TestStep` para o membro da equipe correto.",
                "SchemaAgent: para criar/deletar bancos e manipular esquemas.",
                "DataAgent: para inserir, atualizar ou deletar dados.",
                "QueryAgent: para realizar consultas de leitura e verificar a existência.",
                "SecurityAgent: para testar operações que devem falhar por falta de permissão.",
                "Execute os passos na ordem exata em que são fornecidos.",
                "Após cada passo, relate o resultado para o orquestrador do workflow."
            ],
            **kwargs,
        )

    def run_test_plan(self, plan: TestPlan) -> List[ExecutionResult]:
        """
        Executa todos os passos de um TestPlan e retorna os resultados.
        """
        all_results: List[ExecutionResult] = []
        
        steps_to_run: List[TestStep] = plan.setup_steps + plan.main_steps + plan.teardown_steps

        for step in steps_to_run:
            start_time = time.time()
            try:
                # O líder da equipe (LLM) escolhe o melhor agente para a tarefa.
                self.run(
                    f"Execute o passo '{step.description}' usando a ferramenta '{step.tool_to_call}' e os parâmetros {step.parameters}."
                )
                
                # A resposta real da ferramenta do membro estará no último 'member_response'.
                if not self.run_response or not self.run_response.member_responses:
                    raise ToolExecutionError("A equipe não produziu uma resposta de membro.")
                
                member_run_response = self.run_response.member_responses[-1]

                result = ExecutionResult(
                    step_id=step.step_id,
                    status="success",
                    actual_output=member_run_response.content,
                    duration_ms=(time.time() - start_time) * 1000,
                )
            except Exception as e:
                result = ExecutionResult(
                    step_id=step.step_id,
                    status="failure",
                    error_message=str(e),
                    duration_ms=(time.time() - start_time) * 1000,
                )
            
            # Validação de teste negativo
            if step.is_negative_test and result.status == "failure":
                result.status = "success"
                print(f"✅ Passo {step.step_id} (Negativo): Falhou como esperado.")
            elif result.status == "success":
                print(f"✅ Passo {step.step_id}: {step.description} - SUCESSO")
            else:
                print(f"❌ Passo {step.step_id}: {step.description} - FALHA: {result.error_message}")
            
            all_results.append(result)
            
        return all_results