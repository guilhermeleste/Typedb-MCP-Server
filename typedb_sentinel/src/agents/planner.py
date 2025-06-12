# src/agents/planner.py

"""
Define o TestPlannerAgent.

Este agente é o cérebro criativo do TypeDB Sentinel. Sua responsabilidade
é receber uma descrição de alto nível de um cenário de teste e gerar um
plano de teste detalhado e estruturado (um objeto TestPlan) que pode ser
executado pelo TestRunnerTeam.
"""
from __future__ import annotations

from agno.agent import Agent
from agno.models.google import Gemini
from agno.tools.reasoning import ReasoningTools

# Importa o modelo Pydantic que este agente deve gerar.
from src.models.plan_models import TestPlan

# Usaremos o Gemini 2.5 Pro por suas fortes capacidades de raciocínio.
LLM_MODEL = Gemini(model="gemini-2.5-pro-exp-0525")

# --- Agente de Planejamento de Testes ---

TestPlannerAgent = Agent(
    name="TestPlannerAgent",
    role="Engenheiro de Testes de Software Sênior, especialista em bancos de dados de grafos e sistemas distribuídos.",
    model=LLM_MODEL,
    tools=[ReasoningTools(add_instructions=True)],
    instructions=[
        "Sua tarefa é criar um plano de teste (`TestPlan`) robusto e detalhado com base na descrição de um cenário fornecida pelo usuário.",
        "O plano deve ser abrangente, incluindo testes positivos, negativos e de casos de borda.",
        "É essencial que cada `TestPlan` inclua passos de `setup` para criar um ambiente limpo e passos de `teardown` para limpar todos os recursos criados, garantindo o isolamento do teste.",
        
        "**Use o ciclo `think`->`analyze` para construir o plano:**",
        "1. **`think`**: Brainstorm sobre os aspectos a serem testados. Quais são as principais funcionalidades? Quais são os possíveis pontos de falha? Que sequência de operações faz sentido? Como testar a segurança e a validação de entrada?",
        "2. **`analyze`**: Revise seu brainstorm. O plano está completo? Os passos são lógicos e sequenciais? Os `teardown_steps` limpam adequadamente os `setup_steps`? Você cobriu os testes negativos (onde um erro é esperado)?",
        "3. Repita o ciclo se necessário para refinar e adicionar mais detalhes ao plano.",

        "**Regras para os `TestStep`:**",
        "- `tool_to_call`: Deve ser o nome exato de uma ferramenta do `TypeDBToolkit` (ex: 'create_database', 'database.query_read').",
        "- `parameters`: Deve ser um dicionário com os argumentos exatos que a ferramenta espera.",
        "- `expected_outcome_description`: Deve ser uma descrição clara e verificável do que constitui um sucesso para aquele passo.",
        "- `is_negative_test`: Defina como `true` para passos onde a expectativa é que o servidor retorne um erro (ex: tentar criar um banco que já existe).",

        "Sua saída final **DEVE OBRIGATORIAMENTE** ser um objeto JSON que valide com o modelo Pydantic `TestPlan`.",
    ],
    # Forçar a saída estruturada é essencial para a automação do workflow.
    response_model=TestPlan,
    
    # Ativar para depuração detalhada do processo de planejamento
    show_tool_calls=False, 
    debug_mode=False,
)