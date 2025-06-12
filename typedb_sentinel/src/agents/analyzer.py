# src/agents/analyzer.py

"""
Define os agentes responsáveis por analisar e relatar os resultados dos testes.

Este módulo contém:
- ResultAnalyzerAgent: Um agente que usa raciocínio para comparar os resultados
  reais com os esperados e determinar a causa raiz de quaisquer falhas.
- ReportGeneratorAgent: Um agente que pega a análise estruturada e a formata
  em um relatório Markdown de fácil leitura para os desenvolvedores.
"""
from __future__ import annotations

from agno.agent import Agent
from agno.models.google import Gemini
from agno.tools.reasoning import ReasoningTools

# Importa os modelos de dados Pydantic que servem como contrato de API
from src.models.plan_models import AnalysisReport, FinalReport

# Usaremos o Gemini 2.5 Pro para ambos os agentes devido às suas
# excelentes capacidades de raciocínio e de seguir instruções para saídas estruturadas.
LLM_MODEL = Gemini(model="gemini-2.5-pro-exp-0525")

# --- Agente de Análise de Resultados ---

# Instanciamos o agente diretamente, pois sua configuração é estática.
ResultAnalyzerAgent = Agent(
    name="ResultAnalyzerAgent",
    role="Especialista em depuração de sistemas e análise de causa raiz.",
    model=LLM_MODEL,
    tools=[ReasoningTools(add_instructions=True)],
    instructions=[
        "Sua tarefa é realizar uma análise detalhada dos resultados de um teste.",
        "Você receberá um objeto JSON com duas chaves: 'plan' (o que era esperado) e 'results' (o que realmente aconteceu).",
        "Para cada passo no plano, compare a 'expected_outcome_description' com o 'actual_output' ou 'error_message' do resultado correspondente.",
        "Use o ciclo 'think'->'analyze' para diagnosticar falhas. No seu 'think', liste as hipóteses para a falha. No 'analyze', use o contexto dos passos anteriores para confirmar a hipótese mais provável.",
        "Se um teste for marcado como 'is_negative_test: true', um status de 'failure' no resultado é considerado um 'PASS'. Sua justificativa deve explicar isso.",
        "Se um passo não tiver um resultado correspondente, marque-o como 'SKIPPED'.",
        "Sua saída final DEVE ser um objeto JSON que valide com o modelo Pydantic 'AnalysisReport'.",
    ],
    # Forçar a saída estruturada é crucial para a comunicação entre agentes
    response_model=AnalysisReport,
    # Habilitar para depuração detalhada do processo de raciocínio
    show_tool_calls=False, 
    debug_mode=False,
)


# --- Agente de Geração de Relatórios ---

ReportGeneratorAgent = Agent(
    name="ReportGeneratorAgent",
    role="Escritor técnico especializado na criação de relatórios de teste claros e concisos.",
    model=LLM_MODEL,
    # Este agente não precisa de ferramentas, apenas de formatação.
    tools=[],
    instructions=[
        "Você receberá um objeto JSON representando um 'AnalysisReport'.",
        "Sua única tarefa é transformar esses dados estruturados em um relatório abrangente e bem formatado em Markdown.",
        "O relatório deve incluir as seguintes seções:",
        "  - `## Resumo Geral`: Com o status geral e um resumo de alto nível.",
        "  - `## Cenário de Teste`: Com o nome e a descrição do cenário.",
        "  - `## Resultados Detalhados`: Uma lista ou tabela mostrando cada passo, seu status (com emoji ✅ para PASS, ❌ para FAIL) e a justificativa da análise.",
        "  - `## Análise de Falhas`: Se houver falhas, forneça uma análise mais aprofundada da causa raiz com base na justificativa fornecida.",
        "Use formatação Markdown (negrito, listas, blocos de código) para melhorar a legibilidade.",
        "Sua saída final DEVE ser um objeto JSON que valide com o modelo Pydantic 'FinalReport'.",
    ],
    response_model=FinalReport,
    debug_mode=False,
)