# src/models/plan_models.py

"""
Define os modelos de dados Pydantic para o workflow de teste TypeDB Sentinel.

Este módulo estabelece as estruturas de dados que são passadas entre os
diferentes agentes (Planner, Runner, Analyzer, Reporter). O uso de modelos
Pydantic garante a validação de dados e um contrato de API claro e
auto-documentado entre os componentes do sistema.
"""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class TestStep(BaseModel):
    """
    Representa um único passo de teste a ser executado.

    Cada passo define uma ação específica (uma chamada de ferramenta), os parâmetros
    para essa ação e uma descrição em linguagem natural do resultado esperado,
    que será usada pelo ResultAnalyzerAgent para validar o sucesso.
    """

    step_id: int = Field(
        ..., description="Identificador sequencial único para o passo de teste."
    )
    description: str = Field(
        ..., description="Descrição em linguagem natural do que este passo visa testar."
    )
    tool_to_call: str = Field(
        ...,
        description="O nome completo da ferramenta a ser chamada no toolkit. Ex: 'create_database' ou 'database.query_read'.",
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Um dicionário contendo os parâmetros a serem passados para a ferramenta.",
    )
    expected_outcome_description: str = Field(
        ...,
        description="Descrição em linguagem natural do resultado esperado. Ex: 'A operação deve retornar OK.' ou 'A lista deve conter um novo banco de dados chamado xyz.'",
    )
    is_negative_test: bool = Field(
        False,
        description="Indica se este é um teste negativo, onde um erro é o resultado esperado.",
    )


class TestPlan(BaseModel):
    """
    Define um plano de teste completo, gerado pelo TestPlannerAgent.

    Um plano de teste consiste em um cenário com uma série de passos, incluindo
    passos de configuração (setup) e limpeza (teardown) para garantir
    o isolamento e a reprodutibilidade do teste.
    """

    scenario_name: str = Field(
        ..., description="Um nome descritivo e único para o cenário de teste."
    )
    scenario_description: str = Field(
        ..., description="Uma breve descrição do objetivo geral deste cenário de teste."
    )
    # CORREÇÃO: Usando string forward reference para evitar erros do Pylance
    setup_steps: List["TestStep"] = Field(
        default_factory=list,
        description="Passos a serem executados antes do teste principal para preparar o ambiente (ex: criar um banco de dados).",
    )
    # CORREÇÃO: Usando string forward reference para evitar erros do Pylance
    main_steps: List["TestStep"] = Field(
        ..., description="A sequência principal de passos que constitui o teste."
    )
    # CORREÇÃO: Usando string forward reference para evitar erros do Pylance
    teardown_steps: List["TestStep"] = Field(
        default_factory=list,
        description="Passos a serem executados após o teste principal para limpar os recursos (ex: deletar o banco de dados).",
    )


class ExecutionResult(BaseModel):
    """
    Armazena o resultado da execução de um único TestStep.
    """

    step_id: int = Field(
        ..., description="O ID do passo de teste correspondente do TestPlan."
    )
    status: Literal["success", "failure"] = Field(
        ..., description="Indica se o passo foi executado com sucesso ou falhou."
    )
    actual_output: Optional[Any] = Field(
        None,
        description="A saída real retornada pela execução da ferramenta. Pode ser um JSON, string, etc.",
    )
    error_message: Optional[str] = Field(
        None,
        description="A mensagem de erro, caso a execução do passo tenha falhado.",
    )
    duration_ms: float = Field(
        ..., description="Duração da execução do passo em milissegundos."
    )


class StepAnalysis(BaseModel):
    """
    Contém a análise de um único passo de teste, gerada pelo ResultAnalyzerAgent.
    """

    step_id: int
    description: str
    status: Literal["PASS", "FAIL", "SKIPPED"]
    reasoning: str = Field(
        ...,
        description="A justificativa do ResultAnalyzerAgent para o status PASS/FAIL, explicando a lógica da validação.",
    )
    actual_output_summary: str = Field(
        ..., description="Um resumo conciso da saída real obtida."
    )


class AnalysisReport(BaseModel):
    """
    O resultado da análise de um TestPlan completo, gerado pelo ResultAnalyzerAgent.
    """

    scenario_name: str
    overall_status: Literal["PASS", "FAIL"] = Field(
        ..., description="O status geral do cenário de teste."
    )
    summary: str = Field(
        ...,
        description="Um resumo de alto nível da execução do teste, destacando sucessos e falhas principais.",
    )
    step_by_step_analysis: List["StepAnalysis"] = Field(
        ..., description="Uma lista contendo a análise detalhada de cada passo."
    )


class FinalReport(BaseModel):
    """
    O relatório final em formato Markdown, pronto para ser salvo em um arquivo.
    """

    markdown_content: str = Field(
        ..., description="O conteúdo completo do relatório de teste em formato Markdown."
    )