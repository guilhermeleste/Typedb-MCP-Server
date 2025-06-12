# config.py

"""
Configuração centralizada para a aplicação TypeDB Sentinel.

Este módulo usa `pydantic-settings` para carregar configurações de variáveis de
ambiente ou de um arquivo .env. Isso permite uma gestão segura e flexível das
credenciais e parâmetros da aplicação, separando a configuração do código.

Para usar, crie um arquivo .env na raiz do projeto com base no .env.example
e preencha com os valores apropriados.
"""
# CORREÇÃO: Importado 'Optional' para uso nas anotações de tipo.
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Define e valida as configurações da aplicação.

    As variáveis são carregadas de um arquivo .env ou do ambiente do sistema.
    A validação do Pydantic garante que as configurações essenciais estejam presentes
    e no formato correto antes que a aplicação comece a rodar.
    """

    # Configurações da API Gemini
    GEMINI_API_KEY: str

    # Configurações do Servidor TypeDB
    TYPEDB_SERVER_URL: str
    TYPEDB_ADMIN_TOKEN: str
    TYPEDB_SECURITY_TOKEN: Optional[str] = None # Token com permissões limitadas para testes de segurança
    TYPEDB_TLS_CA_PATH: Optional[str] = None # Caminho para o certificado da CA para conexões WSS

    # Configuração do Pydantic-Settings para ler do arquivo .env
    model_config = SettingsConfigDict(
        env_file=".env",        # Nome do arquivo de onde carregar as variáveis
        env_file_encoding="utf-8", # Codificação do arquivo .env
        extra="ignore"          # Ignora variáveis extras no .env que não estão definidas aqui
    )


# Cria uma única instância das configurações que será importada por outros módulos.
# O Pydantic garante que isso só será executado uma vez.
try:
    settings = Settings()
except Exception as e:
    # Levanta um erro mais amigável se o .env ou as variáveis estiverem faltando.
    raise ImportError(
        f"Não foi possível carregar as configurações. Certifique-se de que um arquivo .env existe e contém todas as variáveis necessárias (ex: GEMINI_API_KEY, TYPEDB_SERVER_URL, etc.). Erro original: {e}"
    )