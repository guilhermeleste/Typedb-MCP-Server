# src/toolkit/typedb_toolkit.py

"""
Um SDK Python de alto nível e um Toolkit Agno para interagir com o `typedb-mcp-server`.

Este módulo fornece uma interface segura, assíncrona e idiomática para o TypeDB
via o protocolo MCP sobre WebSockets, permitindo integração direta com Agentes Agno
e uso programático em Workflows.
"""
from __future__ import annotations

import asyncio
import json
import ssl
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional

from ...config import get_ca_cert_path, get_oidc_token # Adjusted import path assuming toolkit is in a subfolder of src

# CORREÇÃO: Importar tipos específicos do websockets para type hinting.
import websockets
from websockets.client import WebSocketClientProtocol
from websockets.exceptions import InvalidStatusCode


from agno.tools import Toolkit
# CORREÇÃO: Importar diretamente os tipos necessários do mcp-sdk.
# Se o Pylance ainda reclamar, significa que a biblioteca mcp-sdk não tem
# um `py.typed` ou stubs, mas o código funcionará em tempo de execução.
from mcp.shared.exceptions import McpError
from mcp.types import (
    CallToolResult,
    ErrorData,
    InitializeResult,
    TextContent,
)
from pydantic import BaseModel, Field, field_validator


# --- Configuração e Exceções ---


class TypeDBConfig(BaseModel):
    server_url: str = Field(..., description="URL WebSocket do servidor (wss://...).")
    auth_token: Optional[str] = Field(None, description="Token JWT OAuth2.")
    tls_ca_path: Optional[str] = Field(None, description="Caminho para o PEM da CA customizada.")
    request_timeout: float = Field(30.0, description="Timeout em segundos para requisições.")

    @field_validator("server_url")
    @classmethod
    def check_protocol(cls, v: str) -> str:
        if not v.startswith(("wss://", "ws://")):
            raise ValueError("server_url deve começar com ws:// ou wss://")
        return v


class TypeDBError(Exception):
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        self.message = message
        self.original_error = original_error
        super().__init__(f"{message}: {original_error}" if original_error else message)


class ConnectionError(TypeDBError):
    pass


class AuthorizationError(TypeDBError):
    pass


class ToolExecutionError(TypeDBError):
    pass


# --- Handler com Escopo ---


class _DatabaseHandler:
    def __init__(self, toolkit: "TypeDBToolkit", db_name: str):
        self._toolkit = toolkit
        self._db_name = db_name

    async def query_read(self, query: str) -> Any:
        # CORREÇÃO: Chamar um método público/interno (não privado) para a execução.
        return await self._toolkit.execute_tool("query_read", databaseName=self._db_name, query=query)

    async def insert(self, query: str) -> Any:
        return await self._toolkit.execute_tool("insert_data", databaseName=self._db_name, query=query)

    async def update(self, query: str) -> Any:
        return await self._toolkit.execute_tool("update_data", databaseName=self._db_name, query=query)

    async def delete(self, query: str) -> str:
        return await self._toolkit.execute_tool("delete_data", databaseName=self._db_name, query=query)

    async def get_schema(self, schema_type: str = "full") -> str:
        return await self._toolkit.execute_tool("get_schema", databaseName=self._db_name, schemaType=schema_type)

    async def define_schema(self, schema_definition: str) -> str:
        return await self._toolkit.execute_tool("define_schema", databaseName=self._db_name, schemaDefinition=schema_definition)

    async def undefine_schema(self, schema_undefinition: str) -> str:
        return await self._toolkit.execute_tool("undefine_schema", databaseName=self._db_name, schemaUndefinition=schema_undefinition)

    async def validate_query(self, query: str) -> str:
        return await self._toolkit.execute_tool("validate_query", databaseName=self._db_name, query=query)

    async def exists(self) -> bool:
        return await self._toolkit.database_exists(self._db_name)


# --- Classe Principal do Toolkit ---


class TypeDBToolkit(Toolkit):
    
    # CORREÇÃO: Adicionar anotações de tipo aos atributos da classe.
    _ws: WebSocketClientProtocol
    _config: TypeDBConfig
    _tools_schema: Dict[str, Dict[str, Any]]
    _pending_responses: Dict[str, asyncio.Future[CallToolResult]]
    _listener_task: Optional[asyncio.Task[None]]

    def __init__(self, websocket: WebSocketClientProtocol, tools_schema: List[Dict[str, Any]], config: TypeDBConfig):
        super().__init__(name="typedb")
        self._ws = websocket
        self._config = config
        self._tools_schema = {tool["name"]: tool for tool in tools_schema}
        self._pending_responses = {}
        self._listener_task = None

        for tool_name, tool_spec in self._tools_schema.items():
            self._add_tool_method(tool_name, tool_spec)

    @classmethod
    async def create(cls, server_url: str, use_security_token: bool = False) -> "TypeDBToolkit":
        ca_path = get_ca_cert_path()
        # Determine role based on use_security_token.
        # The issue description implies 'readonly-role' for True, and 'admin-role' for False.
        # This seems counter-intuitive if 'use_security_token' implies more secure/restricted.
        # Sticking to the issue's direct request:
        role_name = "readonly-role" if use_security_token else "admin-role"
        token = get_oidc_token(role_name)
        
        headers = {"Authorization": f"Bearer {token}"}
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(cafile=ca_path)
        
        # Assuming _send_initialize and _listen_for_messages are existing methods
        # that need to be called as part of the toolkit creation.
        websocket = await websockets.connect(server_url, extra_headers=headers, ssl=ssl_context)
        
        # The following lines for _send_initialize and _listener_task are based on the issue description's snippet.
        # Ensure they match the actual class structure.
        # If 'cls._send_initialize' and 'toolkit._listen_for_messages' are not defined elsewhere,
        # this will cause an error. For now, assuming they exist as per the issue.

        # Placeholder for actual initialization logic if it differs:
        # init_result = await cls._send_initialize(websocket) # From issue
        # toolkit = cls(websocket, init_result.tools) # From issue
        # toolkit._listener_task = asyncio.create_task(toolkit._listen_for_messages()) # From issue

        # A more generic way if the above are not exactly matching:
        # Create an instance of the class first
        # toolkit = cls(websocket, []) # Assuming tools might be empty or populated later

        # If _send_initialize is a method of the instance:
        # init_result = await toolkit._send_initialize(websocket)
        # toolkit.tools = init_result.tools # or however tools are set

        # If _listen_for_messages is a method of the instance:
        # toolkit._listener_task = asyncio.create_task(toolkit._listen_for_messages())

        # For the subtask, let's use the structure provided in the issue strictly:
        # Adjusting the constructor call to include a TypeDBConfig instance
        temp_config = TypeDBConfig(server_url=server_url, auth_token=token, tls_ca_path=ca_path)
        init_result = await cls._send_initialize(websocket) # This must be a static or class method
        toolkit = cls(websocket, init_result.tools, temp_config) # Pass the created config
        toolkit._listener_task = asyncio.create_task(toolkit._listen_for_messages()) # This is an instance method

        return toolkit

    async def close(self):
        if self._listener_task and not self._listener_task.done():
            self._listener_task.cancel()
        if self._ws and not self._ws.closed:
            await self._ws.close()

    @staticmethod
    async def _send_initialize(websocket: WebSocketClientProtocol) -> InitializeResult:
        req_id = "init-" + uuid.uuid4().hex
        message = {"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": req_id}
        await websocket.send(json.dumps(message))
        response_raw = await websocket.recv()
        resp_data = json.loads(str(response_raw)) # Cast para string para garantir
        if resp_data.get("id") != req_id or "result" not in resp_data:
            raise TypeDBError(f"Resposta de inicialização inválida: {resp_data.get('error')}")
        return InitializeResult.model_validate(resp_data["result"])

    async def _listen_for_messages(self):
        try:
            async for message_raw in self._ws:
                resp_data = json.loads(str(message_raw))
                resp_id = resp_data.get("id")
                if resp_id and resp_id in self._pending_responses:
                    future = self._pending_responses.pop(resp_id)
                    if "error" in resp_data:
                        error = ErrorData.model_validate(resp_data["error"])
                        future.set_exception(McpError(error))
                    else:
                        future.set_result(CallToolResult.model_validate(resp_data["result"]))
        except websockets.ConnectionClosed:
            pass
        except Exception as e:
            for future in self._pending_responses.values():
                if not future.done():
                    future.set_exception(e)

    # CORREÇÃO: Renomear _execute_tool para execute_tool (torná-lo público para o _DatabaseHandler).
    # Uma alternativa seria manter _execute_tool e fazer o _DatabaseHandler chamar um método público
    # que por sua vez chama o privado, mas para simplicidade, torná-lo público é aceitável aqui.
    async def execute_tool(self, tool_name: str, **kwargs: Any) -> Any:
        """Envia uma chamada de ferramenta MCP e aguarda a resposta."""
        if self._ws.closed:
            raise ConnectionError("A conexão WebSocket está fechada.")
            
        req_id = str(uuid.uuid4())
        message = {"jsonrpc": "2.0", "method": "call_tool", "params": {"name": tool_name, "arguments": kwargs}, "id": req_id}
        future: asyncio.Future[CallToolResult] = asyncio.get_event_loop().create_future()
        self._pending_responses[req_id] = future
        
        try:
            await self._ws.send(json.dumps(message))
            result = await asyncio.wait_for(future, timeout=self._config.request_timeout)
            
            if result.isError:
                # FIX: Corrigido para fornecer o parâmetro 'type' obrigatório.
                error_content = result.content[0] if result.content else TextContent(type="text", text="Erro desconhecido")
                raise ToolExecutionError(f"A ferramenta '{tool_name}' falhou: {error_content.text}")

            if result.content and isinstance(result.content[0], TextContent):
                text_response = result.content[0].text
                try:
                    return json.loads(text_response)
                except json.JSONDecodeError:
                    return text_response
            return None
        except asyncio.TimeoutError:
            raise TimeoutError(f"A chamada da ferramenta '{tool_name}' expirou.")
        except McpError as e:
            if e.error.code == 403 or "Authorization" in e.error.message:
                raise AuthorizationError(e.error.message, e)
            raise ToolExecutionError(f"Ferramenta '{tool_name}' falhou: {e.error.message}", e)
        finally:
            self._pending_responses.pop(req_id, None)

    def _add_tool_method(self, tool_name: str, tool_spec: Dict[str, Any]):
        async def tool_method(**kwargs: Any) -> Any:
            # CORREÇÃO: Chamar o método agora público.
            return await self.execute_tool(tool_name, **kwargs)
        
        description = tool_spec.get('description', 'Nenhuma descrição fornecida.')
        params = tool_spec.get('parameters', {}).get('properties', {})
        param_docs = "\n".join([f"    {name} ({spec.get('type', 'any')}): {spec.get('description', '')}" for name, spec in params.items()])
        tool_method.__doc__ = f"{description}\n\nArgs:\n{param_docs}"
        tool_method.__name__ = tool_name
        
        setattr(self, tool_name, tool_method)
        self.register(tool_method, name=tool_name)
    
    # --- API de Alto Nível ---

    async def list_databases(self) -> List[str]:
        return await self.execute_tool("list_databases")

    async def create_database(self, name: str) -> str:
        return await self.execute_tool("create_database", name=name)
        
    async def delete_database(self, name: str) -> str:
        return await self.execute_tool("delete_database", name=name)

    async def database_exists(self, name: str) -> bool:
        result = await self.execute_tool("database_exists", name=name)
        return str(result).lower() == "true"

    def database(self, name: str) -> "_DatabaseHandler":
        return _DatabaseHandler(self, name)


# --- Ponto de Entrada Público ---


@asynccontextmanager
async def typedb_toolkit(config: TypeDBConfig) -> AsyncGenerator["TypeDBToolkit", None]:
    toolkit = None
    try:
        toolkit = await TypeDBToolkit.create(config)
        yield toolkit
    finally:
        if toolkit:
            await toolkit.close()