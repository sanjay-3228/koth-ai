"""Tool interface and execution adapters for safe KOTH reconnaissance.

Enforces:
- Standard library Python.
- Tool registration for HTTP probing only.
- Strict rejection of arbitrary shell commands, reverse shells, or unknown parameters.
- Controlled execution interface delegating execution safely.
"""

from abc import ABC, abstractmethod
import json
import re
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error


class ToolError(Exception):
    """Base exception for tool execution errors."""
    pass


class ToolValidationError(ToolError):
    """Raised when tool parameters fail validation."""
    pass


class ArbitraryCommandError(ToolError):
    """Raised when arbitrary shell execution or command injection is detected."""
    pass


class PolicyViolationError(ToolError):
    """Raised when tool execution violates gateway or safety policy."""
    pass


# Disallow characters that could indicate command injection or path traversal
SHELL_METACHACTERS = {";", "`", "$", "&", "|", "*", "?", "~", "<", ">", "^", "(", ")", "[", "]", "{", "}", "\n", "\r", "\x00"}
BLOCKED_PARAMS = {"cmd", "command", "exec", "shell", "run", "args", "script", "bash", "sh"}


class ExecutionAdapter(ABC):
    """Controlled interface for executing registered reconnaissance actions."""

    @abstractmethod
    def execute_http_probe(
        self,
        target: Dict[str, Any],
        path: str = "/",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Execute a bounded HTTP probe against an authorized target."""
        pass

    def execute_command(self, *args, **kwargs) -> Any:
        """Explicitly refuse arbitrary shell command execution."""
        raise ArbitraryCommandError("Direct execution of arbitrary shell commands is strictly prohibited by security policy")


class MockExecutionAdapter(ExecutionAdapter):
    """In-memory controlled execution adapter for testing and deterministic evaluation."""

    def __init__(self, routes: Optional[Dict[str, Dict[str, Any]]] = None):
        self.routes: Dict[str, Dict[str, Any]] = routes or {
            "/": {
                "status": 200,
                "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/html; charset=utf-8"},
                "body": "<html><body><h1>KOTH Lab Target 01</h1></body></html>",
            },
            "/robots.txt": {
                "status": 200,
                "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/plain"},
                "body": "User-agent: *\nDisallow: /admin\nDisallow: /internal-secret\n",
            },
            "/admin": {
                "status": 200,
                "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/html"},
                "body": "Admin Dashboard [Training Mode Active]",
            },
            "/internal-secret": {
                "status": 403,
                "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/plain"},
                "body": "Forbidden: Internal network only",
            },
        }
        self.call_history: List[Dict[str, Any]] = []

    def set_route(self, path: str, response: Dict[str, Any]) -> None:
        self.routes[path] = response

    def execute_http_probe(
        self,
        target: Dict[str, Any],
        path: str = "/",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        self.call_history.append({
            "target": target.get("id"),
            "path": path,
            "method": method,
            "headers": headers or {},
        })

        route_data = self.routes.get(path, {
            "status": 404,
            "headers": {"Server": "BaseHTTP/0.6", "Content-Type": "text/plain"},
            "body": "404 Not Found",
        })

        status_code = int(route_data.get("status", 404))
        is_success = 200 <= status_code < 400

        return {
            "tool": "http_probe",
            "target": target.get("id"),
            "path": path,
            "method": method,
            "status_code": status_code,
            "headers": route_data.get("headers", {}),
            "body": route_data.get("body", ""),
            "success": is_success,
        }


class GatewayExecutionAdapter(ExecutionAdapter):
    """Adapter executing safe HTTP probes against resolved lab targets via standard HTTP requests."""

    def __init__(self, default_timeout: float = 5.0):
        self.default_timeout = default_timeout

    def execute_http_probe(
        self,
        target: Dict[str, Any],
        path: str = "/",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        ip = target.get("ip")
        port = target.get("port", 8080)
        target_id = target.get("id", "unknown")

        if not ip:
            # Fallback if container is on localhost/mapped port in dev or resolve error
            ip = "127.0.0.1"

        url = f"http://{ip}:{port}{path}"
        req = urllib.request.Request(url, method=method)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

        try:
            with urllib.request.urlopen(req, timeout=self.default_timeout) as resp:
                status_code = resp.status
                resp_headers = dict(resp.headers.items())
                body_bytes = resp.read()
                body = body_bytes.decode("utf-8", errors="replace")
                return {
                    "tool": "http_probe",
                    "target": target_id,
                    "path": path,
                    "method": method,
                    "status_code": status_code,
                    "headers": resp_headers,
                    "body": body,
                    "success": 200 <= status_code < 400,
                }
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            return {
                "tool": "http_probe",
                "target": target_id,
                "path": path,
                "method": method,
                "status_code": exc.code,
                "headers": dict(exc.headers.items()) if exc.headers else {},
                "body": body,
                "success": False,
            }
        except Exception as exc:
            return {
                "tool": "http_probe",
                "target": target_id,
                "path": path,
                "method": method,
                "status_code": 0,
                "headers": {},
                "body": "",
                "error": str(exc),
                "success": False,
            }


class BaseTool(ABC):
    """Abstract base class for all registered reconnaissance tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        pass

    @abstractmethod
    def validate_parameters(self, params: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    def execute(
        self,
        target: Dict[str, Any],
        params: Dict[str, Any],
        adapter: ExecutionAdapter,
    ) -> Dict[str, Any]:
        pass


class HttpProbeTool(BaseTool):
    """Registered safe HTTP reconnaissance probe."""

    @property
    def name(self) -> str:
        return "http_probe"

    @property
    def description(self) -> str:
        return "Safe, bounded HTTP GET/HEAD reconnaissance probe against an authorized target"

    def validate_parameters(self, params: Dict[str, Any]) -> None:
        if not isinstance(params, dict):
            raise ToolValidationError("Tool parameters must be a dictionary")

        # Check for arbitrary command injection attempts
        for key in params.keys():
            if key.lower() in BLOCKED_PARAMS:
                raise ArbitraryCommandError(f"Prohibited command parameter detected: '{key}'")

        allowed_keys = {"path", "method", "headers"}
        extra = set(params.keys()) - allowed_keys
        if extra:
            raise ArbitraryCommandError(f"Unauthorized tool parameters: {extra}")

        path = params.get("path", "/")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ToolValidationError(f"Invalid path: '{path}'. Must be a string starting with '/'")

        if ".." in path:
            raise ToolValidationError(f"Path traversal characters '..' are prohibited in path: {path}")

        for ch in SHELL_METACHACTERS:
            if ch in path:
                raise ArbitraryCommandError(f"Shell metacharacter '{ch}' is prohibited in path")

        method = params.get("method", "GET")
        if not isinstance(method, str) or method.upper() not in {"GET", "HEAD"}:
            raise ToolValidationError(f"Prohibited HTTP method '{method}'. Only read-only GET and HEAD are permitted.")

        headers = params.get("headers")
        if headers is not None:
            if not isinstance(headers, dict):
                raise ToolValidationError("Headers must be a dictionary of strings")
            for k, v in headers.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise ToolValidationError("Header keys and values must be strings")
                for ch in SHELL_METACHACTERS:
                    if ch in k or ch in v:
                        raise ArbitraryCommandError(f"Shell metacharacter in header: {k}={v}")

    def execute(
        self,
        target: Dict[str, Any],
        params: Dict[str, Any],
        adapter: ExecutionAdapter,
    ) -> Dict[str, Any]:
        self.validate_parameters(params)

        path = params.get("path", "/")
        method = params.get("method", "GET").upper()
        headers = params.get("headers")

        return adapter.execute_http_probe(
            target=target,
            path=path,
            method=method,
            headers=headers,
        )


class ToolRegistry:
    """Central registry for authorized reconnaissance tools."""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        # Pre-register default safe HTTP probe
        self.register(HttpProbeTool())

    def register(self, tool: BaseTool) -> None:
        if not isinstance(tool, BaseTool):
            raise ToolValidationError("Tool must implement BaseTool")
        self._tools[tool.name] = tool

    def get(self, tool_name: str) -> BaseTool:
        if tool_name not in self._tools:
            raise ToolValidationError(f"Tool '{tool_name}' is not registered in reconnaissance registry")
        return self._tools[tool_name]

    def has(self, tool_name: str) -> bool:
        return tool_name in self._tools

    def list_tools(self) -> List[str]:
        return sorted(list(self._tools.keys()))
