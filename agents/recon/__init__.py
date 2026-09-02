"""Reconnaissance agent package for authorized KOTH/CTF research."""

from .agent import ReconAgent, ReconError, TargetRegistry, UnregisteredTargetError
from .planner import ReconPlanner
from .tools import (
    ArbitraryCommandError,
    BaseTool,
    ExecutionAdapter,
    GatewayExecutionAdapter,
    HttpProbeTool,
    MockExecutionAdapter,
    PolicyViolationError,
    ToolError,
    ToolRegistry,
    ToolValidationError,
)

__all__ = [
    "ReconAgent",
    "ReconError",
    "UnregisteredTargetError",
    "TargetRegistry",
    "ReconPlanner",
    "BaseTool",
    "HttpProbeTool",
    "ToolRegistry",
    "ExecutionAdapter",
    "MockExecutionAdapter",
    "GatewayExecutionAdapter",
    "ToolError",
    "ToolValidationError",
    "ArbitraryCommandError",
    "PolicyViolationError",
]
