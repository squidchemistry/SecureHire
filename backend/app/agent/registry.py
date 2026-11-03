"""Structured tool registry: every tool has strict Pydantic input/output schemas.

A model-proposed call is executed only after `validate_call()` has checked,
in order: the name is well-formed and registered, the tool is on this step's
allowlist, the arguments are a small JSON object, no identity field is
present, and the arguments validate against the input schema (unknown fields
are rejected). Identity never comes from arguments: tools receive the user id
from the server-side `ToolContext`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy.orm import Session

from app.config import Settings
from app.llm.base import LLMClient

MAX_ARGS_CHARS = 2_000
_NAME = re.compile(r"^[a-z][a-z0-9_]{1,48}$")
IDENTITY_KEYS = {"user_id", "userid", "user", "owner", "owner_id", "account", "account_id", "tenant", "tenant_id"}


class StrictInput(BaseModel):
    """Base for tool inputs: unknown fields are an error, strings are bounded."""

    model_config = ConfigDict(extra="forbid", str_max_length=200)


class ToolError(Exception):
    """Permanent failure; the message is safe to show to the model and the user."""


class TransientToolError(ToolError):
    """Retryable failure (timeouts, temporary upstream errors)."""


@dataclass(frozen=True)
class ToolContext:
    """Server-side execution context. Nothing here is chosen by the model."""

    user_id: int
    run_id: str
    settings: Settings
    llm: LLMClient
    open_session: Callable[[], AbstractContextManager[Session]]
    options: Mapping[str, Any]
    resume_document_id: str | None
    jd_document_id: str | None
    artifacts: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_model: type[StrictInput]
    output_model: type[BaseModel]
    fn: Callable[[Any, ToolContext], BaseModel | dict[str, Any]]
    produces: str
    requires: tuple[str, ...] = ()
    max_calls: int = 2
    # What the model sees as the observation (defaults to the full output).
    render: Callable[[Any], Any] | None = None
    # What the UI timeline shows: counts and names only, never document text.
    summarize: Callable[[Any], dict[str, Any]] | None = None

    def openai_schema(self) -> dict[str, Any]:
        params = self.input_model.model_json_schema()
        params.pop("title", None)
        return {
            "type": "function",
            "function": {"name": self.name, "description": self.description, "parameters": params},
        }


class CallRejected(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# Rejections that indicate an attack or a compromised model, not a slip.
SECURITY_CODES = {"unknown_tool", "not_allowed", "identity_field", "too_many_calls"}


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool {tool.name}")
        if not _NAME.match(tool.name):
            raise ValueError(f"invalid tool name {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        return self._tools[name]

    def __iter__(self) -> Iterator[Tool]:
        return iter(self._tools.values())

    def names(self) -> list[str]:
        return list(self._tools)

    def schemas(self, names: list[str]) -> list[dict[str, Any]]:
        return [self._tools[n].openai_schema() for n in names]

    def validate_call(self, name: str, raw_args: str, allowed: set[str]) -> tuple[Tool, StrictInput]:
        if not isinstance(name, str) or not _NAME.match(name) or name not in self._tools:
            raise CallRejected("unknown_tool", "No such tool exists.")
        if name not in allowed:
            raise CallRejected("not_allowed", f"Tool '{name}' is not available at this step.")
        if raw_args is None or len(raw_args) > MAX_ARGS_CHARS:
            raise CallRejected("malformed_arguments", "Arguments missing or too large.")
        try:
            args = json.loads(raw_args or "{}")
        except json.JSONDecodeError:
            raise CallRejected("malformed_arguments", "Arguments are not valid JSON.") from None
        if not isinstance(args, dict):
            raise CallRejected("malformed_arguments", "Arguments must be a JSON object.")
        lowered = {str(k).lower() for k in args}
        if lowered & IDENTITY_KEYS:
            raise CallRejected(
                "identity_field",
                "Identity is set by the server; tools do not accept user identifiers.",
            )
        tool = self._tools[name]
        try:
            parsed = tool.input_model.model_validate(args)
        except ValidationError as exc:
            fields = ", ".join(".".join(str(p) for p in e["loc"]) or "(root)" for e in exc.errors()[:5])
            raise CallRejected("schema_violation", f"Invalid arguments for '{name}': {fields}.") from None
        return tool, parsed
