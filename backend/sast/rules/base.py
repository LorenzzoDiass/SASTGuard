"""Base class and registry for AST rules."""
from __future__ import annotations

import ast
from typing import Dict, List, Type

from sast.models import Finding
from sast.parser.ast_parser import ParsedModule


class Rule:
    """Base class for a single AST detection rule.

    Subclasses implement :meth:`check`, which receives the parsed module and
    returns a list of :class:`Finding`. Rules operate purely on the AST and
    source text; they never execute analysed code.
    """

    rule_id: str = "GENERIC"
    title: str = "Generic rule"

    def check(self, module: ParsedModule) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    # convenience ------------------------------------------------------------
    def iter_calls(self, module: ParsedModule):
        """Yield every ast.Call node in the module tree."""
        if not module.tree:
            return
        for node in ast.walk(module.tree):
            if isinstance(node, ast.Call):
                yield node


_REGISTRY: Dict[str, Rule] = {}


def register(cls: Type[Rule]) -> Type[Rule]:
    """Class decorator that instantiates and registers a rule."""
    instance = cls()
    _REGISTRY[instance.rule_id] = instance
    return cls


def get_rules() -> List[Rule]:
    """Return all registered rule instances."""
    return list(_REGISTRY.values())
