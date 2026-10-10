"""Extensible SAST rule registry.

Rules self-register via the ``@register`` decorator. The AST scanner iterates
over all registered rules, so adding a new detection is just adding a class.
"""
from sast.rules.base import Rule, register, get_rules

# Import rule modules so their classes register on import.
from sast.rules import secrets          # noqa: F401
from sast.rules import dangerous_calls  # noqa: F401
from sast.rules import crypto           # noqa: F401
from sast.rules import deserialization  # noqa: F401
from sast.rules import injection        # noqa: F401
from sast.rules import misc             # noqa: F401

__all__ = ["Rule", "register", "get_rules"]
