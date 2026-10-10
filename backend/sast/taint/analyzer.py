"""Intraprocedural taint analysis for Python.

Tracks data flowing from untrusted SOURCES through variable PROPAGATION into
dangerous SINKS, producing a Finding with the full source->propagation->sink
chain. Sanitizers clear taint. A limited interprocedural pass links functions
whose arguments are tainted at the call site.

The analysis is purely static over the AST; analysed code is never executed.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from sast.models import Finding, TaintStep
from sast.parser.ast_parser import ParsedModule, attr_chain
from sast.taint.config import (
    SOURCE_CALLS,
    SOURCE_ATTRS,
    SINKS,
    SANITIZER_CALLS,
)


@dataclass
class TaintState:
    """Taint facts for a single function scope."""

    # variable name -> origin description (the source expression text)
    tainted: Dict[str, str] = field(default_factory=dict)
    # variable name -> source line where it became tainted
    origin_line: Dict[str, int] = field(default_factory=dict)
    # variable name -> propagation chain (list of TaintStep)
    chain: Dict[str, List[TaintStep]] = field(default_factory=dict)


class TaintAnalyzer:
    def __init__(self, module: ParsedModule):
        self.module = module
        self.findings: List[Finding] = []
        # function name -> set of parameter indices that are tainted at a call site
        self._tainted_funcs: Dict[str, Set[int]] = {}

    # ------------------------------------------------------------------ API
    def analyze(self) -> List[Finding]:
        if not self.module.tree:
            return self.findings

        functions = [
            n for n in ast.walk(self.module.tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        # First pass: analyse each function body and the module top-level.
        self._analyze_scope(self.module.tree.body, params_tainted=set())
        for fn in functions:
            self._analyze_scope(fn.body, params_tainted=self._tainted_funcs.get(fn.name, set()),
                                 param_names=[a.arg for a in fn.args.args])
        return self.findings

    # ------------------------------------------------------------- internals
    def _analyze_scope(self, body: List[ast.stmt], params_tainted: Set[int],
                       param_names: Optional[List[str]] = None) -> None:
        state = TaintState()

        # Seed tainted parameters (interprocedural propagation).
        if param_names:
            for idx, pname in enumerate(param_names):
                if idx in params_tainted:
                    state.tainted[pname] = f"tainted argument '{pname}'"
                    state.origin_line[pname] = 0
                    state.chain[pname] = [
                        TaintStep("SOURCE", f"tainted parameter '{pname}'", 0, pname)
                    ]

        self._checked_calls: Set[int] = set()
        for stmt in body:
            self._visit_stmt(stmt, state)

    def _visit_stmt(self, stmt: ast.stmt, state: TaintState) -> None:
        if isinstance(stmt, ast.Assign):
            self._handle_assign(stmt, state)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self._handle_assign_like(stmt.target, stmt.value, stmt.lineno, state)
        elif isinstance(stmt, ast.AugAssign):
            # x += tainted  -> x becomes tainted
            self._handle_assign_like(stmt.target, stmt.value, stmt.lineno, state,
                                     augmented_target=stmt.target)

        # Check call expressions that belong directly to this statement
        # (expressions in this node, excluding nested statement bodies) against
        # sinks. This keeps ordering correct: nested statements are visited
        # afterwards with the taint state produced here.
        for node in self._own_calls(stmt):
            if id(node) not in self._checked_calls:
                self._checked_calls.add(id(node))
                self._check_sink(node, state)
                self._track_call_propagation(node, state)

        # Recurse into nested statements (if/for/while/with/try bodies) in order,
        # so later statements see taint state updated by earlier ones.
        # Do NOT descend into nested function/class definitions: those get their
        # own dedicated scope pass (avoids double-analysis).
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                self._visit_stmt(child, state)

    @staticmethod
    def _own_calls(stmt: ast.stmt) -> List[ast.Call]:
        """Yield Call nodes that belong to this statement's own expressions,
        not those inside nested statement bodies (which are visited separately).
        """
        calls: List[ast.Call] = []
        for field_name, value in ast.iter_fields(stmt):
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, ast.stmt):
                    continue  # skip nested statements
                if isinstance(item, ast.AST):
                    for sub in ast.walk(item):
                        if isinstance(sub, ast.Call):
                            calls.append(sub)
        return calls

    # --- assignments ---------------------------------------------------
    def _handle_assign(self, stmt: ast.Assign, state: TaintState) -> None:
        for target in stmt.targets:
            self._handle_assign_like(target, stmt.value, stmt.lineno, state)

    def _handle_assign_like(self, target: ast.expr, value: ast.expr, lineno: int,
                            state: TaintState, augmented_target: Optional[ast.expr] = None) -> None:
        if not isinstance(target, ast.Name):
            return
        name = target.id

        src_desc = self._taint_of_expr(value, state)
        extra_tainted = bool(augmented_target and name in state.tainted)

        if src_desc is None and not extra_tainted:
            # assignment clears any previous taint
            state.tainted.pop(name, None)
            state.chain.pop(name, None)
            state.origin_line.pop(name, None)
            return

        # Build/extend the propagation chain.
        code = self.module.snippet(lineno)
        if self._expr_is_direct_source(value):
            chain = [TaintStep("SOURCE", src_desc or "untrusted input", lineno, code)]
            state.origin_line[name] = lineno
        else:
            # propagated from existing tainted vars
            base_chain = self._inherit_chain(value, state)
            chain = list(base_chain)
            chain.append(TaintStep("PROPAGATION", f"{self._vars_in(value, state)} -> {name}",
                                   lineno, code))
            state.origin_line.setdefault(name, lineno)

        state.tainted[name] = src_desc or state.tainted.get(name, "tainted")
        state.chain[name] = chain

    # --- expression taint ----------------------------------------------
    def _taint_of_expr(self, expr: ast.expr, state: TaintState) -> Optional[str]:
        """Return a description if the expression is tainted, else None.

        Sanitizer-aware: a tainted value wrapped in a sanitizer call (e.g.
        int(x), os.path.basename(x), shlex.quote(x)) is considered clean and
        the traversal does not descend into its arguments.
        """
        # A sanitizer call neutralizes any taint flowing through it.
        if isinstance(expr, ast.Call):
            fname = attr_chain(expr.func)
            if fname in SANITIZER_CALLS:
                return None

        # Direct source call/attr/subscript at this node.
        direct = self._direct_source_desc(expr)
        if direct:
            return direct

        # A bare tainted variable reference.
        if isinstance(expr, ast.Name) and expr.id in state.tainted:
            return state.tainted[expr.id]

        # Recurse into child expressions (so sanitizer short-circuit applies
        # per sub-expression instead of flattening the whole tree).
        for child in ast.iter_child_nodes(expr):
            if isinstance(child, ast.expr):
                desc = self._taint_of_expr(child, state)
                if desc is not None:
                    return desc
        return None

    def _direct_source_desc(self, node: ast.AST) -> Optional[str]:
        """If node is a direct taint source, return its description."""
        if isinstance(node, ast.Call):
            name = attr_chain(node.func)
            if name in SOURCE_CALLS:
                return f"{name}(...)"
        if isinstance(node, ast.Subscript):
            base = attr_chain(node.value)
            if base in SOURCE_ATTRS:
                return f"{base}[...]"
        if isinstance(node, ast.Attribute):
            chain = attr_chain(node)
            if chain in SOURCE_ATTRS:
                return chain
        return None

    def _expr_is_direct_source(self, expr: ast.expr) -> bool:
        return self._direct_source_desc(expr) is not None

    def _inherit_chain(self, expr: ast.expr, state: TaintState) -> List[TaintStep]:
        for node in ast.walk(expr):
            if isinstance(node, ast.Name) and node.id in state.chain:
                return state.chain[node.id]
        return []

    def _vars_in(self, expr: ast.expr, state: TaintState) -> str:
        names = [n.id for n in ast.walk(expr)
                 if isinstance(n, ast.Name) and n.id in state.tainted]
        return ", ".join(dict.fromkeys(names)) or "input"

    # --- call propagation (interprocedural seed) -----------------------
    def _track_call_propagation(self, call: ast.Call, state: TaintState) -> None:
        """Record that a user function was called with tainted args."""
        fname = attr_chain(call.func)
        for idx, arg in enumerate(call.args):
            if self._taint_of_expr(arg, state) is not None:
                self._tainted_funcs.setdefault(fname, set()).add(idx)

    # --- sinks ----------------------------------------------------------
    def _check_sink(self, call: ast.Call, state: TaintState) -> None:
        for category, meta in SINKS.items():
            if not self._call_matches_sink(call, meta):
                continue
            tainted_arg = self._first_tainted_arg(call, state)
            if tainted_arg is None:
                continue

            arg_expr, desc = tainted_arg

            # Parameterized SQL is safe: execute(sql, params) with a constant sql
            if category == "sql" and self._is_parameterized_sql(call):
                continue

            # Command sink with an argv list and shell=False is safe: the shell
            # is never involved, so a tainted element is just an argument value.
            if category == "command" and self._is_safe_argv(call, arg_expr):
                continue

            chain = self._build_sink_chain(call, arg_expr, state, meta, category)
            self.findings.append(self._make_finding(call, meta, chain))

    def _is_safe_argv(self, call: ast.Call, tainted_arg: ast.expr) -> bool:
        """True when a subprocess call uses an argument list with shell=False.

        os.system/os.popen always use the shell, so they are never "safe argv".
        """
        name = attr_chain(call.func)
        if name in ("os.system", "os.popen"):
            return False
        # shell=True is explicitly unsafe.
        for kw in call.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return False
        # The tainted argument must be (inside) a list/tuple literal, i.e. argv.
        return isinstance(tainted_arg, (ast.List, ast.Tuple))

    def _call_matches_sink(self, call: ast.Call, meta: dict) -> bool:
        name = attr_chain(call.func)
        if meta.get("attr_only"):
            if not isinstance(call.func, ast.Attribute):
                return False
            return call.func.attr in meta["calls"]
        return name in meta["calls"] or (
            isinstance(call.func, ast.Attribute) and call.func.attr in meta["calls"]
        )

    def _first_tainted_arg(self, call: ast.Call, state: TaintState):
        for arg in call.args:
            desc = self._taint_of_expr(arg, state)
            if desc is not None:
                return arg, desc
        return None

    def _is_parameterized_sql(self, call: ast.Call) -> bool:
        """execute(query, params): query must not itself be a tainted dynamic string."""
        if not call.args:
            return False
        first = call.args[0]
        has_params = len(call.args) >= 2
        # If first arg is a plain string constant with placeholders -> safe
        if has_params and isinstance(first, ast.Constant) and isinstance(first.value, str):
            return True
        return False

    def _build_sink_chain(self, call: ast.Call, arg_expr: ast.expr, state: TaintState,
                          meta: dict, category: str) -> List[TaintStep]:
        chain: List[TaintStep] = []
        # Pull the propagation history from the tainted variable, if any.
        for node in ast.walk(arg_expr):
            if isinstance(node, ast.Name) and node.id in state.chain:
                chain = list(state.chain[node.id])
                break
        if not chain:
            # Direct source used inline at the sink.
            d = self._taint_of_expr(arg_expr, state)
            chain = [TaintStep("SOURCE", d or "untrusted input", call.lineno,
                               self.module.snippet(call.lineno))]
        sink_name = attr_chain(call.func)
        chain.append(TaintStep("SINK", f"{sink_name}(...)", call.lineno,
                               self.module.snippet(call.lineno)))
        return chain

    def _make_finding(self, call: ast.Call, meta: dict, chain: List[TaintStep]) -> Finding:
        return Finding(
            rule_id=meta["rule_id"],
            title=meta["title"],
            description=(
                "Taint analysis found a data flow from an untrusted source to a "
                "dangerous sink without sanitization."
            ),
            file_path=self.module.file_path,
            line=call.lineno,
            column=call.col_offset,
            code_snippet=self.module.snippet(call.lineno),
            severity=meta["severity"],
            confidence=0.85,
            cwe=meta["cwe"],
            owasp=meta["owasp"],
            recommendation=meta["recommendation"],
            engines=["taint"],
            taint_path=chain,
        )


def analyze_taint(module: ParsedModule) -> List[Finding]:
    """Convenience wrapper that runs taint analysis on a parsed module."""
    return TaintAnalyzer(module).analyze()
