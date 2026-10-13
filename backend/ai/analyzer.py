
"""AI analyzer: turns a detected finding into an enriched, structured review.

Pipeline position:
    SAST detects -> Finding created -> AI receives minimal context ->
    AI returns JSON (severity, false-positive, explanation, remediation,
    fixed_code).

If the configured AI provider is disabled or unreachable, analyze returns
available=False. The deterministic SAST analysis remains intact.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from ai.ollama_client import OllamaClient
from ai.groq_client import GroqClient
from ai.prompts import SYSTEM_PROMPT, build_user_prompt
from app.core.config import settings
from app.core.enums import Severity

_VALID_SEVERITIES = {s.value for s in Severity}


@dataclass
class AIResult:
    available: bool = False
    model: Optional[str] = None
    ai_severity: Optional[str] = None
    confidence: Optional[float] = None
    possible_false_positive: Optional[bool] = None
    explanation: str = "AI analysis unavailable"
    impact: str = ""
    remediation: str = ""
    fixed_code: str = ""

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "model": self.model,
            "ai_severity": self.ai_severity,
            "confidence": self.confidence,
            "possible_false_positive": self.possible_false_positive,
            "explanation": self.explanation,
            "impact": self.impact,
            "remediation": self.remediation,
            "fixed_code": self.fixed_code,
        }


class AIAnalyzer:
    def __init__(self, client=None):
        if client is not None:
            self.client = client
        elif settings.ai_provider.lower() == "groq":
            self.client = GroqClient()
        else:
            self.client = OllamaClient()

    def analyze(self, finding: dict) -> AIResult:
        """Analyze a finding dict. Always returns an AIResult."""
        if (
            settings.ai_provider.lower() != "groq"
            and not settings.ollama_enabled
        ):
            return AIResult(
                available=False,
                explanation="AI analysis unavailable",
            )

        if not self.client.is_available():
            return AIResult(
                available=False,
                explanation="AI analysis unavailable",
            )

        prompt = build_user_prompt(finding)
        raw = self.client.generate(SYSTEM_PROMPT, prompt)

        if not raw:
            return AIResult(
                available=False,
                explanation="AI analysis unavailable",
            )

        parsed = _safe_parse_json(raw)

        if parsed is None:
            return AIResult(
                available=False,
                explanation="AI analysis unavailable (unparseable response)",
            )

        return self._to_result(parsed)

    def _to_result(self, data: dict) -> AIResult:
        severity = str(data.get("severity", "")).upper().strip()

        if severity not in _VALID_SEVERITIES:
            severity = None

        confidence = _coerce_float(data.get("confidence"))

        fp = data.get("possible_false_positive")

        if isinstance(fp, str):
            fp = fp.strip().lower() in ("true", "yes", "1")

        return AIResult(
            available=True,
            model=self.client.model,
            ai_severity=severity,
            confidence=confidence,
            possible_false_positive=bool(fp) if fp is not None else None,
            explanation=str(data.get("explanation", "")).strip(),
            impact=str(data.get("impact", "")).strip(),
            remediation=str(data.get("remediation", "")).strip(),
            fixed_code=str(data.get("fixed_code", "")).strip(),
        )


def _coerce_float(value) -> Optional[float]:
    try:
        f = float(value)
        return max(0.0, min(1.0, f))
    except (TypeError, ValueError):
        return None


def _safe_parse_json(text: str) -> Optional[dict]:
    """Parse JSON, tolerating code fences and surrounding text."""
    text = text.strip()

    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    fenced = re.search(
        r"```(?:json)?\s*(\{.*?\})\s*```",
        text,
        re.DOTALL,
    )

    if fenced:
        try:
            obj = json.loads(fenced.group(1))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    brace = re.search(r"\{.*\}", text, re.DOTALL)

    if brace:
        try:
            obj = json.loads(brace.group(0))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    return None
