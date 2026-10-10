"""Thin client for a local Ollama server.

Never raises on connection problems: callers get None and fall back to the
deterministic analysis. No external paid APIs are used.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from app.core.config import settings

logger = logging.getLogger("sastguard.ai")


class OllamaClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.model = model or settings.ollama_model
        self.timeout = timeout or settings.ollama_timeout

    def is_available(self) -> bool:
        """Return True if the Ollama server responds to /api/tags."""
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception as exc:  # noqa: BLE001 - any failure means unavailable
            logger.debug("Ollama availability check failed: %s", exc)
            return False

    def generate(self, system: str, prompt: str) -> Optional[str]:
        """Call Ollama /api/chat and return the raw text response, or None.

        Uses non-streaming mode and requests JSON formatting from the model.
        """
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1},
        }
        try:
            resp = httpx.post(
                f"{self.base_url}/api/chat", json=payload, timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            # /api/chat returns {"message": {"content": "..."}}
            return data.get("message", {}).get("content")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Ollama generate failed: %s", exc)
            return None
