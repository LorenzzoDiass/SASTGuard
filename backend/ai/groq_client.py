
"""Cliente Groq compatível com o AIAnalyzer do SASTGuard."""
import logging
from typing import Optional

import httpx

from app.core.config import settings

logger = logging.getLogger("sastguard.ai")


class GroqClient:
    def __init__(self):
        self.model = settings.groq_model
        self.timeout = settings.groq_timeout
        self.api_key = settings.groq_api_key
        self.base_url = "https://api.groq.com/openai/v1"

    def is_available(self) -> bool:
        return bool(self.api_key)

    def generate(self, system: str, prompt: str) -> Optional[str]:
        if not self.api_key:
            return None

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }

        try:
            response = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except Exception as exc:
            logger.warning("Groq generate failed: %s", exc)
            return None
