"""
Feature 15 - LLM natural-language explanation layer.

CRITICAL ARCHITECTURAL RULE: the LLM is ONLY a natural-language
explanation layer over already-computed, structured, model-grounded
evidence. It MUST NOT make the attack prediction, change the attack
probability, calculate the MITRE score, select the MITRE stage,
calculate a risk score, decide mitigation, invent evidence, invent
feature contributions, or override any model output. The deterministic
explainability engine (model_explainer.py, Feature 13, Feature 14) is
the sole source of truth; the LLM only rephrases it.

Provider is configurable and the project MUST remain runnable without
any LLM API key: DisabledLLMExplainer is the default and performs no
network access.
"""

import json
import os
from abc import ABC, abstractmethod


SYSTEM_INSTRUCTIONS = """You are an explanation-writing assistant for a network security research system.

You will be given STRUCTURED EVIDENCE as JSON. This evidence was produced entirely by
deterministic statistical/ML models and rule engines that ran BEFORE you were called.

STRICT RULES:
1. Use ONLY the supplied evidence. Do not invent facts, feature names, numbers, or contributions
   that are not present in the JSON you were given.
2. Do not invent or alter feature contributions. Every numeric value you state must come directly
   from the supplied evidence, reproduced exactly (do not round differently or recompute).
3. Do not convert an "evidence score" (0-100, MITRE stage evidence) into a probability or percentage.
   Report it as "evidence score: X/100", never as "X% likely".
4. Distinguish PREDICTION from CONFIRMATION. A model prediction or a MITRE "evidence score" is not
   proof that an attack occurred. Use language such as "consistent with", "the model predicts",
   "evidence suggests" - never "confirmed", "proven", or "occurred".
5. State uncertainty explicitly where the evidence itself states a limitation.
6. Mention important telemetry limitations included in the evidence (e.g. missing IP-address data,
   TEST-partition class limitations) when they are present in the supplied evidence.
7. Preserve numerical values exactly as given - do not round to a different precision or invent
   derived percentages.
8. Do NOT recommend mitigation, remediation, or any defensive action. That is out of scope for
   this explanation.

Write your answer with these five sections, in this order:
1. Summary
2. Why the model produced this prediction
3. Important temporal signals
4. MITRE evidence
5. Uncertainty and limitations
"""


class BaseLLMExplainer(ABC):
    """Interface every LLM provider must implement."""

    name = "base"

    @abstractmethod
    def is_configured(self) -> bool:
        ...

    @abstractmethod
    def explain(self, structured_evidence: dict) -> dict:
        """Returns {"status": ..., "text": ..., "provider": ..., "prompt": ...}."""
        ...

    def build_prompt(self, structured_evidence: dict) -> str:
        return (
            SYSTEM_INSTRUCTIONS
            + "\n\nSTRUCTURED EVIDENCE (JSON):\n"
            + json.dumps(structured_evidence, indent=2, default=str)
            + "\n\nWrite the five-section explanation now, using only the evidence above."
        )


class DisabledLLMExplainer(BaseLLMExplainer):
    """Default provider. Performs no network access. The project must remain fully
    runnable (structured explanation + evaluation) with this provider active."""

    name = "disabled"

    def is_configured(self) -> bool:
        return False

    def explain(self, structured_evidence: dict) -> dict:
        return {
            "status": "LLM_DISABLED - no provider configured (set an LLM provider/API key to enable)",
            "text": None,
            "provider": self.name,
            "prompt": self.build_prompt(structured_evidence),
        }


class OpenAICompatibleExplainer(BaseLLMExplainer):
    """
    Generic OpenAI-chat-completions-compatible provider (works with OpenAI itself or
    any self-hosted/compatible endpoint that speaks the same API shape).

    Configuration is read ONLY from environment variables - never hard-coded:
        LLM_API_KEY       - required to activate this provider
        LLM_BASE_URL      - default "https://api.openai.com/v1"
        LLM_MODEL         - default "gpt-4o-mini"

    If LLM_API_KEY is not set, is_configured() returns False and callers should fall
    back to DisabledLLMExplainer.
    """

    name = "openai_compatible"

    def __init__(self, base_url: str = None, model: str = None, api_key: str = None, timeout: float = 30.0):
        self.api_key = api_key if api_key is not None else os.environ.get("LLM_API_KEY")
        self.base_url = base_url or os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")
        self.model = model or os.environ.get("LLM_MODEL", "gpt-4o-mini")
        self.timeout = timeout

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def explain(self, structured_evidence: dict) -> dict:
        if not self.is_configured():
            return {
                "status": "LLM_DISABLED - LLM_API_KEY environment variable not set",
                "text": None, "provider": self.name, "prompt": self.build_prompt(structured_evidence),
            }
        prompt = self.build_prompt(structured_evidence)
        try:
            import urllib.request

            payload = json.dumps({
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_INSTRUCTIONS},
                    {"role": "user", "content": json.dumps(structured_evidence, default=str)},
                ],
                "temperature": 0.0,
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/chat/completions", data=payload,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
            text = body["choices"][0]["message"]["content"]
            return {"status": "LLM_OK", "text": text, "provider": self.name, "prompt": prompt}
        except Exception as e:  # network/provider errors must never crash the pipeline
            return {"status": f"LLM_ERROR - {type(e).__name__}: {e}", "text": None, "provider": self.name, "prompt": prompt}


def get_configured_explainer() -> BaseLLMExplainer:
    """Factory: returns a configured provider if the environment requests one, else the
    safe no-op default. Never raises for a missing key."""
    provider = os.environ.get("LLM_PROVIDER", "disabled").lower()
    if provider == "openai_compatible":
        explainer = OpenAICompatibleExplainer()
        return explainer if explainer.is_configured() else DisabledLLMExplainer()
    return DisabledLLMExplainer()
