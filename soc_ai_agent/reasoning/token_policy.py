from dataclasses import dataclass
import json
from math import ceil

from .errors import BackendTokenBudgetExceeded


@dataclass(frozen=True)
class InputTokenEstimate:
    estimated_evidence_tokens: int
    estimated_instruction_tokens: int
    estimated_skill_tokens: int
    estimated_schema_tokens: int
    estimated_overhead_tokens: int
    estimated_total_input_tokens: int


@dataclass(frozen=True)
class TokenPolicy:
    max_input_tokens: int = 12_000

    def estimate(self, value) -> int:
        encoded = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
        # Aproximación conservadora: JSON, puntuación y nombres de schema suelen tokenizar peor que prosa.
        return max(1, ceil(len(encoded) / 3))

    def estimate_openai_input(self, payload: dict) -> InputTokenEstimate:
        """Estima todos los componentes transmitidos a Responses, sin enviar datos."""
        inputs = payload.get("input", ())
        skill_text = ""; evidence_text = ""
        for item in inputs:
            texts = "".join(part.get("text", "") for part in item.get("content", ()) if isinstance(part, dict))
            if item.get("role") == "developer": skill_text += texts
            elif item.get("role") == "user": evidence_text += texts
        schema = payload.get("text", {}).get("format", {}).get("schema", {})
        envelope = {"model": payload.get("model"), "instructions": "", "input": [
            {"role": item.get("role"), "content": [{"type": part.get("type"), "text": ""}
             for part in item.get("content", ()) if isinstance(part, dict)]} for item in inputs],
            "text": {"format": {key: ({} if key == "schema" else value)
                for key, value in payload.get("text", {}).get("format", {}).items()}},
            "max_output_tokens": payload.get("max_output_tokens"), "store": payload.get("store"),
            "truncation": payload.get("truncation")}
        if "temperature" in payload: envelope["temperature"] = payload["temperature"]
        if "reasoning" in payload: envelope["reasoning"] = payload["reasoning"]
        estimate = InputTokenEstimate(self.estimate(evidence_text), self.estimate(payload.get("instructions", "")),
            self.estimate(skill_text), self.estimate(schema), self.estimate(envelope), 0)
        return InputTokenEstimate(estimate.estimated_evidence_tokens, estimate.estimated_instruction_tokens,
            estimate.estimated_skill_tokens, estimate.estimated_schema_tokens, estimate.estimated_overhead_tokens,
            sum((estimate.estimated_evidence_tokens, estimate.estimated_instruction_tokens,
                 estimate.estimated_skill_tokens, estimate.estimated_schema_tokens, estimate.estimated_overhead_tokens)))

    def enforce_openai_input(self, payload: dict) -> InputTokenEstimate:
        estimate = self.estimate_openai_input(payload)
        if estimate.estimated_total_input_tokens > self.max_input_tokens:
            raise BackendTokenBudgetExceeded("full input token budget exceeded: "
                f"{estimate.estimated_total_input_tokens}>{self.max_input_tokens}")
        return estimate

    @staticmethod
    def estimation_error_percent(estimated: int | None, actual: int | None) -> float | None:
        if estimated is None or actual is None or estimated <= 0:
            return None
        return round(((actual - estimated) / estimated) * 100, 2)

    def enforce_input(self, evidence_json: str) -> int:
        tokens = self.estimate(evidence_json)
        if tokens > self.max_input_tokens:
            raise BackendTokenBudgetExceeded(f"input token budget exceeded: {tokens}>{self.max_input_tokens}")
        return tokens

    def enforce_output(self, response, maximum: int) -> int:
        reported = response.backend_metadata.output_token_count if response.backend_metadata else None
        tokens = reported if reported is not None else self.estimate(response)
        if tokens > maximum:
            raise BackendTokenBudgetExceeded(f"output token budget exceeded: {tokens}>{maximum}")
        return tokens
