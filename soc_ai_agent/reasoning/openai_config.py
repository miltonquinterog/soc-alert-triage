"""Configuración explícita; no incluye valores de modelo ni secretos por defecto."""

from dataclasses import dataclass
import os

from .errors import BackendSchemaViolation, BackendUnavailable


@dataclass(frozen=True)
class OpenAIModelCapabilities:
    supports_temperature: bool = False
    supports_reasoning_effort: bool = False


@dataclass(frozen=True)
class OpenAIConfig:
    api_key: str
    model: str
    timeout_seconds: float = 20.0
    max_output_tokens: int = 1_200
    temperature: float | None = None
    reasoning_effort: str | None = None
    capabilities: OpenAIModelCapabilities = OpenAIModelCapabilities()

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        api_key, model = env.get("OPENAI_API_KEY"), env.get("SOC_OPENAI_MODEL")
        if not api_key: raise BackendUnavailable("OPENAI_API_KEY is not configured")
        if not model: raise BackendUnavailable("SOC_OPENAI_MODEL is not configured")
        temperature = float(env["SOC_OPENAI_TEMPERATURE"]) if env.get("SOC_OPENAI_TEMPERATURE") else None
        reasoning_effort = env.get("SOC_OPENAI_REASONING_EFFORT")
        caps = OpenAIModelCapabilities(env.get("SOC_OPENAI_SUPPORTS_TEMPERATURE", "false").lower() == "true",
            env.get("SOC_OPENAI_SUPPORTS_REASONING_EFFORT", "false").lower() == "true")
        if temperature is not None and not caps.supports_temperature:
            raise BackendSchemaViolation("temperature configured without declared model capability")
        if reasoning_effort and not caps.supports_reasoning_effort:
            raise BackendSchemaViolation("reasoning effort configured without declared model capability")
        return cls(api_key, model, float(env.get("SOC_OPENAI_TIMEOUT_SECONDS", "20")),
            int(env.get("SOC_OPENAI_MAX_OUTPUT_TOKENS", "1200")), temperature, reasoning_effort, caps)
