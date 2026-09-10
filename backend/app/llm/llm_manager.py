"""Ollama-backed LLM manager for the FIA backend.

This module is responsible only for communicating with the Ollama service.
It does not perform retrieval, prompt construction, or response parsing.
"""

from __future__ import annotations

from typing import Any, Callable

import httpx
from ollama import Client
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.config import ENV_FILE
from app.core.logging import get_logger

logger = get_logger(__name__)


class LLMSettings(BaseSettings):
    """Configuration values for the Ollama LLM manager."""

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
        validate_assignment=True,
        case_sensitive=False,
    )

    ollama_host: str = Field(default="http://localhost:11434")

    llm_model: str = Field(default="llama3")

    llm_temperature: float = Field(default=0.0)

    llm_context_window: int = Field(default=4096)

    llm_timeout: float = Field(default=60.0)


class LLMManager:
    """Manage communication with an Ollama-hosted language model."""

    def __init__(self, settings: LLMSettings | None = None) -> None:
        """Initialize the manager with configuration and an Ollama client.

        Args:
            settings: Optional settings override. When omitted, environment
                variables are used.
        """

        self._settings = settings or LLMSettings()
        self._client = Client(
            host=self._settings.ollama_host,
            timeout=self._settings.llm_timeout,
        )
        self._model_name = self._settings.llm_model

        logger.info(
            "LLM manager initialized.",
            extra={
                "model": self._model_name,
                "host": self._settings.ollama_host,
                "timeout": self._settings.llm_timeout,
            },
        )

    @property
    def client(self) -> Client:
        """Return the configured Ollama client."""

        return self._client

    @property
    def model_name(self) -> str:
        """Return the configured model name."""

        return self._model_name

    def verify_model(self) -> None:
        """Verify that the configured Ollama model exists."""

        try:
            response = self.client.list()
        except Exception as exc:
            raise RuntimeError(
                f"Unable to connect to Ollama at '{self._settings.ollama_host}'."
            ) from exc

        available_models = {
            model.model
            for model in response.models
        }

        if self._model_name not in available_models:
            raise RuntimeError(
                f"Model '{self._model_name}' is not installed in Ollama."
            )

        logger.info(
            "Verified Ollama model: %s",
            self._model_name,
        )

    def _generate_streaming(
        self,
        messages: list[dict[str, str]],
        options: dict[str, Any],
        on_token: Callable[[str], None],
    ) -> str:
        """Stream a completion, forwarding chunks and returning the whole.

        The accumulated text is what the caller receives, so a streamed
        answer is indistinguishable downstream from a non-streamed one. A
        failing ``on_token`` callback must not lose the generation already
        paid for, so its errors are logged and swallowed: the client may miss
        a chunk, but the complete text still returns and is still parsed,
        calibrated and enforced against.
        """

        chunks: list[str] = []

        for part in self.client.chat(
            model=self._model_name,
            messages=messages,
            stream=True,
            options=options,
        ):

            piece = ""

            if isinstance(part, dict):
                message = part.get("message") or {}
                if isinstance(message, dict):
                    piece = message.get("content") or ""
            else:
                message = getattr(part, "message", None)
                if message is not None:
                    piece = getattr(message, "content", "") or ""

            if not piece:
                continue

            chunks.append(piece)

            try:
                on_token(piece)
            except Exception as exc:
                logger.warning(
                    "Streaming consumer raised on a chunk; continuing "
                    "accumulation: %s",
                    exc,
                )

        content = "".join(chunks)

        logger.info(
            "Completed streamed LLM inference (%d chunks, %d chars).",
            len(chunks),
            len(content),
        )

        return content

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        on_token: Callable[[str], None] | None = None,
    ) -> str:
        """Generate text from the configured Ollama model.

        Args:
            prompt: The user prompt to send to the model.
            system_prompt: Optional system prompt to include in the request.
            temperature: Optional override for the configured temperature.
            on_token: Optional callback invoked with each chunk as it
                arrives. Supplying it switches the request to Ollama's
                streaming API.

        Returns:
            The complete generated text, whether or not it was streamed.
            This contract is deliberate: every downstream safety mechanism
            (citation parsing, confidence calibration, signature
            corroboration, malfind qualification) runs on the finished text,
            so streaming must change only how the text arrives, never what
            the caller receives.

        Raises:
            RuntimeError: If the model is unavailable or the request fails.
        """

        effective_temperature = (
            temperature
            if temperature is not None
            else self._settings.llm_temperature
        )

        logger.info(
            "Starting LLM inference.",
            extra={
                "model": self._model_name,
                "temperature": effective_temperature,
            },
        )

        try:
            self.verify_model()
        except RuntimeError:
            raise

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        options = {
            "temperature": effective_temperature,
            "num_ctx": self._settings.llm_context_window,
        }

        try:
            if on_token is not None:
                return self._generate_streaming(
                    messages, options, on_token
                )

            response = self.client.chat(
                model=self._model_name,
                messages=messages,
                stream=False,
                options=options,
            )
        except (TimeoutError, httpx.TimeoutException) as exc:
            # Distinguished from a connection failure on purpose: a read
            # timeout means Ollama was reachable and still generating, which
            # points at LLM_TIMEOUT being too low for the answer length
            # rather than at anything being unreachable.
            raise RuntimeError(
                f"Ollama did not finish generating within "
                f"{self._settings.llm_timeout:.0f}s "
                f"(LLM_TIMEOUT). The model is reachable but the answer took "
                f"longer than the configured limit."
            ) from exc
        except (ConnectionError, httpx.ConnectError) as exc:
            raise RuntimeError(
                f"Failed to connect to Ollama host '{self._settings.ollama_host}'."
            ) from exc
        except Exception as exc:
            if "model" in str(exc).lower():
                raise RuntimeError(
                    f"Ollama model '{self._model_name}' is not available at '{self._settings.ollama_host}'."
                ) from exc
            raise RuntimeError("Ollama generation failed.") from exc

        content = ""
        if isinstance(response, dict):
            message = response.get("message", {})
            if isinstance(message, dict):
                content = message.get("content", "")
        elif hasattr(response, "message"):
            message = getattr(response, "message")
            if hasattr(message, "content"):
                content = str(message.content)

        if not isinstance(content, str):
            content = str(content)

        logger.info(
            "Completed LLM inference.",
            extra={
                "model": self._model_name,
                "response_length": len(content),
            },
        )

        return content


__all__ = ["LLMManager", "LLMSettings"]
