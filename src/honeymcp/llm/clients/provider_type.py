"""LLM provider type enumeration module."""

from enum import Enum


class LLMProviderType(Enum):
    """Enumeration of supported LLM provider types."""

    WATSONX = "watsonx"
    OPENAI = "openai"
    RITS = "rits"
