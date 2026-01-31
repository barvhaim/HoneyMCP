"""Configuration models for HoneyMCP."""

import os
from pathlib import Path
from typing import List, Optional, Union

import yaml
from pydantic import BaseModel, Field

from honeymcp.models.protection_mode import ProtectionMode

EVENT_STORAGE_ENV_VAR = "HONEYMCP_EVENT_PATH"


def _env_event_storage_path() -> Optional[Path]:
    env_value = os.getenv(EVENT_STORAGE_ENV_VAR)
    if not env_value:
        return None
    return Path(os.path.expanduser(env_value))


def resolve_event_storage_path(explicit_path: Optional[Path] = None) -> Path:
    """Resolve event storage path, honoring env override when no explicit path is set."""
    if explicit_path is not None:
        return explicit_path
    env_path = _env_event_storage_path()
    if env_path is not None:
        return env_path
    return Path.home() / ".honeymcp" / "events"


class HoneyMCPConfig(BaseModel):
    """Configuration for HoneyMCP middleware."""

    ghost_tools: List[str] = Field(
        default=["list_cloud_secrets", "execute_shell_command"],
        description="List of static ghost tools to inject",
    )

    protection_mode: ProtectionMode = Field(
        default=ProtectionMode.SCANNER,
        description="Protection mode: SCANNER (lockout) or COGNITIVE (deception)",
    )

    event_storage_path: Path = Field(
        default_factory=resolve_event_storage_path,
        description="Directory for storing attack event JSON files",
    )

    enable_dashboard: bool = Field(default=True, description="Enable Streamlit dashboard")

    webhook_url: Optional[str] = Field(default=None, description="Webhook URL for attack alerts")

    # Dynamic ghost tool configuration
    use_dynamic_tools: bool = Field(
        default=True,
        description="Enable LLM-based dynamic ghost tool generation",
    )

    num_dynamic_tools: int = Field(
        default=3,
        description="Number of dynamic ghost tools to generate",
        ge=1,
        le=10,
    )

    llm_model: Optional[str] = Field(
        default=None,
        description="Override default LLM model for ghost tool generation",
    )

    cache_ttl: int = Field(
        default=3600,
        description="Cache time-to-live in seconds for generated tools",
        ge=0,
    )

    fallback_to_static: bool = Field(
        default=True,
        description="Use static ghost tools if dynamic generation fails",
    )

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "HoneyMCPConfig":
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML configuration file

        Returns:
            HoneyMCPConfig instance

        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If YAML is invalid
        """
        path = Path(path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        return cls._from_yaml_dict(data)

    @classmethod
    def _from_yaml_dict(cls, data: dict) -> "HoneyMCPConfig":
        """Convert YAML dictionary to config object."""
        # Map YAML structure to flat config
        config_dict = {}

        # Protection mode
        if "protection_mode" in data:
            mode_str = data["protection_mode"].upper()
            config_dict["protection_mode"] = ProtectionMode(mode_str.lower())

        # Ghost tools
        if "ghost_tools" in data:
            config_dict["ghost_tools"] = data["ghost_tools"]

        # Dynamic tools section
        dynamic = data.get("dynamic_tools", {})
        if "enabled" in dynamic:
            config_dict["use_dynamic_tools"] = dynamic["enabled"]
        if "num_tools" in dynamic:
            config_dict["num_dynamic_tools"] = dynamic["num_tools"]
        if "fallback_to_static" in dynamic:
            config_dict["fallback_to_static"] = dynamic["fallback_to_static"]
        if "cache_ttl" in dynamic:
            config_dict["cache_ttl"] = dynamic["cache_ttl"]
        if "llm_model" in dynamic and dynamic["llm_model"]:
            config_dict["llm_model"] = dynamic["llm_model"]

        # Alerting section
        alerting = data.get("alerting", {})
        if "webhook_url" in alerting and alerting["webhook_url"]:
            config_dict["webhook_url"] = alerting["webhook_url"]

        # Storage section
        storage = data.get("storage", {})
        if "event_path" in storage:
            path_str = storage["event_path"]
            # Expand ~ to home directory
            config_dict["event_storage_path"] = Path(os.path.expanduser(path_str))

        # Dashboard section
        dashboard = data.get("dashboard", {})
        if "enabled" in dashboard:
            config_dict["enable_dashboard"] = dashboard["enabled"]

        return cls(**config_dict)

    @classmethod
    def load(cls, path: Optional[Union[str, Path]] = None) -> "HoneyMCPConfig":
        """Load configuration from file or use defaults.

        Searches for config in order:
        1. Explicit path if provided
        2. ./honeymcp.yaml
        3. ~/.honeymcp/honeymcp.yaml
        4. Default configuration

        Args:
            path: Optional explicit path to config file

        Returns:
            HoneyMCPConfig instance
        """
        search_paths = []

        if path:
            search_paths.append(Path(path))
        else:
            search_paths.extend(
                [
                    Path("honeymcp.yaml"),
                    Path.home() / ".honeymcp" / "honeymcp.yaml",
                ]
            )

        for config_path in search_paths:
            config_path = config_path.expanduser()
            if config_path.exists():
                return cls.from_yaml(config_path)

        # Return default config
        return cls()
