"""Prompt template loading module."""

from __future__ import annotations

import glob
import os
from typing import Any, Dict

import yaml

_PROMPT_CACHE: Dict[str, Dict[str, Any]] = {}


def get_prompts(prompt_file: str | None = None) -> Dict[str, Any]:
    """Load and return prompt templates from YAML files in the prompts directory.

    Args:
        prompt_file: Optional specific prompt file name (without .yaml extension).
            If provided, loads only that file. If None, loads all YAML files.

    Returns:
        Dictionary containing the loaded prompt templates.
    """
    cache_key = prompt_file or "__all__"
    if cache_key in _PROMPT_CACHE:
        return dict(_PROMPT_CACHE[cache_key])

    prompts: Dict[str, Any] = {}

    # Get the directory where this file is located
    current_dir = os.path.dirname(__file__)

    # If a specific prompt file is requested, load only that file
    if prompt_file:
        # Add .yaml extension if not present
        if not prompt_file.endswith(".yaml"):
            prompt_file = f"{prompt_file}.yaml"

        yaml_file_path = os.path.join(current_dir, prompt_file)

        try:
            with open(yaml_file_path, "r", encoding="utf-8") as f:
                file_content = yaml.safe_load(f)
                if file_content:
                    prompts.update(file_content)
        except (yaml.YAMLError, IOError) as e:
            print(f"Warning: Failed to load {yaml_file_path}: {e}")

        _PROMPT_CACHE[cache_key] = dict(prompts)
        return dict(prompts)

    # Otherwise, load all YAML files in the prompts directory
    yaml_pattern = os.path.join(current_dir, "*.yaml")
    yaml_files = glob.glob(yaml_pattern)

    for yaml_file in yaml_files:
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                file_content = yaml.safe_load(f)
                if file_content:
                    prompts.update(file_content)
        except (yaml.YAMLError, IOError) as e:
            # Continue loading other files even if one fails
            print(f"Warning: Failed to load {yaml_file}: {e}")

    _PROMPT_CACHE[cache_key] = dict(prompts)
    return dict(prompts)


def format_prompt(prompt_key: str, *, prompt_file: str | None = None, **kwargs: Any) -> str:
    """Load a prompt template by key and format it with provided values."""
    prompts = get_prompts(prompt_file=prompt_file)
    if prompt_key not in prompts:
        available = ", ".join(sorted(prompts.keys()))
        raise KeyError(f"Prompt '{prompt_key}' not found. Available keys: {available}")

    template = prompts[prompt_key]
    if not isinstance(template, str):
        raise TypeError(f"Prompt '{prompt_key}' must be a string, got {type(template)}")

    return template.format(**kwargs)
