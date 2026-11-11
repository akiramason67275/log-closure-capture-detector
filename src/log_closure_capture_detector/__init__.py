"""Detect log messages that embed large mutable state via closures or repr strings."""

from .core import (
    Finding,
    Detector,
    DetectorConfig,
    DEFAULT_CONFIG,
    inspect_message,
)

__all__ = [
    "Finding",
    "Detector",
    "DetectorConfig",
    "DEFAULT_CONFIG",
    "inspect_message",
]
