"""
Feature L3.2 - Sandbox/Lab Traffic Capture: bounded capture configuration.

Pure configuration + validation. No capture, no networking, no
subprocess invocation happens in this module.
"""

from dataclasses import dataclass
from pathlib import Path


class CaptureConfigError(ValueError):
    """Raised when a CaptureConfig is invalid - never silently corrected."""


@dataclass(frozen=True)
class CaptureConfig:
    interface: str
    output_path: Path
    max_duration_s: float | None = None
    max_packets: int | None = None
    max_file_size_bytes: int | None = None
    mechanism: str = "tcpdump"  # only mechanism this feature implements - see capture_adapter.py

    def __post_init__(self):
        if not self.interface or not isinstance(self.interface, str):
            raise CaptureConfigError("interface must be a non-empty string.")
        if self.max_duration_s is None and self.max_packets is None and self.max_file_size_bytes is None:
            raise CaptureConfigError(
                "At least one bound (max_duration_s, max_packets, or max_file_size_bytes) is required - "
                "an unbounded capture is never permitted by this contract."
            )
        if self.max_duration_s is not None and self.max_duration_s <= 0:
            raise CaptureConfigError(f"max_duration_s must be positive, got {self.max_duration_s}.")
        if self.max_packets is not None and self.max_packets <= 0:
            raise CaptureConfigError(f"max_packets must be positive, got {self.max_packets}.")
        if self.max_file_size_bytes is not None and self.max_file_size_bytes <= 0:
            raise CaptureConfigError(f"max_file_size_bytes must be positive, got {self.max_file_size_bytes}.")
        if self.mechanism != "tcpdump":
            raise CaptureConfigError(f"Only the 'tcpdump' mechanism is implemented by this feature, got '{self.mechanism}'.")
        if Path(self.output_path).exists():
            raise CaptureConfigError(
                f"output_path {self.output_path} already exists - this adapter never overwrites an existing "
                "file (could silently destroy prior capture evidence). Choose a new path."
            )
