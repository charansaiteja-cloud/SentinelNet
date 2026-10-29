"""Validated runtime configuration for SentinelNet."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings loaded from ``SENTINEL_*`` environment variables or a ``.env`` file."""

    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        extra="ignore",
    )

    interface: str | None = None
    pcap: Path | None = None
    bpf: str | None = None
    baseline_packets: int = Field(default=200, ge=10, le=100_000)
    contamination: float = Field(default=0.02, gt=0.0, lt=0.5)
    cooldown_seconds: float = Field(default=10.0, ge=0.0, le=3600.0)
    alert_log: Path | None = None
    model_path: Path | None = None
    seed: int = Field(default=42, ge=0)
    log_level: str = "INFO"
    json_logs: bool = False

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        normalised = value.upper()
        if normalised not in allowed:
            raise ValueError(f"log level must be one of {sorted(allowed)}")
        return normalised

    @field_validator("bpf")
    @classmethod
    def validate_bpf(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("BPF filter must not be empty")
        return cleaned

    @model_validator(mode="after")
    def validate_source(self) -> Settings:
        if self.interface and self.pcap:
            raise ValueError("choose either an interface or a pcap file, not both")
        return self

    @property
    def source(self) -> str:
        """Human-readable capture source."""
        if self.pcap is not None:
            return f"pcap:{self.pcap}"
        if self.interface:
            return f"iface:{self.interface}"
        return "unconfigured"
