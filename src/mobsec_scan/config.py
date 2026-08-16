"""Configuration loading.

Two sources, kept deliberately separate:

* ``config.yaml`` — non-secret settings that belong in version control
  (which detectors run, where things get written, the triage prompt).
* ``.env`` — secrets that must never be committed (``GEMINI_API_KEY``).

Paths in the YAML are relative to the project root — the directory containing
``config.yaml`` — and are resolved to absolute paths at load time so that
commands behave the same regardless of the working directory they run from.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

DEFAULT_CONFIG_NAME = "config.yaml"


def find_project_root(start: Path | None = None) -> Path:
    """Walk upward from ``start`` looking for the directory holding config.yaml.

    Falls back to the installed package's grandparent so an editable install
    still works when invoked from an unrelated directory.
    """
    start = (start or Path.cwd()).resolve()
    for candidate in [start, *start.parents]:
        if (candidate / DEFAULT_CONFIG_NAME).is_file():
            return candidate
    return Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Detector:
    """One configured check."""

    key: str
    label: str
    enabled: bool


@dataclass(frozen=True)
class Config:
    root: Path
    apks_dir: Path
    results_dir: Path
    database: Path
    analysis_dir: Path
    detectors: dict[str, Detector]
    triage: dict = field(default_factory=dict)
    log_level: str = "INFO"

    @property
    def active_detectors(self) -> dict[str, Detector]:
        """Enabled checks only, in config-file order.

        This is the single source of truth that report formatting, CSV columns
        and the flagged summary all key off — the role ACTIVE_RQS used to play.
        """
        return {k: d for k, d in self.detectors.items() if d.enabled}

    @property
    def gemini_api_key(self) -> str | None:
        return os.environ.get("GEMINI_API_KEY")


def load_config(config_path: Path | None = None) -> Config:
    """Load ``config.yaml`` (plus ``.env``) into a :class:`Config`."""
    if config_path is not None:
        config_path = Path(config_path).resolve()
        root = config_path.parent
    else:
        root = find_project_root()
        config_path = root / DEFAULT_CONFIG_NAME

    if not config_path.is_file():
        raise FileNotFoundError(
            f"No {DEFAULT_CONFIG_NAME} found at {config_path}. "
            "Run mobsec from the project root, or pass --config."
        )

    load_dotenv(root / ".env")

    with config_path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    paths = raw.get("paths", {})

    def _resolve(key: str, default: str) -> Path:
        value = Path(paths.get(key, default))
        return value if value.is_absolute() else (root / value)

    detectors: dict[str, Detector] = {}
    for key, spec in (raw.get("detectors") or {}).items():
        spec = spec or {}
        detectors[key] = Detector(
            key=key,
            label=spec.get("label", key.upper()),
            enabled=bool(spec.get("enabled", False)),
        )

    return Config(
        root=root,
        apks_dir=_resolve("apks_dir", "apks"),
        results_dir=_resolve("results_dir", "results"),
        database=_resolve("database", "sql_practice/compliance_findings.db"),
        analysis_dir=_resolve("analysis_dir", "results/analysis"),
        detectors=detectors,
        triage=raw.get("triage") or {},
        log_level=(raw.get("logging") or {}).get("level", "INFO"),
    )
