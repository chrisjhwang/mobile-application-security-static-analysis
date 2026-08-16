"""``mobsec`` command-line interface.

One entry point for the whole workflow:

    mobsec scan <apk>       run every enabled detector against one APK
    mobsec batch            resumable batch run over the APK corpus
    mobsec build-db         parse results/*.txt into SQLite
    mobsec triage           AI-assisted true/false-positive triage
    mobsec analyze          statistics, charts and a markdown summary
    mobsec dashboard        launch the interactive Streamlit dashboard

Subcommands are added phase by phase; the ones not yet implemented exit with a
clear message rather than a traceback.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from . import __version__
from .config import Config, load_config
from .logging_config import setup_logging

app = typer.Typer(
    name="mobsec",
    help="Static analysis, AI triage and reporting for Android APK security findings.",
    no_args_is_help=True,
    add_completion=False,
)

# Populated by the root callback so every subcommand shares one loaded config.
_state: dict[str, object] = {}


def get_config() -> Config:
    config = _state.get("config")
    if config is None:  # pragma: no cover - only when a command is called directly
        config = load_config()
        _state["config"] = config
    return config  # type: ignore[return-value]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mobsec {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to config.yaml (default: found by walking up from cwd)."
    ),
    log_level: Optional[str] = typer.Option(
        None, "--log-level", help="DEBUG, INFO, WARNING or ERROR. Overrides config.yaml."
    ),
    log_file: Optional[Path] = typer.Option(
        None, "--log-file", help="Also write a full-detail log to this file."
    ),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Load configuration and set up logging for whichever subcommand runs."""
    cfg = load_config(config)
    _state["config"] = cfg
    setup_logging(log_level or cfg.log_level, log_file)


@app.command("show-config")
def show_config() -> None:
    """Print the resolved configuration — useful for checking what will run."""
    cfg = get_config()
    typer.echo(f"Project root : {cfg.root}")
    typer.echo(f"APKs dir     : {cfg.apks_dir}")
    typer.echo(f"Results dir  : {cfg.results_dir}")
    typer.echo(f"Database     : {cfg.database}")
    typer.echo(f"Analysis dir : {cfg.analysis_dir}")
    typer.echo(f"Log level    : {cfg.log_level}")
    typer.echo("")
    typer.echo("Detectors:")
    for det in cfg.detectors.values():
        mark = "on " if det.enabled else "off"
        typer.echo(f"  [{mark}] {det.key:<6} {det.label}")
    typer.echo("")
    key_state = "set" if cfg.gemini_api_key else "not set (triage will fail)"
    typer.echo(f"GEMINI_API_KEY: {key_state}")


def _not_yet(phase: str) -> None:
    typer.secho(
        f"Not implemented yet — arrives in {phase} of the build plan.",
        fg=typer.colors.YELLOW,
        err=True,
    )
    raise typer.Exit(code=1)


@app.command()
def scan(
    apk: Path = typer.Argument(..., exists=True, help="Path to a single .apk file."),
) -> None:
    """Run every enabled detector against one APK and print a unified report."""
    _not_yet("Phase 2")


@app.command()
def batch(
    apks_dir: Optional[Path] = typer.Option(None, "--apks-dir", help="Override configured APK dir."),
    limit: Optional[int] = typer.Option(None, "--limit", help="Only process the first N APKs."),
) -> None:
    """Resumable batch run: per-app reports, summary.csv and flagged.txt."""
    _not_yet("Phase 2")


@app.command("build-db")
def build_db() -> None:
    """Parse the plaintext reports in results/ into the SQLite database."""
    _not_yet("Phase 3")


@app.command()
def triage(
    limit: Optional[int] = typer.Option(None, "--limit", help="Only triage N findings."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show prompts without calling the API."),
) -> None:
    """Send un-triaged findings to Gemini and record TP/FP verdicts."""
    _not_yet("Phase 4")


@app.command()
def analyze() -> None:
    """Compute statistics, render charts and write ANALYSIS.md."""
    _not_yet("Phase 5")


@app.command()
def dashboard() -> None:
    """Launch the interactive Streamlit dashboard."""
    _not_yet("Phase 6")


if __name__ == "__main__":  # pragma: no cover
    app()
