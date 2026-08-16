"""Detector modules.

Each detector exposes ``check(apk, dex_list, dx=None) -> dict`` so the pipeline can
call them all uniformly. The dict always carries a ``found`` bool and a ``notes``
string, plus check-specific detail keys.

Importing this package does NOT import the detectors themselves — they pull in
androguard, which is an optional extra. Use :func:`load_detector` instead.
"""

from importlib import import_module

# config.yaml keys -> module name inside this package
DETECTOR_MODULES = {
    "rq1_2": "ssl_tls_misuse",
    "rq4": "internet_pii_permissions",
    "rq5": "unused_permissions",
    "rq7": "exported_components",
}


def load_detector(key: str):
    """Return the ``check`` callable for a detector key (e.g. ``"rq4"``)."""
    try:
        module_name = DETECTOR_MODULES[key]
    except KeyError:
        known = ", ".join(sorted(DETECTOR_MODULES))
        raise KeyError(f"Unknown detector {key!r}. Known detectors: {known}") from None

    try:
        module = import_module(f"{__name__}.{module_name}")
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.split(".")[0] == "androguard":
            raise ModuleNotFoundError(
                f"Detector {key!r} needs androguard, which is an optional extra.\n"
                "Install it with:  pip install -e '.[scan]'"
            ) from exc
        raise

    return module.check
