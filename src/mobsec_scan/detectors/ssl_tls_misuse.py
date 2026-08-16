#!/usr/bin/env python3
# encoding: utf-8

from androguard.misc import AnalyzeAPK
from androguard.decompiler.decompile import DvClass

import argparse
import base64
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path


TRUST_MANAGER_SIGNATURES = [
    {
        "access_flags": "public",
        "return": "void",
        "name": "checkServerTrusted",
        "params": [
            "java.security.cert.X509Certificate[]",
            "java.lang.String",
        ],
    },
]

HOSTNAME_VERIFIER_SIGNATURES = [
    {
        "access_flags": "public",
        "return": "boolean",
        "name": "verify",
        "params": ["java.lang.String", "javax.net.ssl.SSLSession"],
    },
    {
        "access_flags": "public",
        "return": "void",
        "name": "verify",
        "params": [
            "java.lang.String",
            "java.security.cert.X509Certificate",
        ],
    },
    {
        "access_flags": "public",
        "return": "void",
        "name": "verify",
        "params": ["java.lang.String", "javax.net.ssl.SSLSocket"],
    },
    {
        "access_flags": "public",
        "return": "void",
        "name": "verify",
        "params": [
            "java.lang.String",
            "java.lang.String[]",
            "java.lang.String[]",
        ],
    },
]

TRUST_MANAGER_INTERFACES = [
    "Ljavax/net/ssl/TrustManager;",
    "Ljavax/net/ssl/X509TrustManager;",
]

HOSTNAME_VERIFIER_INTERFACES = [
    "Ljavax/net/ssl/HostnameVerifier;",
    "Lorg/apache/http/conn/ssl/X509HostnameVerifier;",
]

HOSTNAME_VERIFIER_SUPERCLASSES = [
    "Lorg/apache/http/conn/ssl/AbstractVerifier;",
    "Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;",
    "Lorg/apache/http/conn/ssl/BrowserCompatHostnameVerifier;",
    "Lorg/apache/http/conn/ssl/StrictHostnameVerifier;",
]

TRUST_MANAGER_RUNTIME_SINKS = [
    {
        "class_name": "Ljavax/net/ssl/SSLContext;",
        "method_name": "init",
        "descriptors": {
            "([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V",
        },
        "reason": "Method also calls SSLContext.init(..., TrustManager[], ...).",
    },
    {
        "class_name": "Ljavax/net/ssl/HttpsURLConnection;",
        "method_name": "setSSLSocketFactory",
        "descriptors": {
            "(Ljavax/net/ssl/SSLSocketFactory;)V",
        },
        "reason": "Method also calls HttpsURLConnection.setSSLSocketFactory(...).",
    },
    {
        "class_name": "Lokhttp3/OkHttpClient$Builder;",
        "method_name": "sslSocketFactory",
        "descriptor_contains": [
            "Ljavax/net/ssl/SSLSocketFactory;",
        ],
        "reason": "Method also configures an OkHttp SSLSocketFactory.",
    },
    {
        "class_name": "Lcom/squareup/okhttp/OkHttpClient;",
        "method_name": "setSslSocketFactory",
        "descriptor_contains": [
            "Ljavax/net/ssl/SSLSocketFactory;",
        ],
        "reason": "Method also configures an OkHttp SSLSocketFactory.",
    },
]

HOSTNAME_VERIFIER_RUNTIME_SINKS = [
    {
        "class_name": "Ljavax/net/ssl/HttpsURLConnection;",
        "method_name": "setHostnameVerifier",
        "descriptors": {
            "(Ljavax/net/ssl/HostnameVerifier;)V",
        },
        "reason": "Method also calls HttpsURLConnection.setHostnameVerifier(...).",
    },
    {
        "class_name": "Ljavax/net/ssl/HttpsURLConnection;",
        "method_name": "setDefaultHostnameVerifier",
        "descriptors": {
            "(Ljavax/net/ssl/HostnameVerifier;)V",
        },
        "reason": "Method also calls HttpsURLConnection.setDefaultHostnameVerifier(...).",
    },
    {
        "class_name": "Lokhttp3/OkHttpClient$Builder;",
        "method_name": "hostnameVerifier",
        "descriptor_contains": [
            "Ljavax/net/ssl/HostnameVerifier;",
        ],
        "reason": "Method also configures an OkHttp HostnameVerifier.",
    },
    {
        "class_name": "Lcom/squareup/okhttp/OkHttpClient;",
        "method_name": "setHostnameVerifier",
        "descriptor_contains": [
            "Ljavax/net/ssl/HostnameVerifier;",
        ],
        "reason": "Method also configures an OkHttp HostnameVerifier.",
    },
    {
        "class_name": "Lorg/apache/http/conn/ssl/SSLSocketFactory;",
        "method_name": "setHostnameVerifier",
        "descriptor_contains": [
            "Lorg/apache/http/conn/ssl/X509HostnameVerifier;",
        ],
        "reason": "Method also calls Apache SSLSocketFactory.setHostnameVerifier(...).",
    },
    {
        "class_name": "Lorg/apache/http/conn/ssl/SSLSocketFactory;",
        "method_name": "<init>",
        "descriptor_contains": [
            "Lorg/apache/http/conn/ssl/X509HostnameVerifier;",
        ],
        "reason": "Method also constructs an Apache SSLSocketFactory with a custom verifier.",
    },
]

REPORT_LINE = "=" * 80
SECTION_LINE = "-" * 80
SOURCE_LINE = "`" * 3


def _get_java_code(_class_analysis, _vmx):
    try:
        _decompiler = DvClass(_class_analysis.get_vm_class(), _vmx)
        _decompiler.process()
        return _decompiler.get_source()
    except Exception:
        print(
            "Error getting Java source code for: {:s}".format(
                _class_analysis.name
            )
        )
        return None


def _get_method_key(_method):
    return (
        _method.get_class_name(),
        _method.get_name(),
        _method.get_descriptor(),
    )


def _translate_class_name(_class_name):
    _class_name = _class_name[1:-1]
    return _class_name.replace("/", ".")


def _translate_method_name(_method):
    return "{:s}->{:s}{:s}".format(
        _translate_class_name(_method.get_class_name()),
        _method.get_name(),
        _method.get_descriptor(),
    )


def _has_required_access_flags(_method, _required_flags):
    _flags = set(_method.get_access_flags_string().split())
    _required = set(_required_flags.split())
    return _required.issubset(_flags)


def _has_signature(_method, _signatures):
    _name = _method.get_name()
    _method_info = _method.get_information()
    _return = _method_info.get("return")
    _params = [_param[1] for _param in _method_info.get("params", [])]

    for _signature in _signatures:
        if (
            _has_required_access_flags(_method, _signature["access_flags"])
            and _name == _signature["name"]
            and _return == _signature["return"]
            and _params == _signature["params"]
        ):
            return True
    return False


def _class_implements_interface(_class_analysis, _interfaces):
    _class = _class_analysis.get_vm_class()
    _class_interfaces = _class.get_interfaces() or []
    return any(_interface in _class_interfaces for _interface in _interfaces)


def _class_extends_class(_class_analysis, _classes):
    return _class_analysis.get_vm_class().get_superclassname() in _classes


def _get_method_instructions(_method):
    _code = _method.get_code()
    _instructions = []
    if _code:
        _bc = _code.get_bc()
        for _instr in _bc.get_instructions():
            _instructions.append(_instr)
    return _instructions


def _returns_true(_method):
    _instructions = _get_method_instructions(_method)
    if len(_instructions) == 2:
        _combined = "->".join(
            [
                _instructions[0].get_output(),
                _instructions[1].get_name()
                + ","
                + _instructions[1].get_output(),
            ]
        )
        _combined = _combined.replace(" ", "")
        _register = _instructions[0].get_output().split(",")[0]
        _expected = "{:s},1->return,{:s}".format(_register, _register)
        return _combined == _expected
    return False


def _returns_void(_method):
    _instructions = _get_method_instructions(_method)
    return len(_instructions) == 1 and _instructions[0].get_name() == "return-void"


def _get_flattened_xref_methods(_class_analysis):
    _methods = {}

    for _method_analysis, _offset in _class_analysis.get_xref_new_instance():
        _key = _get_method_key(_method_analysis.get_method())
        _entry = _methods.setdefault(
            _key,
            {"method_analysis": _method_analysis, "origins": set()},
        )
        _entry["origins"].add("new-instance")

    for _caller_class, _refs in _class_analysis.get_xref_from().items():
        if isinstance(_refs, tuple):
            _refs = [_refs]
        for _ref in _refs:
            if len(_ref) != 3:
                continue
            _ref_kind, _method_analysis, _offset = _ref
            _key = _get_method_key(_method_analysis.get_method())
            _entry = _methods.setdefault(
                _key,
                {"method_analysis": _method_analysis, "origins": set()},
            )
            _entry["origins"].add(str(_ref_kind))

    return list(_methods.values())


def _get_javab64_xref(_class_analysis, _vmx):
    _source = _get_java_code(_class_analysis, _vmx)
    _java_b64 = base64.b64encode(_source.encode()) if _source else None
    _xref = []

    for _entry in _get_flattened_xref_methods(_class_analysis):
        _xref.append(_entry["method_analysis"].get_method())

    return _java_b64, _xref


def _matches_runtime_sink(_method, _sink):
    if _method.get_class_name() != _sink["class_name"]:
        return False
    if _method.get_name() != _sink["method_name"]:
        return False

    _descriptor = _method.get_descriptor()

    if "descriptors" in _sink and _descriptor in _sink["descriptors"]:
        return True

    if "descriptor_contains" in _sink:
        return all(_piece in _descriptor for _piece in _sink["descriptor_contains"])

    return False


def _collect_runtime_uses(_class_analysis, _runtime_sinks):
    _runtime_uses = []
    _seen = set()

    for _entry in _get_flattened_xref_methods(_class_analysis):
        _method_analysis = _entry["method_analysis"]
        _caller_method = _method_analysis.get_method()

        for _called_class, _called_method_analysis, _offset in _method_analysis.get_xref_to():
            _called_method = _called_method_analysis.get_method()
            for _sink in _runtime_sinks:
                if not _matches_runtime_sink(_called_method, _sink):
                    continue

                _key = (
                    _get_method_key(_caller_method),
                    _get_method_key(_called_method),
                    _offset,
                )
                if _key in _seen:
                    continue
                _seen.add(_key)

                _runtime_uses.append(
                    {
                        "caller": _caller_method,
                        "callee": _called_method,
                        "offset": _offset,
                        "origins": sorted(_entry["origins"]),
                        "reason": _sink["reason"],
                    }
                )

    return _runtime_uses


def _get_or_create_finding(_findings, _kind, _class_analysis, _vmx):
    _class_name = _class_analysis.name
    _bucket = _findings[_kind]

    if _class_name not in _bucket:
        _java_b64, _xref = _get_javab64_xref(_class_analysis, _vmx)
        _bucket[_class_name] = {
            "class": _class_analysis.get_vm_class(),
            "class_analysis": _class_analysis,
            "xref": _xref,
            "java_b64": _java_b64,
            "naive": False,
            "matching_methods": [],
            "runtime_uses": [],
            "risk": "LOW",
        }

    return _bucket[_class_name]


def _register_matching_method(_finding, _method):
    _method_key = "{:s}{:s}".format(_method.get_name(), _method.get_descriptor())
    if _method_key not in _finding["matching_methods"]:
        _finding["matching_methods"].append(_method_key)

    if _returns_true(_method) or _returns_void(_method):
        _finding["naive"] = True


def _check_trust_manager(_class_analysis, _method, _findings, _vmx):
    if not _has_signature(_method, TRUST_MANAGER_SIGNATURES):
        return
    if not _class_implements_interface(_class_analysis, TRUST_MANAGER_INTERFACES):
        return

    _finding = _get_or_create_finding(
        _findings, "trustmanager", _class_analysis, _vmx
    )
    _register_matching_method(_finding, _method)


def _check_hostname_verifier(_class_analysis, _method, _findings, _vmx):
    if not _has_signature(_method, HOSTNAME_VERIFIER_SIGNATURES):
        return

    if not (
        _class_implements_interface(_class_analysis, HOSTNAME_VERIFIER_INTERFACES)
        or _class_extends_class(_class_analysis, HOSTNAME_VERIFIER_SUPERCLASSES)
    ):
        return

    _finding = _get_or_create_finding(
        _findings, "customhostnameverifier", _class_analysis, _vmx
    )
    _register_matching_method(_finding, _method)


def _finalize_findings(_findings):
    for _finding in _findings["trustmanager"].values():
        _finding["runtime_uses"] = _collect_runtime_uses(
            _finding["class_analysis"],
            TRUST_MANAGER_RUNTIME_SINKS,
        )
        if _finding["runtime_uses"]:
            _finding["risk"] = "HIGH"

    for _finding in _findings["customhostnameverifier"].values():
        _finding["runtime_uses"] = _collect_runtime_uses(
            _finding["class_analysis"],
            HOSTNAME_VERIFIER_RUNTIME_SINKS,
        )
        if _finding["runtime_uses"]:
            _finding["risk"] = "HIGH"


def _check_all(_vmx):
    _findings = {
        "trustmanager": {},
        "customhostnameverifier": {},
    }

    for _class_analysis in _vmx.get_internal_classes():
        for _method_analysis in _class_analysis.get_methods():
            if _method_analysis.is_external():
                continue

            _method = _method_analysis.get_method()
            _check_hostname_verifier(
                _class_analysis,
                _method,
                _findings,
                _vmx,
            )
            _check_trust_manager(
                _class_analysis,
                _method,
                _findings,
                _vmx,
            )

    _finalize_findings(_findings)

    return {
        "trustmanager": list(_findings["trustmanager"].values()),
        "customhostnameverifier": list(
            _findings["customhostnameverifier"].values()
        ),
    }


def _build_finding_entries(_result):
    _entries = []

    for _finding in _result["trustmanager"]:
        _entries.append(
            {
                "kind": "trustmanager",
                "title": "Custom TrustManager",
                "finding": _finding,
            }
        )

    for _finding in _result["customhostnameverifier"]:
        _entries.append(
            {
                "kind": "customhostnameverifier",
                "title": "Custom HostnameVerifier",
                "finding": _finding,
            }
        )

    return _entries


def _get_detection_reason(_entry):
    if _entry["kind"] == "trustmanager":
        return (
            "Implements checkServerTrusted(...) in a "
            "TrustManager/X509TrustManager class."
        )
    return (
        "Overrides verify(...) in a HostnameVerifier/"
        "X509HostnameVerifier class."
    )


def _get_naive_note(_entry):
    if not _entry["finding"]["naive"]:
        return None

    if _entry["kind"] == "trustmanager":
        return (
            "checkServerTrusted(...) appears empty or trivially accepts "
            "certificates."
        )

    return "verify(...) appears empty or trivially accepts hostnames."


def _get_reference_lines(_finding):
    _references = []
    _seen = set()

    for _ref in _finding["xref"]:
        _translated = _translate_method_name(_ref)
        if _translated in _seen:
            continue
        _seen.add(_translated)
        _references.append(_translated)

    return sorted(_references)


def _print_field(_label, _value):
    print("{:<16} {:s}".format("{:s}:".format(_label), _value))


def _print_runtime_evidence(_finding):
    print("Runtime evidence:")

    if not _finding["runtime_uses"]:
        print(" - Not confirmed in reachable TLS setup code")
        return

    for _index, _runtime_use in enumerate(_finding["runtime_uses"], 1):
        print(" {:d}. Caller : {:s}".format(
            _index,
            _translate_method_name(_runtime_use["caller"]),
        ))
        print(" Calls : {:s}".format(
            _translate_method_name(_runtime_use["callee"])
        ))
        print(" Reason : {:s}".format(_runtime_use["reason"]))
        print(" Xref : {:s}".format(", ".join(_runtime_use["origins"])))


def _print_references(_finding):
    print("References:")

    _references = _get_reference_lines(_finding)
    if not _references:
        print(" - None found")
        return

    for _reference in _references:
        print(" - {:s}".format(_reference))


def _print_java_source(_finding):
    print("Java source:")

    if not _finding["java_b64"]:
        print(" Source unavailable from Androguard decompiler.")
        return

    print(SOURCE_LINE + "java")
    print(base64.b64decode(_finding["java_b64"]).decode().rstrip())
    print(SOURCE_LINE)


def _print_finding(_index, _entry, _include_source):
    _finding = _entry["finding"]
    print("Finding {:d} | {:s}".format(_index, _entry["title"]))
    _print_field("Class", _translate_class_name(_finding["class"].get_name()))
    _print_field("Risk", _finding["risk"])
    _print_field("Flagged", _get_detection_reason(_entry))

    _naive_note = _get_naive_note(_entry)
    if _naive_note:
        _print_field("Naive check", _naive_note)

    print()
    _print_runtime_evidence(_finding)
    print()
    _print_references(_finding)
    print()
    _print_java_source(_finding)


def _print_section(_title, _entries, _start_index, _include_source):
    print("{:s} FINDINGS".format(_title))
    print(SECTION_LINE)

    for _offset, _entry in enumerate(_entries):
        _print_finding(_start_index + _offset, _entry, _include_source)
        print(SECTION_LINE)


def _print_result(_apk_path, _package_name, _result, _include_source=False, _status=None):
    _entries = _build_finding_entries(_result)
    _high_risk = [e for e in _entries if e["finding"]["risk"] == "HIGH"]
    _low_risk = [e for e in _entries if e["finding"]["risk"] != "HIGH"]

    print(REPORT_LINE)
    print("APK SSL Misuse Report")
    print(REPORT_LINE)
    _print_field("APK", Path(_apk_path).name)
    _print_field("Package", _package_name)
    _print_field(
        "Findings",
        "{:d} total | {:d} HIGH | {:d} LOW".format(
            len(_entries),
            len(_high_risk),
            len(_low_risk),
        ),
    )
    print(REPORT_LINE)
    print()

    if _status:
        print("Status: {:s}".format(_status))
        print()

    if not _entries:
        print("No findings detected.")
        print()
        print(SECTION_LINE)
        print("End of report")
        return

    _next_index = 1

    if _high_risk:
        _print_section("HIGH RISK", _high_risk, _next_index, _include_source)
        _next_index += len(_high_risk)

    if _low_risk:
        _print_section("LOW RISK", _low_risk, _next_index, _include_source)

    print("End of report")


def _empty_result():
    return {
        "trustmanager": [],
        "customhostnameverifier": [],
    }


def _has_high_risk_findings(_findings):
    return any(_finding["risk"] == "HIGH" for _finding in _findings)


def _build_apk_summary(
    _apk_path,
    _package_name,
    _result,
    _ssl_analyzed,
    _analysis_failed=False,
    _status=None,
):
    return {
        "apk_path": str(_apk_path),
        "package_name": _package_name,
        "status": _status,
        "analysis_failed": _analysis_failed,
        "ssl_analyzed": _ssl_analyzed,
        "has_high_risk_trustmanager": _has_high_risk_findings(
            _result["trustmanager"]
        ),
        "has_high_risk_hostnameverifier": _has_high_risk_findings(
            _result["customhostnameverifier"]
        ),
    }


def _analyze_apk(_apk_path, _include_source=False):
    try:
        _apk, _dex, _analysis = AnalyzeAPK(str(_apk_path))
    except Exception as _error:
        print(REPORT_LINE)
        print("APK Report: {:s}".format(Path(_apk_path).name))
        print("Package: unknown")
        print("Summary: 0 findings total | 0 HIGH | 0 LOW")
        print(REPORT_LINE)
        print()
        print("Status: Analysis failed")
        print("Error: {:s}".format(str(_error)))
        print()
        print(SECTION_LINE)
        print("End of report")
        return _build_apk_summary(
            _apk_path,
            "unknown",
            _empty_result(),
            _ssl_analyzed=False,
            _analysis_failed=True,
            _status="Analysis failed",
        )

    _package_name = _apk.get_package()

    if "android.permission.INTERNET" not in _apk.get_permissions():
        _empty = _empty_result()
        _print_result(
            _apk_path,
            _package_name,
            _empty,
            _include_source,
            _status=(
                "INTERNET permission not requested. SSL misuse analysis "
                "was skipped."
            ),
        )
        return _build_apk_summary(
            _apk_path,
            _package_name,
            _empty,
            _ssl_analyzed=False,
            _status="INTERNET permission not requested",
        )

    _result = _check_all(_analysis)
    _print_result(
        _apk_path,
        _package_name,
        _result,
        _include_source,
    )
    return _build_apk_summary(
        _apk_path,
        _package_name,
        _result,
        _ssl_analyzed=True,
    )


def _analyze_apk_to_text(_apk_path, _include_source=False):
    _buffer = StringIO()

    with redirect_stdout(_buffer), redirect_stderr(_buffer):
        _apk_summary = _analyze_apk(_apk_path, _include_source)

    return _buffer.getvalue(), _apk_summary


def _write_report(_output_dir, _apk_path, _report_text):
    _report_path = _output_dir / "{:s}.txt".format(_apk_path.stem)
    _report_path.write_text(_report_text, encoding="utf-8")
    return _report_path


def _calculate_percentage(_count, _total):
    if _total == 0:
        return 0.0
    return (_count / _total) * 100.0


def _build_batch_summary(_apk_summaries):
    _total_selected = len(_apk_summaries)
    _analyzed = [_summary for _summary in _apk_summaries if _summary["ssl_analyzed"]]
    _analyzed_count = len(_analyzed)
    _failed_count = sum(1 for _summary in _apk_summaries if _summary["analysis_failed"])
    _skipped_count = _total_selected - _analyzed_count - _failed_count
    _high_risk_trustmanager_count = sum(
        1 for _summary in _analyzed if _summary["has_high_risk_trustmanager"]
    )
    _high_risk_hostnameverifier_count = sum(
        1 for _summary in _analyzed if _summary["has_high_risk_hostnameverifier"]
    )

    return {
        "total_selected": _total_selected,
        "analyzed_count": _analyzed_count,
        "failed_count": _failed_count,
        "skipped_count": _skipped_count,
        "high_risk_trustmanager_count": _high_risk_trustmanager_count,
        "high_risk_hostnameverifier_count": _high_risk_hostnameverifier_count,
        "high_risk_trustmanager_percentage": _calculate_percentage(
            _high_risk_trustmanager_count,
            _analyzed_count,
        ),
        "high_risk_hostnameverifier_percentage": _calculate_percentage(
            _high_risk_hostnameverifier_count,
            _analyzed_count,
        ),
    }


def _format_batch_summary(_batch_summary, _start_position, _processed_count):
    _end_position = _start_position + _processed_count - 1

    _lines = [
        REPORT_LINE,
        "Batch Summary",
        REPORT_LINE,
        "Selected APKs: {:d}".format(_batch_summary["total_selected"]),
        "Processed positions: {:d} to {:d}".format(
            _start_position,
            _end_position,
        ),
        "Successfully analyzed for SSL misuse: {:d}".format(
            _batch_summary["analyzed_count"]
        ),
        "Skipped (no INTERNET permission): {:d}".format(
            _batch_summary["skipped_count"]
        ),
        "Failed to analyze: {:d}".format(_batch_summary["failed_count"]),
        "",
        (
            "Apps with HIGH-risk custom trust managers: {:d}/{:d} ({:.2f}%)"
        ).format(
            _batch_summary["high_risk_trustmanager_count"],
            _batch_summary["analyzed_count"],
            _batch_summary["high_risk_trustmanager_percentage"],
        ),
        (
            "Apps with HIGH-risk hostname verifiers: {:d}/{:d} ({:.2f}%)"
        ).format(
            _batch_summary["high_risk_hostnameverifier_count"],
            _batch_summary["analyzed_count"],
            _batch_summary["high_risk_hostnameverifier_percentage"],
        ),
        REPORT_LINE,
    ]

    return "\n".join(_lines) + "\n"


def _write_batch_summary(_output_dir, _summary_text):
    _summary_path = _output_dir / "batch_summary.txt"
    _summary_path.write_text(_summary_text, encoding="utf-8")
    return _summary_path


def _slice_apk_files(_apk_files, _start, _count):
    if _start < 1:
        raise ValueError("--start must be 1 or greater")

    if _count is not None and _count < 1:
        raise ValueError("--count must be 1 or greater")

    if _start > len(_apk_files):
        raise ValueError(
            "--start ({:d}) is greater than the number of APKs found ({:d})".format(
                _start,
                len(_apk_files),
            )
        )

    _start_index = _start - 1

    if _count is None:
        return _apk_files[_start_index:]

    return _apk_files[_start_index : _start_index + _count]


def _analyze_directory(
    _apk_dir,
    _output_dir,
    _include_source=False,
    _start=1,
    _count=None,
):
    _apk_dir = Path(_apk_dir)
    _output_dir = Path(_output_dir)

    if not _apk_dir.exists():
        raise FileNotFoundError(
            "APK directory does not exist: {:s}".format(str(_apk_dir))
        )

    if not _apk_dir.is_dir():
        raise NotADirectoryError(
            "APK path is not a directory: {:s}".format(str(_apk_dir))
        )

    _apk_files = sorted(
        _path for _path in _apk_dir.iterdir() if _path.is_file() and _path.suffix.lower() == ".apk"
    )

    if not _apk_files:
        raise FileNotFoundError(
            "No APK files found in directory: {:s}".format(str(_apk_dir))
        )

    _selected_apk_files = _slice_apk_files(_apk_files, _start, _count)
    _output_dir.mkdir(parents=True, exist_ok=True)

    print(
        "Found {:d} APK file(s) in {:s}".format(
            len(_apk_files),
            str(_apk_dir),
        )
    )
    print(
        "Processing {:d} APK file(s), starting at position {:d}".format(
            len(_selected_apk_files),
            _start,
        )
    )
    print("Writing reports to {:s}".format(str(_output_dir)))

    _apk_summaries = []

    for _apk_path in _selected_apk_files:
        _report_text, _apk_summary = _analyze_apk_to_text(
            _apk_path,
            _include_source,
        )
        _report_path = _write_report(_output_dir, _apk_path, _report_text)
        _apk_summaries.append(_apk_summary)
        print(
            "Wrote report for {:s} to {:s}".format(
                _apk_path.name,
                str(_report_path),
            )
        )

    _batch_summary = _build_batch_summary(_apk_summaries)
    _batch_summary_text = _format_batch_summary(
        _batch_summary,
        _start,
        len(_selected_apk_files),
    )
    _batch_summary_path = _write_batch_summary(_output_dir, _batch_summary_text)
    print("Wrote batch summary to {:s}".format(str(_batch_summary_path)))


def _parseargs():
    _parser = argparse.ArgumentParser(
        description=(
            "Analyze Android APKs for custom TrustManagers and "
            "HostnameVerifiers, and label them as HIGH risk when runtime "
            "TLS use is detected. By default, the script scans all APKs in "
            "the ./apks directory and writes one .txt report per APK."
        )
    )
    _parser.add_argument(
        "-f",
        "--file",
        help="APK file to check",
        type=str,
    )
    _parser.add_argument(
        "-d",
        "--directory",
        help="Directory containing APK files to check",
        type=str,
        default="apks",
    )
    _parser.add_argument(
        "-o",
        "--output-dir",
        help="Directory where .txt reports will be written in batch mode",
        type=str,
        default="reports",
    )
    _parser.add_argument(
        "--include-source",
        help=(
            "Deprecated compatibility flag. Decompiled Java source is now "
            "included in every finding automatically when available."
        ),
        action="store_true",
    )
    _parser.add_argument(
        "--start",
        help="1-based position in the sorted APK list where batch processing should begin",
        type=int,
        default=1,
    )
    _parser.add_argument(
        "--count",
        help="Number of APKs to process in batch mode",
        type=int,
    )
    return _parser.parse_args()


def main():
    _args = _parseargs()

    if _args.file:
        _analyze_apk(Path(_args.file), _args.include_source)
        return

    _analyze_directory(
        _args.directory,
        _args.output_dir,
        _args.include_source,
        _args.start,
        _args.count,
    )


if __name__ == "__main__":
    main()
