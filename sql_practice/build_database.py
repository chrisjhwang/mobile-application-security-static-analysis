#!/usr/bin/env python3
"""
build_database.py — Parse results/*_report.txt (real output from run_batch_analysis.py)
into a normalized SQLite database for SQL practice.

Usage:
    python build_database.py

Reads:  ../results/*_report.txt   (199 real per-app reports: RQ4, RQ5, RQ7)
Writes: compliance_findings.db
"""

import re
import sqlite3
import glob
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE.parent / "results"
DB_PATH = HERE / "compliance_findings.db"

SCHEMA = """
CREATE TABLE apps (
    app_id       INTEGER PRIMARY KEY,
    app_name     TEXT NOT NULL,
    file_name    TEXT NOT NULL,
    analyzed_at  TEXT
);

-- RQ4: Internet + PII permission combinations
CREATE TABLE rq4_scan (
    app_id          INTEGER PRIMARY KEY REFERENCES apps(app_id),
    has_internet    INTEGER NOT NULL,          -- 0/1
    normal_count    INTEGER NOT NULL,
    dangerous_count INTEGER NOT NULL,
    risk_level      TEXT NOT NULL,              -- HIGH / MEDIUM / LOW / NONE
    notes           TEXT
);

CREATE TABLE rq4_permissions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id           INTEGER REFERENCES apps(app_id),
    permission       TEXT NOT NULL,
    permission_type  TEXT NOT NULL              -- normal / dangerous
);

CREATE TABLE rq4_permission_evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id       INTEGER REFERENCES apps(app_id),
    permission   TEXT NOT NULL,
    call_site    TEXT NOT NULL
);

-- RQ5: declared-but-unused (over-privileged) permissions
CREATE TABLE rq5_scan (
    app_id       INTEGER PRIMARY KEY REFERENCES apps(app_id),
    status       TEXT NOT NULL,                 -- CLEAN / VULNERABLE
    notes        TEXT
);

CREATE TABLE rq5_unused_permissions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id       INTEGER REFERENCES apps(app_id),
    permission   TEXT NOT NULL
);

CREATE TABLE rq5_used_permissions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id       INTEGER REFERENCES apps(app_id),
    permission   TEXT NOT NULL
);

CREATE TABLE rq5_used_permission_evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id       INTEGER REFERENCES apps(app_id),
    permission   TEXT NOT NULL,
    call_site    TEXT NOT NULL
);

-- RQ7: exported components without a real permission guard
CREATE TABLE rq7_scan (
    app_id       INTEGER PRIMARY KEY REFERENCES apps(app_id),
    status       TEXT NOT NULL,                 -- CLEAN / VULNERABLE
    notes        TEXT
);

CREATE TABLE rq7_vulnerable_components (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id           INTEGER REFERENCES apps(app_id),
    component_type   TEXT NOT NULL,             -- activity/service/receiver/provider
    component_name   TEXT NOT NULL,
    export_type      TEXT,                      -- explicit / implicit
    reason           TEXT
);

CREATE TABLE rq7_safe_exports (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id           INTEGER REFERENCES apps(app_id),
    component_type   TEXT NOT NULL,
    component_name   TEXT NOT NULL,
    safe_reason      TEXT
);
"""

HEADER_RE = re.compile(
    r"APP\s*:\s*(?P<app>.*)\n"
    r"FILE\s*:\s*(?P<file>.*)\n"
    r"DATE\s*:\s*(?P<date>.*)\n"
)


def split_sections(text: str) -> dict:
    markers = ["[RQ4]", "[RQ5]", "[RQ7]"]
    idx = {m: text.find(m) for m in markers if m in text}
    ordered = sorted(idx.items(), key=lambda kv: kv[1])
    sections = {}
    for i, (marker, start) in enumerate(ordered):
        end = ordered[i + 1][1] if i + 1 < len(ordered) else len(text)
        sections[marker] = text[start:end]
    return sections


def parse_rq4(block: str) -> dict:
    notes = re.search(r"Notes\s*:\s*(.*)", block)
    internet = re.search(r"Internet\s*:\s*(YES|NO)", block)
    risk = re.search(r"Risk level:\s*(\S+)", block)
    normal_hdr = re.search(r"Normal permissions found with INTERNET \((\d+)\):", block)
    dangerous_hdr = re.search(r"Dangerous permissions found with INTERNET \((\d+)\):", block)

    lines = block.splitlines()
    normal_perms, dangerous_perms, evidence = [], [], []

    mode = None
    current_perm = None
    for line in lines:
        if "Normal permissions found with INTERNET" in line:
            mode = "normal"
            continue
        if "Dangerous permissions found with INTERNET" in line:
            mode = "dangerous"
            continue
        if "Risk level:" in line:
            mode = None
            continue
        if mode == "normal":
            m = re.match(r"^\s{4}(android\.permission\.\S+)\s*$", line)
            if m:
                normal_perms.append(m.group(1))
        elif mode == "dangerous":
            m = re.match(r"^\s{4}(android\.permission\.\S+)\s*$", line)
            if m:
                current_perm = m.group(1)
                dangerous_perms.append(current_perm)
                continue
            m2 = re.match(r"^\s{8}@\s*(.+)$", line)
            if m2 and current_perm:
                evidence.append((current_perm, m2.group(1).strip()))

    return {
        "notes": notes.group(1).strip() if notes else None,
        "has_internet": 1 if internet and internet.group(1) == "YES" else 0,
        "normal_count": int(normal_hdr.group(1)) if normal_hdr else 0,
        "dangerous_count": int(dangerous_hdr.group(1)) if dangerous_hdr else 0,
        "risk_level": risk.group(1) if risk else "NONE",
        "normal_perms": normal_perms,
        "dangerous_perms": dangerous_perms,
        "evidence": evidence,
    }


def parse_rq5(block: str) -> dict:
    status = re.search(r"Status\s*:\s*(\S+)", block)
    notes = re.search(r"Notes\s*:\s*(.*)", block)

    lines = block.splitlines()
    unused, used, evidence = [], [], []
    mode = None
    current_perm = None
    for line in lines:
        if "Used permissions" in line and "call-site evidence" in line:
            mode = "used"
            continue
        m = re.match(r"^\s{4}-\s*(android\.permission\.\S+)\s*$", line)
        if m and mode != "used":
            unused.append(m.group(1))
            continue
        if mode == "used":
            m2 = re.match(r"^\s{4}\+\s*(android\.permission\.\S+)\s*$", line)
            if m2:
                current_perm = m2.group(1)
                used.append(current_perm)
                continue
            m3 = re.match(r"^\s{8}@\s*(.+)$", line)
            if m3 and current_perm:
                evidence.append((current_perm, m3.group(1).strip()))

    return {
        "status": status.group(1) if status else "CLEAN",
        "notes": notes.group(1).strip() if notes else None,
        "unused": unused,
        "used": used,
        "evidence": evidence,
    }


def parse_rq7(block: str) -> dict:
    status = re.search(r"Status\s*:\s*(\S+)", block)
    notes = re.search(r"Notes\s*:\s*(.*)", block)

    lines = block.splitlines()
    vulnerable, safe = [], []
    mode = None
    cur = None
    for line in lines:
        m = re.match(r"^\s{4}\[UNPROTECTED (\w+)\]\s*(.+)$", line)
        if m:
            cur = {"component_type": m.group(1).lower(), "component_name": m.group(2).strip(),
                   "export_type": None, "reason": None}
            vulnerable.append(cur)
            mode = "vuln"
            continue
        if "Safe-by-design exports" in line:
            mode = "safe"
            cur = None
            continue
        if mode == "vuln" and cur is not None:
            m2 = re.match(r"^\s{6}export\s*:\s*(.+)$", line)
            if m2:
                cur["export_type"] = m2.group(1).strip()
                continue
            m3 = re.match(r"^\s{6}reason\s*:\s*(.+)$", line)
            if m3:
                cur["reason"] = m3.group(1).strip()
                continue
        if mode == "safe":
            m4 = re.match(r"^\s{6}\[(\w+)\]\s*(.+)$", line)
            if m4:
                cur = {"component_type": m4.group(1).lower(), "component_name": m4.group(2).strip(),
                       "safe_reason": None}
                safe.append(cur)
                continue
            m5 = re.match(r"^\s{8}(Has expected.*)$", line)
            if m5 and cur is not None:
                cur["safe_reason"] = m5.group(1).strip()

    return {
        "status": status.group(1) if status else "CLEAN",
        "notes": notes.group(1).strip() if notes else None,
        "vulnerable": vulnerable,
        "safe": safe,
    }


def main():
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    report_files = sorted(RESULTS_DIR.glob("*_report.txt"))
    print(f"Found {len(report_files)} report files in {RESULTS_DIR}")

    app_id = 0
    for path in report_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        header = HEADER_RE.search(text)
        if not header:
            print(f"  [skip] no header: {path.name}")
            continue

        app_id += 1
        app_name = header.group("app").strip()
        file_name = header.group("file").strip()
        analyzed_at = header.group("date").strip()
        conn.execute(
            "INSERT INTO apps (app_id, app_name, file_name, analyzed_at) VALUES (?, ?, ?, ?)",
            (app_id, app_name, file_name, analyzed_at),
        )

        sections = split_sections(text)

        if "[RQ4]" in sections:
            rq4 = parse_rq4(sections["[RQ4]"])
            conn.execute(
                "INSERT INTO rq4_scan (app_id, has_internet, normal_count, dangerous_count, risk_level, notes) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (app_id, rq4["has_internet"], rq4["normal_count"], rq4["dangerous_count"],
                 rq4["risk_level"], rq4["notes"]),
            )
            conn.executemany(
                "INSERT INTO rq4_permissions (app_id, permission, permission_type) VALUES (?, ?, ?)",
                [(app_id, p, "normal") for p in rq4["normal_perms"]] +
                [(app_id, p, "dangerous") for p in rq4["dangerous_perms"]],
            )
            conn.executemany(
                "INSERT INTO rq4_permission_evidence (app_id, permission, call_site) VALUES (?, ?, ?)",
                [(app_id, perm, site) for perm, site in rq4["evidence"]],
            )

        if "[RQ5]" in sections:
            rq5 = parse_rq5(sections["[RQ5]"])
            conn.execute(
                "INSERT INTO rq5_scan (app_id, status, notes) VALUES (?, ?, ?)",
                (app_id, rq5["status"], rq5["notes"]),
            )
            conn.executemany(
                "INSERT INTO rq5_unused_permissions (app_id, permission) VALUES (?, ?)",
                [(app_id, p) for p in rq5["unused"]],
            )
            conn.executemany(
                "INSERT INTO rq5_used_permissions (app_id, permission) VALUES (?, ?)",
                [(app_id, p) for p in rq5["used"]],
            )
            conn.executemany(
                "INSERT INTO rq5_used_permission_evidence (app_id, permission, call_site) VALUES (?, ?, ?)",
                [(app_id, perm, site) for perm, site in rq5["evidence"]],
            )

        if "[RQ7]" in sections:
            rq7 = parse_rq7(sections["[RQ7]"])
            conn.execute(
                "INSERT INTO rq7_scan (app_id, status, notes) VALUES (?, ?, ?)",
                (app_id, rq7["status"], rq7["notes"]),
            )
            conn.executemany(
                "INSERT INTO rq7_vulnerable_components "
                "(app_id, component_type, component_name, export_type, reason) VALUES (?, ?, ?, ?, ?)",
                [(app_id, c["component_type"], c["component_name"], c["export_type"], c["reason"])
                 for c in rq7["vulnerable"]],
            )
            conn.executemany(
                "INSERT INTO rq7_safe_exports (app_id, component_type, component_name, safe_reason) VALUES (?, ?, ?, ?)",
                [(app_id, c["component_type"], c["component_name"], c["safe_reason"])
                 for c in rq7["safe"]],
            )

    conn.commit()

    # Sanity-check counts against the report files themselves
    cur = conn.cursor()
    print("\n--- Load summary ---")
    for label, query in [
        ("apps", "SELECT COUNT(*) FROM apps"),
        ("rq4_scan rows", "SELECT COUNT(*) FROM rq4_scan"),
        ("rq4_permissions rows", "SELECT COUNT(*) FROM rq4_permissions"),
        ("rq5_scan rows", "SELECT COUNT(*) FROM rq5_scan"),
        ("rq5_unused_permissions rows", "SELECT COUNT(*) FROM rq5_unused_permissions"),
        ("rq7_scan rows", "SELECT COUNT(*) FROM rq7_scan"),
        ("rq7_vulnerable_components rows", "SELECT COUNT(*) FROM rq7_vulnerable_components"),
        ("apps flagged VULNERABLE on RQ5", "SELECT COUNT(*) FROM rq5_scan WHERE status='VULNERABLE'"),
        ("apps flagged VULNERABLE on RQ7", "SELECT COUNT(*) FROM rq7_scan WHERE status='VULNERABLE'"),
    ]:
        print(f"  {label:36} {cur.execute(query).fetchone()[0]}")

    conn.close()
    print(f"\nDatabase written to {DB_PATH}")


if __name__ == "__main__":
    main()
