#!/usr/bin/env python3
"""
Honeypot Nexus - Isolation Guard
Scans app/honeypot/** and app/events/publisher.py via AST.
Fails with exit code 1 if any database or ORM module is imported,
or if dangerous execution functions are found.
"""

import ast
import os
import sys
from pathlib import Path

FORBIDDEN_MODULES = {
    "app.models",
    "app.models.models",
    "sqlalchemy",
    "sqlite3",
    "flask_sqlalchemy",
}

FORBIDDEN_SYMBOLS = {
    "db", # from app.extensions
}

DANGEROUS_CALLS = {
    "os.system",
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "eval",
    "exec",
    "compile",
}


def check_file(file_path: Path):
    violations = []
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    try:
        tree = ast.parse(content, filename=str(file_path))
    except SyntaxError as e:
        return [f"Syntax error parsing {file_path}: {e}"]

    for node in ast.walk(tree):
        # Check standard imports: import X
        if isinstance(node, ast.Import):
            for alias in node.names:
                for forbidden in FORBIDDEN_MODULES:
                    if alias.name == forbidden or alias.name.startswith(forbidden + "."):
                        violations.append(f"Forbidden import: 'import {alias.name}' at line {node.lineno}")

        # Check from imports: from X import Y
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for forbidden in FORBIDDEN_MODULES:
                if mod == forbidden or mod.startswith(forbidden + "."):
                    violations.append(f"Forbidden import: 'from {mod} import ...' at line {node.lineno}")
            if mod == "app.extensions":
                for alias in node.names:
                    if alias.name in FORBIDDEN_SYMBOLS:
                        violations.append(f"Forbidden symbol: 'from app.extensions import {alias.name}' at line {node.lineno}")

        # Check function calls for dangerous operations
        elif isinstance(node, ast.Call):
            call_name = ""
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                val = node.func.value
                val_id = val.id if isinstance(val, ast.Name) else ""
                call_name = f"{val_id}.{node.func.attr}" if val_id else node.func.attr

            if call_name in DANGEROUS_CALLS:
                violations.append(f"Dangerous call: '{call_name}()' at line {node.lineno}")

    return violations


def run_isolation_check():
    base_dir = Path(__file__).resolve().parent.parent
    targets = [base_dir / "app" / "honeypot", base_dir / "app" / "events" / "publisher.py"]

    total_violations = {}

    for target in targets:
        if target.is_file():
            v = check_file(target)
            if v:
                total_violations[str(target)] = v
        elif target.is_dir():
            for root, _, files in os.walk(target):
                for f in files:
                    if f.endswith(".py"):
                        p = Path(root) / f
                        v = check_file(p)
                        if v:
                            total_violations[str(p)] = v

    if total_violations:
        print("[ISOLATION FAILURE] Found forbidden dependencies or dangerous calls in untrusted layers:")
        for file_path, issues in total_violations.items():
            print(f"\nFile: {file_path}")
            for iss in issues:
                print(f"  - {iss}")
        return False

    print("[ISOLATION SUCCESS] Layer 1 Honeypot is completely isolated from database/ORM and dangerous APIs.")
    return True


if __name__ == "__main__":
    if not run_isolation_check():
        sys.exit(1)
    sys.exit(0)
