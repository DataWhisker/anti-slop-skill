#!/usr/bin/env python3
"""
anti-slop scan.py — Deterministic code quality scanner for the anti-slop skill.

Scans source files for AI-generated slop patterns, security issues, placeholders,
hedging language, cross-language leakage, and structural smells. Outputs JSON
findings for Claude to incorporate into the Anti-Slop Report.

Usage:
    python scan.py <file_or_dir> [file_or_dir ...] [--json] [--severity <level>]
    python scan.py --staged          # scan git staged files
    python scan.py --unstaged        # scan git modified files
    python scan.py --diff HEAD~3     # scan files changed in last 3 commits

Sources & Inspiration:
    - peakoss/anti-slop (GitHub Action — PR quality heuristics, honeypot traps)
    - rsionnach/sloppylint (Python AI slop — cross-language leakage, hallucinated imports)
    - skew202/antislop (Rust linter — deferrals, hedging, stubs, zero false positive core)
    - CodeDeficient/KarpeSlop (TypeScript — 3-axis: Noise/Lies/Soul)
    - h33tlit/secret-regex-list, gitleaks, trufflehog (secret patterns)

Requires: Python 3.9+ (stdlib only — no pip dependencies)
"""

from __future__ import annotations

import argparse
import ast
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Severity levels (match SKILL.md scoring)
# ---------------------------------------------------------------------------

class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


SEVERITY_NAMES = {
    Severity.LOW: "LOW",
    Severity.MEDIUM: "MEDIUM",
    Severity.HIGH: "HIGH",
    Severity.CRITICAL: "CRITICAL",
}


# ---------------------------------------------------------------------------
# Finding data class
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    file: str
    line: int
    category: str
    severity: str
    severity_points: int
    rule_id: str
    message: str
    match: str = ""
    suggested_fix: str = ""


# ---------------------------------------------------------------------------
# Category 1 — Stubs & Placeholders
# ---------------------------------------------------------------------------

STUB_COMMENT_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("naked_todo", re.compile(r"#\s*TODO(?!\s*\()\s*(?::?\s*)?$", re.IGNORECASE), "Naked TODO without context or owner"),
    ("naked_fixme", re.compile(r"#\s*FIXME(?!\s*\()\s*(?::?\s*)?$", re.IGNORECASE), "FIXME without context"),
    ("naked_hack", re.compile(r"#\s*HACK\b", re.IGNORECASE), "HACK marker left in code"),
    ("naked_xxx", re.compile(r"#\s*XXX\b", re.IGNORECASE), "XXX marker left in code"),
    ("todo_with_context", re.compile(r"#\s*TODO\s*\(.+?\)", re.IGNORECASE), "TODO with owner/context (informational)"),
]

PLACEHOLDER_STRING_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("placeholder_lorem", re.compile(r"""(['"])lorem ipsum\1""", re.IGNORECASE), "Lorem ipsum placeholder string"),
    ("placeholder_changeme", re.compile(r"""(['"])(CHANGEME|REPLACE_ME|CHANGE_ME|PUT_.*_HERE|YOUR_.*_HERE|INSERT_.*_HERE)\1""", re.IGNORECASE), "Placeholder string that needs replacing"),
    ("placeholder_example_domain", re.compile(r"""(['"])(https?://)?(www\.)?(example\.com|example\.org|test\.com|foo\.bar)\1""", re.IGNORECASE), "Example domain in non-test code"),
    ("placeholder_fake_email", re.compile(r"""(['"]).*@example\.(com|org)\1""", re.IGNORECASE), "Fake email placeholder"),
]


def check_stubs_placeholders(filepath: str, content: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    is_test = _is_test_file(filepath)

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # --- Comment-based stubs ---
        for rule_id, pattern, msg in STUB_COMMENT_PATTERNS:
            if pattern.search(stripped):
                sev = Severity.LOW if rule_id == "todo_with_context" else Severity.HIGH
                if is_test and rule_id != "naked_hack":
                    sev = Severity.LOW
                findings.append(Finding(
                    file=filepath, line=i, category="stubs_placeholders",
                    severity=SEVERITY_NAMES[sev], severity_points=int(sev),
                    rule_id=rule_id, message=msg, match=stripped.strip(),
                ))
                break  # one match per line

        # --- Placeholder strings ---
        if not is_test:
            for rule_id, pattern, msg in PLACEHOLDER_STRING_PATTERNS:
                m = pattern.search(stripped)
                if m:
                    findings.append(Finding(
                        file=filepath, line=i, category="stubs_placeholders",
                        severity=SEVERITY_NAMES[Severity.HIGH],
                        severity_points=int(Severity.HIGH),
                        rule_id=rule_id, message=msg, match=m.group(0),
                    ))

    # --- Python-specific AST checks ---
    if filepath.endswith(".py"):
        findings.extend(_check_python_stubs(filepath, content, is_test))

    return findings


def _check_python_stubs(filepath: str, content: str, is_test: bool) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if len(body) == 1:
                stmt = body[0]
                # pass as sole body
                if isinstance(stmt, ast.Pass):
                    # skip abstract methods
                    is_abstract = any(
                        isinstance(d, ast.Name) and "abstract" in d.id.lower()
                        for d in node.decorator_list
                        if isinstance(d, ast.Name)
                    ) or any(
                        isinstance(d, ast.Attribute) and "abstract" in d.attr.lower()
                        for d in node.decorator_list
                        if isinstance(d, ast.Attribute)
                    )
                    if not is_abstract:
                        sev = Severity.MEDIUM if is_test else Severity.HIGH
                        findings.append(Finding(
                            file=filepath, line=node.lineno,
                            category="stubs_placeholders",
                            severity=SEVERITY_NAMES[sev],
                            severity_points=int(sev),
                            rule_id="pass_placeholder",
                            message=f"Function `{node.name}` has only `pass` as body",
                            suggested_fix="Implement the function or mark as @abstractmethod",
                        ))
                # Ellipsis as sole body
                elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is ...:
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        category="stubs_placeholders",
                        severity=SEVERITY_NAMES[Severity.HIGH],
                        severity_points=int(Severity.HIGH),
                        rule_id="ellipsis_placeholder",
                        message=f"Function `{node.name}` has only `...` as body",
                        suggested_fix="Implement the function or use NotImplementedError with reason",
                    ))
                # raise NotImplementedError
                elif isinstance(stmt, ast.Raise) and isinstance(getattr(stmt, 'exc', None), ast.Call):
                    exc = stmt.exc
                    if isinstance(exc.func, ast.Name) and exc.func.id == "NotImplementedError":
                        findings.append(Finding(
                            file=filepath, line=node.lineno,
                            category="stubs_placeholders",
                            severity=SEVERITY_NAMES[Severity.MEDIUM],
                            severity_points=int(Severity.MEDIUM),
                            rule_id="not_implemented_stub",
                            message=f"Function `{node.name}` raises NotImplementedError",
                            suggested_fix="Implement the function or document why it's deferred",
                        ))
            # Also check if body is [docstring, pass]
            elif len(body) == 2:
                if (isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
                        and isinstance(body[0].value.value, str) and isinstance(body[1], ast.Pass)):
                    # skip abstract methods (same logic as pass-only check above)
                    is_abstract = any(
                        isinstance(d, ast.Name) and "abstract" in d.id.lower()
                        for d in node.decorator_list
                        if isinstance(d, ast.Name)
                    ) or any(
                        isinstance(d, ast.Attribute) and "abstract" in d.attr.lower()
                        for d in node.decorator_list
                        if isinstance(d, ast.Attribute)
                    )
                    if not is_abstract:
                        sev = Severity.MEDIUM if is_test else Severity.HIGH
                        findings.append(Finding(
                            file=filepath, line=node.lineno,
                            category="stubs_placeholders",
                            severity=SEVERITY_NAMES[sev],
                            severity_points=int(sev),
                            rule_id="docstring_pass_only",
                            message=f"Function `{node.name}` has only a docstring and `pass`",
                            suggested_fix="Implement the function body",
                        ))

        # Bare except or overly broad except
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                findings.append(Finding(
                    file=filepath, line=node.lineno,
                    category="stubs_placeholders",
                    severity=SEVERITY_NAMES[Severity.CRITICAL],
                    severity_points=int(Severity.CRITICAL),
                    rule_id="bare_except",
                    message="Bare `except:` catches everything including SystemExit and KeyboardInterrupt",
                    suggested_fix="Catch specific exceptions: except ValueError, except OSError, etc.",
                ))
            elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                body = node.body
                if len(body) == 1 and isinstance(body[0], ast.Pass):
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        category="stubs_placeholders",
                        severity=SEVERITY_NAMES[Severity.HIGH],
                        severity_points=int(Severity.HIGH),
                        rule_id="except_exception_pass",
                        message="`except Exception: pass` silently swallows all errors",
                        suggested_fix="Log the error or handle it explicitly",
                    ))

    return findings


# ---------------------------------------------------------------------------
# Category 2 — Hallucination Signals (import verification)
# ---------------------------------------------------------------------------

# Python stdlib modules (3.9+) — comprehensive list for validation
PYTHON_STDLIB_MODULES: set[str] = {
    "__future__", "abc", "aifc", "argparse", "array", "ast", "asynchat",
    "asyncio", "asyncore", "atexit", "audioop", "base64", "bdb", "binascii",
    "binhex", "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb",
    "chunk", "cmath", "cmd", "code", "codecs", "codeop", "collections",
    "colorsys", "compileall", "concurrent", "configparser", "contextlib",
    "contextvars", "copy", "copyreg", "cProfile", "crypt", "csv", "ctypes",
    "curses", "dataclasses", "datetime", "dbm", "decimal", "difflib",
    "dis", "distutils", "doctest", "email", "encodings", "enum", "errno",
    "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch", "fractions",
    "ftplib", "functools", "gc", "getopt", "getpass", "gettext", "glob",
    "grp", "gzip", "hashlib", "heapq", "hmac", "html", "http", "idlelib",
    "imaplib", "imghdr", "imp", "importlib", "inspect", "io", "ipaddress",
    "itertools", "json", "keyword", "lib2to3", "linecache", "locale",
    "logging", "lzma", "mailbox", "mailcap", "marshal", "math", "mimetypes",
    "mmap", "modulefinder", "multiprocessing", "netrc", "nis", "nntplib",
    "numbers", "operator", "optparse", "os", "ossaudiodev", "pathlib",
    "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform",
    "plistlib", "poplib", "posix", "posixpath", "pprint", "profile",
    "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue",
    "quopri", "random", "re", "readline", "reprlib", "resource", "rlcompleter",
    "runpy", "sched", "secrets", "select", "selectors", "shelve", "shlex",
    "shutil", "signal", "site", "smtpd", "smtplib", "sndhdr", "socket",
    "socketserver", "spwd", "sqlite3", "sre_compile", "sre_constants",
    "sre_parse", "ssl", "stat", "statistics", "string", "stringprep",
    "struct", "subprocess", "sunau", "symtable", "sys", "sysconfig",
    "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile", "termios",
    "test", "textwrap", "threading", "time", "timeit", "tkinter", "token",
    "tokenize", "tomllib", "trace", "traceback", "tracemalloc", "tty",
    "turtle", "turtledemo", "types", "typing", "unicodedata", "unittest",
    "urllib", "uu", "uuid", "venv", "warnings", "wave", "weakref",
    "webbrowser", "winreg", "winsound", "wsgiref", "xdrlib", "xml",
    "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
    # common sub-modules people import directly
    "os.path", "collections.abc", "typing.extensions", "typing_extensions",
    "concurrent.futures", "urllib.parse", "urllib.request", "http.client",
    "http.server", "xml.etree", "xml.etree.ElementTree", "email.mime",
    "logging.handlers", "unittest.mock", "importlib.metadata",
    "importlib.resources",
}


def check_hallucinated_imports(filepath: str, content: str, _lines: list[str]) -> list[Finding]:
    """Flag imports of modules that aren't in stdlib and likely don't exist."""
    if not filepath.endswith(".py"):
        return []

    findings: list[Finding] = []
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top not in PYTHON_STDLIB_MODULES and not _module_likely_exists(top):
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        category="hallucination_signals",
                        severity=SEVERITY_NAMES[Severity.MEDIUM],
                        severity_points=int(Severity.MEDIUM),
                        rule_id="unverified_import",
                        message=f"Import `{alias.name}` — not in stdlib; verify it's installed",
                        match=f"import {alias.name}",
                        suggested_fix=f"Run: pip show {top} || pip install {top}",
                    ))
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0]
            if top not in PYTHON_STDLIB_MODULES and not _module_likely_exists(top):
                names = ", ".join(a.name for a in node.names)
                findings.append(Finding(
                    file=filepath, line=node.lineno,
                    category="hallucination_signals",
                    severity=SEVERITY_NAMES[Severity.MEDIUM],
                    severity_points=int(Severity.MEDIUM),
                    rule_id="unverified_import",
                    message=f"Import from `{node.module}` — not in stdlib; verify it's installed",
                    match=f"from {node.module} import {names}",
                    suggested_fix=f"Run: pip show {top} || pip install {top}",
                ))

    return findings


def _module_likely_exists(module_name: str) -> bool:
    """Quick heuristic: check if the module is importable or exists in site-packages."""
    # Check if there's a local file/package by that name
    for ext in ("", ".py"):
        if os.path.exists(module_name + ext):
            return True
    if os.path.isdir(module_name):
        return True

    # Try actual import check (fast, cached)
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False
    except Exception:
        # Module exists but has load errors — still "exists"
        return True


# ---------------------------------------------------------------------------
# Category 3 — Hedging & Uncertainty
# ---------------------------------------------------------------------------

HEDGING_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("hedge_should_work", re.compile(r"#.*\bshould\s+work\b", re.IGNORECASE), "Hedging: 'should work' expresses uncertainty"),
    ("hedge_might_need", re.compile(r"#.*\bmight\s+need\b", re.IGNORECASE), "Hedging: 'might need' signals incomplete thinking"),
    ("hedge_probably", re.compile(r"#.*\bprobably\b(?!\s+O\()", re.IGNORECASE), "Hedging: 'probably' expresses uncertainty"),
    ("hedge_i_think", re.compile(r"#.*\bi\s+think\b", re.IGNORECASE), "Hedging: 'I think' — the code should speak for itself"),
    ("hedge_not_sure", re.compile(r"#.*\bnot\s+sure\b", re.IGNORECASE), "Hedging: 'not sure' signals uncertainty about correctness"),
    ("hedge_may_need", re.compile(r"#.*\bmay\s+need\s+to\b", re.IGNORECASE), "Hedging: 'may need to' signals incomplete implementation"),
    ("hedge_hopefully", re.compile(r"#.*\bhopefully\b", re.IGNORECASE), "Hedging: 'hopefully' — hope is not a strategy"),
    ("hedge_seems_to", re.compile(r"#.*\bthis\s+seems?\s+to\b", re.IGNORECASE), "Hedging: 'this seems to' — verify, don't guess"),
    ("hedge_for_now", re.compile(r"#.*\bfor\s+now\b", re.IGNORECASE), "Deferral: 'for now' indicates temporary implementation"),
    ("hedge_workaround", re.compile(r"#.*\bworkaround\b(?!.*(?:for|because|due to|since))", re.IGNORECASE), "Unexplained workaround — document what it's working around"),
    ("hedge_good_enough", re.compile(r"#.*\bgood\s+enough\b", re.IGNORECASE), "Hedging: 'good enough' — define the actual requirement"),
    ("hedge_quick_fix", re.compile(r"#.*\bquick\s+(?:fix|hack)\b", re.IGNORECASE), "Hedging: 'quick fix/hack' — is this the real solution?"),
    ("hedge_somehow", re.compile(r"#.*\bsomehow\b", re.IGNORECASE), "Hedging: 'somehow' — unclear reasoning"),
]


def check_hedging(filepath: str, _content: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped.startswith("#") and "#" not in stripped:
            continue
        for rule_id, pattern, msg in HEDGING_PATTERNS:
            if pattern.search(stripped):
                sev = Severity.HIGH if rule_id == "hedge_for_now" else Severity.MEDIUM
                findings.append(Finding(
                    file=filepath, line=i, category="hedging_uncertainty",
                    severity=SEVERITY_NAMES[sev], severity_points=int(sev),
                    rule_id=rule_id, message=msg, match=stripped,
                ))
                break
    return findings


# ---------------------------------------------------------------------------
# Category 4 — Cross-Language Leakage (inspired by sloppylint)
# ---------------------------------------------------------------------------

CROSS_LANG_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    # JavaScript patterns in Python
    ("js_push", re.compile(r"\.\bpush\s*\("), "JavaScript `.push()` used in Python", "Use `.append()` instead"),
    ("js_length", re.compile(r"\.\blength\b(?!\s*[=(])"), "JavaScript `.length` used in Python", "Use `len()` instead"),
    ("js_foreach", re.compile(r"\.\bforEach\s*\("), "JavaScript `.forEach()` used in Python", "Use a `for` loop instead"),
    ("js_console_log", re.compile(r"\bconsole\.\blog\s*\("), "JavaScript `console.log()` used in Python", "Use `print()` or `logging`"),
    ("js_const_let", re.compile(r"^\s*(?:const|let|var)\s+\w+\s*="), "JavaScript variable declaration in Python", "Python doesn't use const/let/var"),
    ("js_null", re.compile(r"\bnull\b(?!.*#)"), "JavaScript `null` in Python", "Use `None` instead"),
    ("js_undefined", re.compile(r"\bundefined\b(?!.*#)"), "JavaScript `undefined` in Python", "Python has no `undefined`; use `None`"),
    ("js_triple_eq", re.compile(r"\w\s*===\s*\w|\w\s*!==\s*\w"), "JavaScript strict equality in Python", "Use `==` / `!=` or `is` / `is not`"),
    ("js_arrow_fn", re.compile(r"=>\s*\{"), "JavaScript arrow function syntax", "Use `lambda` or `def`"),
    # Java patterns in Python
    ("java_equals", re.compile(r"\.\bequals\s*\("), "Java `.equals()` used in Python", "Use `==` operator"),
    ("java_tostring", re.compile(r"\.\btoString\s*\("), "Java `.toString()` used in Python", "Use `str()` instead"),
    ("java_isempty", re.compile(r"\.\bisEmpty\s*\("), "Java `.isEmpty()` used in Python", "Use `not obj` or `len(obj) == 0`"),
    ("java_system_out", re.compile(r"\bSystem\.out\.print"), "Java `System.out.print` in Python", "Use `print()`"),
    # Ruby patterns in Python
    ("ruby_nil", re.compile(r"\.\bnil\?\s*$"), "Ruby `.nil?` used in Python", "Use `is None`"),
    ("ruby_puts", re.compile(r"^\s*puts\s+"), "Ruby `puts` used in Python", "Use `print()`"),
    # Go patterns in Python
    ("go_fmt", re.compile(r"\bfmt\.Print"), "Go `fmt.Print` used in Python", "Use `print()`"),
    # C# patterns in Python
    ("csharp_length", re.compile(r"\.\bLength\b"), "C# `.Length` used in Python", "Use `len()`"),
    ("csharp_count", re.compile(r"\.\bCount\b(?!\s*\()"), "C# `.Count` property used in Python", "Use `len()`"),
    ("csharp_tolower", re.compile(r"\.\bToLower\s*\("), "C# `.ToLower()` used in Python", "Use `.lower()`"),
]


def check_cross_language(filepath: str, _content: str, lines: list[str]) -> list[Finding]:
    if not filepath.endswith(".py"):
        return []
    findings: list[Finding] = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for rule_id, pattern, msg, fix in CROSS_LANG_PATTERNS:
            if pattern.search(stripped):
                findings.append(Finding(
                    file=filepath, line=i, category="hallucination_signals",
                    severity=SEVERITY_NAMES[Severity.HIGH],
                    severity_points=int(Severity.HIGH),
                    rule_id=rule_id, message=msg, match=stripped,
                    suggested_fix=fix,
                ))
                break
    return findings


# ---------------------------------------------------------------------------
# Category 5 — Python-Specific Anti-Patterns (inspired by sloppylint)
# ---------------------------------------------------------------------------

def check_python_antipatterns(filepath: str, content: str, _lines: list[str]) -> list[Finding]:
    if not filepath.endswith(".py"):
        return []
    findings: list[Finding] = []
    try:
        tree = ast.parse(content, filename=filepath)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        # Mutable default arguments
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for default in node.args.defaults + node.args.kw_defaults:
                if default is None:
                    continue
                if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        category="stubs_placeholders",
                        severity=SEVERITY_NAMES[Severity.CRITICAL],
                        severity_points=int(Severity.CRITICAL),
                        rule_id="mutable_default_arg",
                        message=f"Mutable default argument in `{node.name}()` — shared state bug",
                        suggested_fix="Use `None` as default, then initialize inside the function",
                    ))
                    break

        # Star imports
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        category="dead_code_noise",
                        severity=SEVERITY_NAMES[Severity.MEDIUM],
                        severity_points=int(Severity.MEDIUM),
                        rule_id="star_import",
                        message=f"Star import `from {node.module} import *` pollutes namespace",
                        suggested_fix="Import specific names instead",
                    ))

    return findings


# ---------------------------------------------------------------------------
# Category 6 — Security & Sensitive Data
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # Cloud provider keys
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID detected"),
    ("aws_mws_token", re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "Amazon MWS Auth Token"),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key detected"),
    ("google_oauth", re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"), "Google OAuth client ID"),

    # Git platform tokens
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    ("github_fine_pat", re.compile(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}"), "GitHub Fine-Grained PAT"),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth Access Token"),
    ("gitlab_pat", re.compile(r"glpat-[A-Za-z0-9\-]{20,}"), "GitLab Personal Access Token"),

    # AI/LLM API keys
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"), "OpenAI API Key"),
    ("anthropic_key", re.compile(r"sk-ant-api\d{2}-[a-zA-Z0-9_\-]{86}"), "Anthropic API Key"),
    ("huggingface_token", re.compile(r"hf_[A-Za-z0-9]{34}"), "HuggingFace Token"),

    # Payment processors
    ("stripe_live", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe Live Secret Key"),
    ("stripe_test", re.compile(r"sk_test_[0-9a-zA-Z]{24,}"), "Stripe Test Secret Key"),

    # Communication platforms
    ("slack_token", re.compile(r"xox[bposa]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}"), "Slack Token"),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"), "Slack Webhook URL"),
    ("twilio_sid", re.compile(r"AC[a-z0-9]{32}"), "Twilio Account SID"),
    ("sendgrid_key", re.compile(r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}"), "SendGrid API Key"),

    # Database / Connection strings
    ("postgres_url", re.compile(r"postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), "PostgreSQL connection string with credentials"),
    ("mysql_url", re.compile(r"mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), "MySQL connection string with credentials"),
    ("mongodb_url", re.compile(r"mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), "MongoDB connection string with credentials"),

    # SSH / Crypto keys
    ("rsa_private", re.compile(r"-----BEGIN RSA PRIVATE KEY-----"), "RSA Private Key"),
    ("ssh_private", re.compile(r"-----BEGIN (?:DSA|EC|OPENSSH) PRIVATE KEY-----"), "SSH Private Key"),
    ("pgp_private", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "PGP Private Key Block"),

    # JWT
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT Token detected"),

    # Generic secrets in assignments
    ("generic_password_assign", re.compile(r"""(?:password|passwd|pwd)\s*=\s*(['"])[^'"]{8,}\1""", re.IGNORECASE), "Hardcoded password in assignment"),
    ("generic_secret_assign", re.compile(r"""(?:secret|api_?key|auth_?token|access_?token)\s*=\s*(['"])[^'"]{8,}\1""", re.IGNORECASE), "Hardcoded secret/token in assignment"),
]

SECURITY_CODE_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    ("sql_fstring", re.compile(r"""f['"][ ]*(?:SELECT\b|INSERT\s+INTO\b|UPDATE\s+\w+\s+SET\b|DELETE\s+FROM\b|DROP\s+(?:TABLE|DATABASE|INDEX|VIEW)\b|ALTER\s+TABLE\b|CREATE\s+(?:TABLE|INDEX|VIEW|DATABASE)\b).*\{""", re.IGNORECASE), "SQL query built with f-string — SQL injection risk", "Use parameterized queries"),
    ("sql_format", re.compile(r"""\.format\(.*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b""", re.IGNORECASE), "SQL query built with .format() — SQL injection risk", "Use parameterized queries"),
    ("sql_concat", re.compile(r"""['"].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*['"]\s*\+\s*""", re.IGNORECASE), "SQL string concatenation — SQL injection risk", "Use parameterized queries"),
    ("eval_call", re.compile(r"\beval\s*\("), "Use of `eval()` — code injection risk", "Avoid eval(); use ast.literal_eval() for data"),
    ("exec_call", re.compile(r"\bexec\s*\("), "Use of `exec()` — code injection risk", "Avoid exec(); find a safer alternative"),
    ("os_system", re.compile(r"\bos\.system\s*\("), "Use of `os.system()` — command injection risk", "Use subprocess.run() with shell=False"),
    ("shell_true", re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"), "subprocess with shell=True — command injection risk", "Use shell=False and pass args as list"),
    ("ssl_no_verify", re.compile(r"verify\s*=\s*False"), "SSL verification disabled", "Enable SSL verification in production"),
    ("debug_true", re.compile(r"\bDEBUG\s*=\s*True\b"), "DEBUG flag set to True", "Ensure DEBUG=False in production"),
    ("cors_wildcard", re.compile(r"""allow_origins\s*=\s*\[\s*['"]?\*['"]?\s*\]"""), "CORS allows all origins", "Restrict to specific allowed origins"),
    ("bind_all_interfaces", re.compile(r"""(?:host|bind)\s*=\s*['"]0\.0\.0\.0['"]"""), "Binding to all network interfaces", "Use 127.0.0.1 for local-only or document the intent"),
]


def check_security(filepath: str, _content: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    is_test = _is_test_file(filepath)
    is_example = "example" in filepath.lower() or "sample" in filepath.lower()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # Secret patterns
        for rule_id, pattern, msg in SECRET_PATTERNS:
            if pattern.search(stripped):
                # Lower severity for test/example files
                sev = Severity.HIGH if (is_test or is_example) else Severity.CRITICAL
                findings.append(Finding(
                    file=filepath, line=i, category="security_sensitive",
                    severity=SEVERITY_NAMES[sev], severity_points=int(sev),
                    rule_id=rule_id, message=msg, match=_truncate(stripped, 80),
                    suggested_fix="Move to environment variable or secrets manager",
                ))
                break  # one secret per line is enough

        # Security code patterns
        for rule_id, pattern, msg, fix in SECURITY_CODE_PATTERNS:
            if pattern.search(stripped):
                sev = Severity.MEDIUM if is_test else Severity.CRITICAL
                findings.append(Finding(
                    file=filepath, line=i, category="security_sensitive",
                    severity=SEVERITY_NAMES[sev], severity_points=int(sev),
                    rule_id=rule_id, message=msg, match=_truncate(stripped, 80),
                    suggested_fix=fix,
                ))

    return findings


# ---------------------------------------------------------------------------
# Category 7 — Dead Code & Noise
# ---------------------------------------------------------------------------

DEBUG_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("debug_print", re.compile(r"^\s*print\s*\("), "Debug `print()` statement left in"),
    ("debug_pdb", re.compile(r"\bpdb\.set_trace\s*\("), "`pdb.set_trace()` debugger left in"),
    ("debug_breakpoint", re.compile(r"^\s*breakpoint\s*\("), "`breakpoint()` debugger left in"),
    ("debug_ipdb", re.compile(r"\bipdb\.set_trace\s*\("), "`ipdb.set_trace()` debugger left in"),
    ("debug_icecream", re.compile(r"\bic\s*\("), "icecream `ic()` debug call left in"),
    ("debug_console_log", re.compile(r"\bconsole\.log\s*\("), "`console.log()` debug statement left in"),
    ("debug_debugger", re.compile(r"^\s*debugger\s*;?\s*$"), "`debugger` statement left in"),
]


def check_dead_code(filepath: str, content: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    is_test = _is_test_file(filepath)

    # Debug statements
    if not is_test:
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for rule_id, pattern, msg in DEBUG_PATTERNS:
                if pattern.search(stripped):
                    # Don't flag print in scripts with __main__
                    if rule_id == "debug_print" and "__main__" in content:
                        continue
                    findings.append(Finding(
                        file=filepath, line=i, category="dead_code_noise",
                        severity=SEVERITY_NAMES[Severity.LOW],
                        severity_points=int(Severity.LOW),
                        rule_id=rule_id, message=msg, match=_truncate(stripped, 60),
                        suggested_fix="Remove or replace with proper logging",
                    ))
                    break

    # Commented-out code blocks (3+ consecutive commented lines that look like code)
    consecutive_comments = 0
    block_start = 0
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") and _looks_like_commented_code(stripped):
            if consecutive_comments == 0:
                block_start = i
            consecutive_comments += 1
        else:
            if consecutive_comments >= 3:
                findings.append(Finding(
                    file=filepath, line=block_start, category="dead_code_noise",
                    severity=SEVERITY_NAMES[Severity.LOW],
                    severity_points=int(Severity.LOW),
                    rule_id="commented_out_code",
                    message=f"Commented-out code block ({consecutive_comments} lines, starting line {block_start})",
                    suggested_fix="Remove dead code — version control has the history",
                ))
            consecutive_comments = 0

    # Final newline check
    if content and not content.endswith("\n"):
        findings.append(Finding(
            file=filepath, line=len(lines), category="structural_smells",
            severity=SEVERITY_NAMES[Severity.LOW],
            severity_points=int(Severity.LOW),
            rule_id="missing_final_newline",
            message="File does not end with a newline character",
            suggested_fix="Add a trailing newline",
        ))

    return findings


def _looks_like_commented_code(line: str) -> bool:
    """Heuristic: does this commented line look like it was once code?"""
    stripped = line.lstrip("#").strip()
    if not stripped:
        return False
    code_indicators = [
        "import ", "from ", "def ", "class ", "return ", "if ", "else:", "elif ",
        "for ", "while ", "try:", "except", "raise ", "with ", "= ", "+=", "-=",
        "(", ")", "[", "]", ".append(", ".extend(", "print(",
    ]
    return any(indicator in stripped for indicator in code_indicators)


# ---------------------------------------------------------------------------
# Category 8 — Structural Smells
# ---------------------------------------------------------------------------

def check_structural(filepath: str, content: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    total_lines = len(lines)

    # File length
    if total_lines > 500:
        findings.append(Finding(
            file=filepath, line=1, category="structural_smells",
            severity=SEVERITY_NAMES[Severity.LOW],
            severity_points=int(Severity.LOW),
            rule_id="file_too_long",
            message=f"File is {total_lines} lines (threshold: 500)",
            suggested_fix="Consider splitting into smaller modules",
        ))

    # Python-specific structural checks
    if filepath.endswith(".py"):
        try:
            tree = ast.parse(content, filename=filepath)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            # Function too long
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = getattr(node, "end_lineno", None)
                if end:
                    length = end - node.lineno + 1
                    if length > 50:
                        findings.append(Finding(
                            file=filepath, line=node.lineno,
                            category="structural_smells",
                            severity=SEVERITY_NAMES[Severity.LOW],
                            severity_points=int(Severity.LOW),
                            rule_id="function_too_long",
                            message=f"Function `{node.name}` is {length} lines (threshold: 50)",
                            suggested_fix="Decompose into smaller functions",
                        ))

                # Too many parameters
                total_args = (
                    len(node.args.args)
                    + len(node.args.posonlyargs)
                    + len(node.args.kwonlyargs)
                )
                # Exclude 'self' and 'cls'
                if node.args.args and node.args.args[0].arg in ("self", "cls"):
                    total_args -= 1
                if total_args > 5:
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        category="structural_smells",
                        severity=SEVERITY_NAMES[Severity.LOW],
                        severity_points=int(Severity.LOW),
                        rule_id="too_many_params",
                        message=f"Function `{node.name}` has {total_args} parameters (threshold: 5)",
                        suggested_fix="Use a dataclass or config object to group parameters",
                    ))

            # Single-method class (over-engineering)
            if isinstance(node, ast.ClassDef):
                methods = [
                    n for n in node.body
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and n.name != "__init__"
                ]
                has_init = any(
                    isinstance(n, ast.FunctionDef) and n.name == "__init__"
                    for n in node.body
                )
                if has_init and len(methods) == 1:
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        category="over_engineering",
                        severity=SEVERITY_NAMES[Severity.LOW],
                        severity_points=int(Severity.LOW),
                        rule_id="single_method_class",
                        message=f"Class `{node.name}` has only __init__ + 1 method — consider a function instead",
                        suggested_fix="Convert to a standalone function unless extensibility is planned",
                    ))
                elif not has_init and len(methods) == 0 and len(node.body) <= 2:
                    findings.append(Finding(
                        file=filepath, line=node.lineno,
                        category="over_engineering",
                        severity=SEVERITY_NAMES[Severity.LOW],
                        severity_points=int(Severity.LOW),
                        rule_id="empty_class",
                        message=f"Class `{node.name}` has no meaningful methods",
                        suggested_fix="Add behavior or use a simpler data structure",
                    ))

    return findings


# ---------------------------------------------------------------------------
# Category 9 — Duplicate / Sequential Numbered Variables
# ---------------------------------------------------------------------------

NUMBERED_VAR_PATTERN = re.compile(r"\b(\w+?)([1-9])\s*=")


def check_duplication(filepath: str, _content: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    seen_numbered: dict[str, list[int]] = {}

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = NUMBERED_VAR_PATTERN.search(stripped)
        if m:
            base = m.group(1)
            seen_numbered.setdefault(base, []).append(i)

    for base, line_nums in seen_numbered.items():
        if len(line_nums) >= 3:
            findings.append(Finding(
                file=filepath, line=line_nums[0], category="duplication",
                severity=SEVERITY_NAMES[Severity.MEDIUM],
                severity_points=int(Severity.MEDIUM),
                rule_id="sequential_numbered_vars",
                message=f"Sequential numbered variables `{base}1`, `{base}2`, ... (lines {line_nums[:5]})",
                suggested_fix="Use a list or loop instead of numbered variables",
            ))

    return findings


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _is_test_file(filepath: str) -> bool:
    p = filepath.lower()
    return (
        "/test" in p or "/tests/" in p or p.endswith("_test.py")
        or p.startswith("test_") or "/spec/" in p or "fixture" in p
        or "/conftest" in p
    )


def _truncate(s: str, max_len: int) -> str:
    return s[:max_len] + "..." if len(s) > max_len else s


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (useful for secret detection)."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

BINARY_EXTENSIONS: set[str] = {
    ".pyc", ".pyo", ".so", ".o", ".a", ".dll", ".exe", ".bin", ".pkl",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".pdf", ".zip", ".gz",
    ".tar", ".whl", ".egg", ".db", ".sqlite", ".sqlite3",
    ".woff", ".woff2", ".ttf", ".eot",
}

IGNORED_DIRS: set[str] = {
    ".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".env", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", ".eggs", "*.egg-info", ".next", ".nuxt",
}


def discover_files(paths: list[str]) -> list[str]:
    files: list[str] = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            if p.suffix not in BINARY_EXTENSIONS:
                files.append(str(p))
        elif p.is_dir():
            for root, dirs, filenames in os.walk(p):
                dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.endswith(".egg-info")]
                for f in filenames:
                    fp = Path(root) / f
                    if fp.suffix not in BINARY_EXTENSIONS:
                        files.append(str(fp))
    return sorted(set(files))


def get_git_files(mode: str, ref: Optional[str] = None) -> list[str]:
    """Get file list from git."""
    try:
        if mode == "staged":
            cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"]
        elif mode == "unstaged":
            cmd = ["git", "diff", "--name-only", "--diff-filter=ACMR"]
        elif mode == "diff" and ref:
            cmd = ["git", "diff", ref, "--name-only", "--diff-filter=ACMR"]
        else:
            return []

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return [f for f in result.stdout.strip().split("\n") if f and Path(f).suffix not in BINARY_EXTENSIONS]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


# ---------------------------------------------------------------------------
# Main scanner pipeline
# ---------------------------------------------------------------------------

ALL_CHECKERS = [
    check_stubs_placeholders,
    check_hallucinated_imports,
    check_hedging,
    check_cross_language,
    check_python_antipatterns,
    check_security,
    check_dead_code,
    check_structural,
    check_duplication,
]


def scan_file(filepath: str) -> list[Finding]:
    """Run all checks against a single file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, PermissionError) as e:
        return [Finding(
            file=filepath, line=0, category="error",
            severity="LOW", severity_points=1,
            rule_id="read_error", message=f"Could not read file: {e}",
        )]

    lines = content.splitlines()
    findings: list[Finding] = []

    for checker in ALL_CHECKERS:
        findings.extend(checker(filepath, content, lines))

    return findings


def compute_verdict(score: int) -> str:
    if score == 0:
        return "CLEAN"
    elif score <= 5:
        return "ACCEPTABLE"
    elif score <= 12:
        return "NEEDS WORK"
    elif score <= 24:
        return "SLOPPY"
    else:
        return "DUMPSTER FIRE"


def scan_all(files: list[str], min_severity: Optional[str] = None) -> dict:
    """Scan all files and return a structured report."""
    severity_filter = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }.get((min_severity or "").lower(), Severity.LOW)

    all_findings: list[Finding] = []
    for filepath in files:
        all_findings.extend(scan_file(filepath))

    # Filter by severity
    filtered = [f for f in all_findings if f.severity_points >= int(severity_filter)]

    # Sort: critical first, then by file and line
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    filtered.sort(key=lambda f: (severity_order.get(f.severity, 99), f.file, f.line))

    total_score = sum(f.severity_points for f in filtered)
    verdict = compute_verdict(total_score)

    # Category breakdown
    categories: dict[str, int] = {}
    for f in filtered:
        categories[f.category] = categories.get(f.category, 0) + f.severity_points

    return {
        "files_scanned": len(files),
        "total_findings": len(filtered),
        "slop_score": total_score,
        "verdict": verdict,
        "category_breakdown": categories,
        "findings": [asdict(f) for f in filtered],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_report(report: dict, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(report, indent=2))
        return

    print("\n" + "=" * 60)
    print("  ANTI-SLOP SCAN REPORT")
    print("=" * 60)
    print(f"  Files scanned:   {report['files_scanned']}")
    print(f"  Total findings:  {report['total_findings']}")
    print(f"  Slop Score:      {report['slop_score']} — {report['verdict']}")

    if report["category_breakdown"]:
        print("\n  Category Breakdown:")
        for cat, pts in sorted(report["category_breakdown"].items(), key=lambda x: -x[1]):
            print(f"    {cat:<30s} {pts:>4d} pts")

    print("-" * 60)

    if not report["findings"]:
        print("  No issues found. Ship it.")
    else:
        current_severity = None
        for f in report["findings"]:
            if f["severity"] != current_severity:
                current_severity = f["severity"]
                print(f"\n  [{current_severity}]")

            loc = f"{f['file']}:{f['line']}"
            print(f"    {loc:<40s} [{f['rule_id']}]")
            print(f"      {f['message']}")
            if f.get("match"):
                print(f"      > {_truncate(f['match'], 70)}")
            if f.get("suggested_fix"):
                print(f"      Fix: {f['suggested_fix']}")

    print("\n" + "=" * 60 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Anti-Slop Scanner — detect AI slop, security issues, and code quality problems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", help="Files or directories to scan")
    parser.add_argument("--staged", action="store_true", help="Scan git staged files")
    parser.add_argument("--unstaged", action="store_true", help="Scan git unstaged (modified) files")
    parser.add_argument("--diff", metavar="REF", help="Scan files changed since REF (e.g., HEAD~3)")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    parser.add_argument("--severity", choices=["low", "medium", "high", "critical"],
                        default="low", help="Minimum severity to report (default: low)")

    args = parser.parse_args()

    # Determine files to scan
    files: list[str] = []
    if args.staged:
        files = get_git_files("staged")
    elif args.unstaged:
        files = get_git_files("unstaged")
    elif args.diff:
        files = get_git_files("diff", args.diff)
    elif args.paths:
        files = discover_files(args.paths)
    else:
        # Default: scan current directory
        files = discover_files(["."])

    if not files:
        if args.json_output:
            print(json.dumps({"error": "No files found to scan"}, indent=2))
        else:
            print("No files found to scan.")
        return 1

    report = scan_all(files, args.severity)
    print_report(report, as_json=args.json_output)

    # Exit code: 0 = clean/acceptable, 1 = needs work or worse
    return 0 if report["slop_score"] <= 5 else 1


if __name__ == "__main__":
    sys.exit(main())
