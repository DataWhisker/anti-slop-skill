<p align="center">
  <img src="https://img.shields.io/badge/slop_score-0-22c55e?style=for-the-badge&labelColor=0d1117" alt="Slop Score: 0">
  <img src="https://img.shields.io/badge/python-3.9+-3776ab?style=for-the-badge&logo=python&logoColor=white&labelColor=0d1117" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/dependencies-zero-22c55e?style=for-the-badge&labelColor=0d1117" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/license-MIT-a855f7?style=for-the-badge&labelColor=0d1117" alt="MIT License">
</p>

<h1 align="center">🧹 anti-slop</h1>

<p align="center">
  <strong>A Claude Code skill that catches AI-generated slop, security hazards, and low-quality code before it ships.</strong>
</p>

<p align="center">
  60+ rules · 9 check categories · AST-powered · zero pip dependencies<br/>
  Automatic subagent delegation for unbiased self-review of AI-generated code
</p>

---

## The Problem

AI coding assistants are incredibly productive. They're also incredibly good at producing code that *looks right* but:

- Imports packages that don't exist
- Leaves `pass` stubs where real logic should be
- Hedges with comments like `# should work for most cases`
- Leaks `.push()` and `.forEach()` into Python files
- Hardcodes API keys in assignments
- Over-engineers single-method classes nobody asked for

Traditional linters don't catch these patterns. They weren't designed to. **anti-slop** was.

## What Makes This Different

**It's a Claude Code skill, not just a linter.** The deterministic scanner (`scan.py`) handles regex and AST checks at machine speed. Claude handles the judgment calls — deciding whether a `TODO` is blocking a feature or fine in test scaffolding, whether an abstraction layer is justified or over-engineered, whether a comment is genuinely hedging or just documenting uncertainty.

**It delegates self-review to an unbiased subagent.** When Claude reviews code it just wrote, it has sunk-cost bias baked into the context window. anti-slop detects this situation and automatically spawns a fresh review agent with zero conversation history — no ego, no rationalization, no "well I did that because..."

## Quick Start

### As a Claude Code Skill (recommended)

Drop the skill into your project or global skills directory:

```bash
# Project-level (this repo only)
mkdir -p .claude/skills
cp -r anti-slop .claude/skills/anti-slop

# Global (all projects)
cp -r anti-slop ~/.claude/skills/anti-slop
```

Then in Claude Code:

```
you: "check this for slop"
you: "is this ready to ship?"
you: "run anti-slop on src/"
you: "review what you just wrote"  ← triggers subagent delegation
```

### As a Standalone Scanner

```bash
# Scan a directory
python scripts/scan.py src/

# Scan staged files before committing
python scripts/scan.py --staged

# Scan changes since last 3 commits
python scripts/scan.py --diff HEAD~3

# JSON output for CI pipelines
python scripts/scan.py src/ --json --severity high

# Only show critical and high findings
python scripts/scan.py . --severity high
```

## What It Catches

### 9 Check Categories, 60+ Rules

| Category | Severity | What It Detects | Source Inspiration |
|---|---|---|---|
| **Stubs & Placeholders** | HIGH | `pass` bodies, `...` stubs, naked `TODO`/`FIXME`, `NotImplementedError`, empty except blocks, placeholder strings | [peakoss/anti-slop](https://github.com/peakoss/anti-slop), [skew202/antislop](https://github.com/skew202/antislop) |
| **Hallucination Signals** | CRITICAL | Imports that don't exist, cross-language leakage (17 patterns: JS, Java, Ruby, Go, C#) | [sloppylint](https://github.com/rsionnach/sloppylint), [KarpeSlop](https://github.com/CodeDeficient/KarpeSlop) |
| **Hedging & Uncertainty** | MEDIUM | "should work", "for now", "hopefully", "not sure", "quick fix", unexplained workarounds (13 patterns) | [skew202/antislop](https://github.com/skew202/antislop) |
| **Security & Secrets** | CRITICAL | 25 secret patterns (AWS, GitHub, Stripe, OpenAI, Anthropic, SSH keys, JWTs, DB connection strings), SQL injection, `eval()`/`exec()`, disabled SSL | [gitleaks](https://github.com/confluentinc/gitleaks), [secret-regex-list](https://github.com/h33tlit/secret-regex-list) |
| **Python Anti-Patterns** | CRITICAL | Mutable default arguments, star imports | [sloppylint](https://github.com/rsionnach/sloppylint) |
| **Dead Code & Noise** | LOW | Debug prints, `breakpoint()`, `pdb`, commented-out code blocks, missing final newlines | [KarpeSlop](https://github.com/CodeDeficient/KarpeSlop) |
| **Documentation Mismatch** | MEDIUM | Docstrings that don't match params/returns *(Claude reasoning layer)* | — |
| **Over-Engineering** | LOW | Single-method classes, empty classes | [sloppylint](https://github.com/rsionnach/sloppylint) |
| **Structural Smells** | LOW | Files >500 lines, functions >50 lines, >5 params, sequential numbered variables | [peakoss/anti-slop](https://github.com/peakoss/anti-slop) |

### Cross-Language Leakage Detection

AI models are trained on code from every language. When generating Python, they frequently leak patterns from others:

```python
# 🚨 anti-slop catches all of these

items.push("new")           # JS → use .append()
if items.length > 10:       # JS → use len()
console.log("debug")        # JS → use print() or logging
user.equals(other)          # Java → use ==
obj.toString()              # Java → use str()
name.ToLower()              # C# → use .lower()
fmt.Println("hello")        # Go → use print()
value === other             # JS → use == or is
const x = 5                 # JS → Python has no const
```

### Secret Detection (25 Patterns)

```
✓ AWS Access Keys (AKIA...)        ✓ GitHub PATs (ghp_, github_pat_)
✓ Google API Keys (AIza...)        ✓ GitLab PATs (glpat-)
✓ OpenAI Keys (sk-...T3BlbkFJ)    ✓ Anthropic Keys (sk-ant-api...)
✓ HuggingFace Tokens (hf_)        ✓ Stripe Keys (sk_live_, sk_test_)
✓ Slack Tokens & Webhooks          ✓ Twilio SIDs, SendGrid Keys
✓ Postgres/MySQL/MongoDB URLs      ✓ RSA/SSH/PGP Private Keys
✓ JWTs (eyJ...)                    ✓ Generic password/secret assigns
```

## Scoring System

Each finding carries a severity weight. The total determines the verdict:

| Score | Verdict | What It Means |
|---|---|---|
| **0** | 🟢 CLEAN | Ship it. |
| **1–5** | 🟡 ACCEPTABLE | Minor issues. Ship if you're comfortable with the tradeoffs. |
| **6–12** | 🟠 NEEDS WORK | Several issues that should be addressed before committing. |
| **13–24** | 🔴 SLOPPY | Significant quality problems. Do not ship without fixes. |
| **25+** | 💀 DUMPSTER FIRE | Major rework needed. Consider starting fresh on the worst files. |

Severity weights: **CRITICAL** = 4 pts · **HIGH** = 3 pts · **MEDIUM** = 2 pts · **LOW** = 1 pt

## The Subagent Pattern

This is what sets anti-slop apart from every other code quality tool.

When you ask Claude to review code **it just wrote**, it automatically delegates to a fresh subagent:

```
┌─────────────────────────────────────────────────────┐
│  You: "build me an API client"                      │
│  Claude: *writes api_client.py*                     │
│  You: "check it for slop"                           │
│                                                     │
│  Claude detects: "I wrote these files"              │
│  ┌───────────────────────────────────────────────┐  │
│  │  SPAWNS SUBAGENT                              │  │
│  │  • Zero conversation history                  │  │
│  │  • No design rationale                        │  │
│  │  • Cold review, as if a stranger wrote it     │  │
│  │  • Cannot soften or rationalize findings      │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  Report header:                                     │
│  Review mode: Subagent (independent reviewer)       │
└─────────────────────────────────────────────────────┘
```

**Why?** AI reviewing its own code is like a student grading their own exam. The specific biases:

- **Sunk-cost rationalization** — "I spent effort on this, so it must be right"
- **Context leakage** — knowing *why* softens judgment of *what*
- **Severity softening** — downgrading findings because you remember the tradeoff
- **Blind spots** — you won't flag over-engineering if it's your default pattern

## Example Output

```
============================================================
  ANTI-SLOP SCAN REPORT
============================================================
  Files scanned:   1
  Total findings:  12
  Slop Score:      31 — DUMPSTER FIRE

  Category Breakdown:
    stubs_placeholders               12 pts
    security_sensitive                9 pts
    hallucination_signals             6 pts
    hedging_uncertainty               3 pts
    structural_smells                 1 pts
------------------------------------------------------------

  [CRITICAL]
    src/api.py:16       [mutable_default_arg]
      Mutable default argument in `process()` — shared state bug
      Fix: Use `None` as default, then initialize inside the function

    src/api.py:42       [bare_except]
      Bare `except:` catches everything including SystemExit
      Fix: Catch specific exceptions: except ValueError, etc.

  [HIGH]
    src/api.py:12       [stripe_live]
      Stripe Live Secret Key
      > API_KEY = "sk_live_************************"
      Fix: Move to environment variable or secrets manager

    src/api.py:28       [js_push]
      JavaScript `.push()` used in Python
      > items.push("new_item")
      Fix: Use `.append()` instead

  [MEDIUM]
    src/api.py:4        [unverified_import]
      Import `nonexistent_module` — not in stdlib; verify it's installed
      Fix: Run: pip show nonexistent_module

    src/api.py:19       [hedge_for_now]
      Deferral: 'for now' indicates temporary implementation
      > # for now just return something

============================================================
```

## Project Structure

```
anti-slop/
├── SKILL.md                       # Orchestration layer (147 lines)
│                                    Scope detection, execution mode routing,
│                                    subagent delegation, bias awareness
│
├── references/
│   └── reviewer-guide.md          # Single source of truth (232 lines)
│                                    All 9 check categories, scoring system,
│                                    output format — read by both the main
│                                    agent and subagents directly
│
└── scripts/
    └── scan.py                    # Deterministic scanner (1,068 lines)
                                     Zero dependencies — stdlib only
                                     AST-powered Python checks
                                     60+ regex patterns
                                     CLI with git integration
```

**Why this structure?** The reviewer guide is a standalone document the subagent reads directly as input tokens — Claude never has to reproduce the check categories or scoring system in its output. This saves ~200 output tokens per subagent invocation and eliminates copy drift.

## Configuration

Create `.claude/anti-slop-config.yaml` in your project root:

```yaml
# Adjust verdict thresholds
thresholds:
  acceptable: 5
  needs_work: 12
  sloppy: 24
  dumpster_fire: 25

# Skip entire categories
ignore_categories:
  - over_engineering
  - structural_smells

# Skip specific rules
ignore_rules:
  - debug_print        # we use print() intentionally
  - todo_with_context  # we track TODOs via issues

# File exclusion patterns
file_exclude:
  - "tests/**"
  - "migrations/**"
  - "*.generated.py"

# Strict mode: lowers all thresholds by one tier
strict_mode: false
```

## CI / Pre-Commit Integration

### Pre-commit hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
python .claude/skills/anti-slop/scripts/scan.py --staged --severity high --json > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ anti-slop: HIGH+ severity findings in staged files"
    python .claude/skills/anti-slop/scripts/scan.py --staged --severity high
    exit 1
fi
```

### GitHub Actions

```yaml
name: Anti-Slop Check
on: [pull_request]

jobs:
  slop-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Run anti-slop scanner
        run: |
          python .claude/skills/anti-slop/scripts/scan.py . \
            --severity medium \
            --json > slop-report.json
          cat slop-report.json | python -c "
          import json, sys
          r = json.load(sys.stdin)
          print(f'Slop Score: {r[\"slop_score\"]} — {r[\"verdict\"]}')
          if r['slop_score'] > 12:
              print('❌ FAILED: Score exceeds threshold')
              sys.exit(1)
          print('✅ PASSED')
          "
```

## Design Philosophy

**Inspired by [peakoss/anti-slop](https://github.com/peakoss/anti-slop)**, a GitHub Action that catches low-quality PRs using behavioral signals rather than linguistic analysis. We apply the same principle to code: don't ask "does this read like AI wrote it" — ask "does this code have the hallmarks of something nobody actually reviewed before shipping."

**Key principles:**

- **Multiple signals, not a single test.** One `TODO` won't tank you. A `TODO` + a hallucinated import + a hardcoded API key = 💀 DUMPSTER FIRE.
- **Context-aware severity.** The same pattern has different weight in test code vs production code.
- **Zero false positives in the core.** Borrowed from [skew202/antislop](https://github.com/skew202/antislop): the default profile should never flag legitimate code.
- **The scanner handles facts. Claude handles judgment.** Regex finds the `TODO`. Claude decides if it matters.

## Acknowledgments

This project stands on the shoulders of the growing anti-slop ecosystem:

| Project | What We Borrowed |
|---|---|
| [peakoss/anti-slop](https://github.com/peakoss/anti-slop) | Scoring philosophy, configurable thresholds, behavioral signal approach |
| [sloppylint](https://github.com/rsionnach/sloppylint) | Cross-language leakage patterns, mutable default detection, 3-axis scoring |
| [skew202/antislop](https://github.com/skew202/antislop) | Hedging/deferral patterns, zero false positive philosophy |
| [KarpeSlop](https://github.com/CodeDeficient/KarpeSlop) | Noise/Lies/Soul framework, debug artifact detection |
| [gitleaks](https://github.com/confluentinc/gitleaks) | Secret pattern design, entropy-based detection concepts |
| [secret-regex-list](https://github.com/h33tlit/secret-regex-list) | Comprehensive API key regex patterns |

## License

MIT — do whatever you want with it. If you build something cool on top of it, let us know.
