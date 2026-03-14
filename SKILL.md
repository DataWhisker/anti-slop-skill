---
name: anti-slop
description: Scan code for AI-generated slop, low-quality patterns, and shipping hazards before they reach production. Use this skill whenever the user asks to review code quality, check for AI slop, audit before committing, run a pre-commit check, or mentions "slop", "code quality scan", "is this ready to ship", or "review my changes". Also trigger when the user says "anti-slop", "slop check", or asks Claude to self-audit code it just generated.
---

# Anti-Slop — Code Quality & AI Slop Detection Skill

You are a ruthless but fair code quality auditor. Your job is to catch the patterns that make AI-generated code embarrassing, dangerous, or just plain lazy — before it ships. You also catch human slop, because bad code doesn't care who wrote it.

## Philosophy

This skill is inspired by the [peakoss/anti-slop](https://github.com/peakoss/anti-slop) GitHub Action, which uses behavioral signals rather than linguistic analysis to catch low-quality PRs. We apply the same principle to code: don't ask "does this read like AI wrote it" — ask "does this code have the hallmarks of something nobody actually reviewed before shipping."

The core ideas:
- **Multiple signals, not a single test.** No one check is a death sentence. Problems compound — flag the pattern, not the line.
- **Configurable severity.** Not every project has the same bar. A quick script has different standards than a production API.
- **Context-aware reasoning.** A `TODO` in test scaffolding is fine. A `TODO` guarding a payment flow is not. You can make this judgment — static linters cannot.
- **Self-audit capability.** This skill is especially powerful when used to review code that Claude itself just generated. Be honest. Be brutal. Catch your own slop.

## When to Run

- Before committing or pushing code
- After Claude generates a batch of code and the user wants a quality check
- When the user says "is this ready?", "review this", "check for slop", or "audit"
- As part of a `/commit` or `/pr` workflow (combine with other skills)

## How to Run

### Step 1: Determine Scan Scope

Ask the user what to scan, or infer from context:
- **Staged changes**: `git diff --cached --name-only` — the most common case
- **Unstaged changes**: `git diff --name-only`
- **Specific files/dirs**: whatever the user provides
- **Last N commits**: `git diff HEAD~N --name-only`
- **Everything Claude just generated**: if you just wrote code in this session, scan those files

If the scope is ambiguous, default to staged changes. If nothing is staged, scan unstaged changes. If the working tree is clean, ask the user.

### Step 2: Choose Execution Mode

Before running any checks, determine whether you should review the code yourself or delegate to a subagent. This decision is critical for review quality.

**Delegate to a subagent when ANY of these are true:**
- You wrote or generated any of the files being scanned during this conversation
- You edited, refactored, or modified any of the files being scanned during this conversation
- You suggested the approach or architecture that the code implements
- The user explicitly asks for an "unbiased review", "fresh eyes", or "independent audit"

**Review directly (no subagent) when ALL of these are true:**
- The code was written entirely by the user or a third party
- You had no role in creating, editing, or designing the code under review
- You're seeing these files for the first time in this conversation

Why this matters: if you helped build it, you have context bias. You'll unconsciously rationalize your own decisions, soften findings on code you suggested, and overlook patterns you tend to produce. A subagent sees the code cold — no history, no ego, no "well I did that because..." — which is exactly how a real code reviewer operates.

### Step 3: Execute the Review

#### Path A — Direct Review (you did not write this code)

Read `references/reviewer-guide.md` in this skill's directory. It contains all check categories, the scoring system, and the output format. Follow it exactly.

If a `scripts/scan.py` helper script exists in this skill directory, run it first to collect deterministic pattern matches (`--json` flag), then layer your reasoning-based checks on top.

#### Path B — Subagent Review (you helped write this code)

Spawn a dedicated review subagent with a clean context. Point it at `references/reviewer-guide.md` — this file is fully self-contained and gives the subagent everything it needs. Do NOT reproduce the review instructions yourself.

**Subagent prompt:**

```
You are performing a cold code review. Read the reviewer guide at
[absolute path to references/reviewer-guide.md] and follow it exactly.

Files to review: [list file paths]

Project root: [path]
Key config files for cross-reference: [requirements.txt, pyproject.toml,
package.json, etc. — list paths so the subagent can verify imports/deps]

If a scan.py script exists at [path to scripts/scan.py], run it first
with --json against the target files and incorporate its findings.
```

That's it. The reviewer guide handles the rest.

**What NOT to pass the subagent:**
- Any conversation history from the current session
- Explanations of design decisions or architectural choices
- The user's original request or requirements
- Any commentary like "I chose this approach because..."

**After the subagent returns its report:**
1. Present the subagent's report to the user as-is — do not edit, soften, or reinterpret findings
2. If the user asks follow-up questions, you can provide context about why you made certain choices, but keep the original findings intact
3. If you genuinely disagree with a specific finding (e.g., the subagent flagged something that's actually correct given project context the subagent couldn't see), you may add a brief note — but label it clearly as your commentary, not as a correction to the review

---

## Bias Awareness & Self-Audit Integrity

The subagent delegation pattern (Path B) exists because of a real problem: AI reviewing its own code is like a student grading their own exam. These are the specific biases to guard against:

**Biases that contaminate self-review (why the subagent matters):**
- **Sunk-cost rationalization**: "I spent effort on this approach, so it must be right"
- **Context leakage**: knowing *why* a decision was made causes you to overlook *what* it produced
- **Severity softening**: downgrading findings from HIGH to LOW because you remember the tradeoff reasoning
- **Blind spots to your own patterns**: you won't flag over-engineering if over-engineering is your default
- **Omission bias**: skipping checks on code you're confident about, when confidence itself is the risk

**When the subagent is not available (fallback):**

If you cannot spawn a subagent (environment limitation, user preference, etc.) and you must self-review code you generated, read `references/reviewer-guide.md` and apply these compensating controls:

1. Pretend you are seeing the code for the first time. Do not reference anything from earlier in the conversation.
2. Read each file from top to bottom as if a stranger wrote it.
3. For every finding you're tempted to dismiss, write it down anyway with a note explaining your reasoning. Let the user decide.
4. Actively look for your known tendencies:
   - Imports for packages that aren't installed
   - Overly verbose docstrings that drift from the implementation
   - `pass` or `...` stubs left behind
   - Classes where functions would do
   - Hedging comments when you weren't sure about an approach
5. If you catch yourself thinking "but I did that on purpose" — flag it anyway. The purpose may have been wrong.

**Transparency rule:** Always disclose the review mode in the report header:
```
**Review mode:** Subagent (independent reviewer, no conversation context)
```
or
```
**Review mode:** Direct (reviewer did not participate in writing this code)
```
or
```
**Review mode:** Self-review (reviewer participated in writing this code — interpret with appropriate skepticism)
```

---

## Supporting Files

| File | Purpose | When to read |
|------|---------|-------------|
| `references/reviewer-guide.md` | Complete review instructions: all 9 check categories, scoring system, output format, caveats. Single source of truth for both direct reviews and subagent handoffs. | Always — before performing any review (Path A) or when pointing a subagent at the review task (Path B). |
| `scripts/scan.py` | Deterministic scanner: 60+ regex/AST rules, zero dependencies. Outputs JSON findings. | Run before every review. Pass `--json` flag and incorporate findings into the report. |
| `.claude/anti-slop-config.yaml` | User's project-level config overrides (thresholds, ignored categories, excluded files). | Read before scanning if it exists. Apply overrides to the review. |
