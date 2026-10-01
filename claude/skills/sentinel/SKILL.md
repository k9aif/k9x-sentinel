---
name: sentinel
description: Read open findings from the live K9X Sentinel (sentinel.k9x.ai), check each against the K9-AIF framework code and capability catalog, and propose the framework changes that would close them. Use when Ravi types /sentinel, optionally with "run" (trigger a run first) or a finding number (e.g. /sentinel 74).
---

# /sentinel — what does K9-AIF need to change?

K9X Sentinel watches new AI-security research daily and judges each threat against
K9-AIF's capability catalog (`k9_aif_abb/k9_security/capabilities.yaml`). This skill
turns its open findings into concrete, verified framework change proposals.

Paths:
- CLI: `python3 ~/ai/k9x-ecosystem/k9x_sentinel/tools/sentinel_cli.py <cmd>` (admin login from that repo's `.env`; never print the password)
- Framework: `~/ai/k9-aif-framework` (read its `CLAUDE.md` and `k9_aif_abb/k9_security/CLAUDE.md` before proposing anything)
- Catalog: `~/ai/k9-aif-framework/k9_aif_abb/k9_security/capabilities.yaml`

## Arguments ($ARGUMENTS)

- empty → analyse all open findings
- `run` → `sentinel_cli.py run --wait` first (shows progress), then analyse
- a number (`74` or `#74`) → analyse only that finding
- `status` → only show `sentinel_cli.py status` and `findings`, no analysis

## Steps

1. `sentinel_cli.py status` and `sentinel_cli.py findings --json`. Open = verdict gap or
   partial. If none: say so, show status, stop.
2. For each open finding: `sentinel_cli.py item <id> --json` (threat, rationale,
   suggested fix, OWASP ids, matched controls, known gap, audit trail).
3. **Verify against the code — Sentinel's suggestion is a lead, not a fact.** For each
   finding, find the framework code the attack would pass through (grep/read under
   `k9_aif_abb/`): what screens it today, what doesn't, and why. Quote file:line. Check
   the catalog entry for every control Sentinel matched and its stated `limits`.
   Check `known_gaps` too.
4. Report, for Ravi (expert architect; no hand-holding):
   - one line per finding: what it exploits, verdict/severity, source link
   - **what the code shows** (confirmed gaps with file:line; anything Sentinel got wrong)
   - **proposed changes table**: # · change (ABB/SBB, file) · closes which finding(s) ·
     size · catalog update. Order by risk closed per effort. Group changes that one
     release could ship.
   - a recommendation: which to build now, as which release.
5. **Stop. Do not implement** until Ravi says which to build.

## When Ravi says build

Follow the framework `CLAUDE.md` exactly: new capability extends a `Base<Concern>`
contract (never edits one); factories/registries; `llm_invoke` only; SPDX header on new
files; tests next to the existing ones; update `capabilities.yaml` **in the same commit**
(`test_security_capabilities.py` must pass); `./generate_pdoc.sh`; CHANGELOG; full test
suite (exclude the live Guardian test if Ollama is busy). Commit and push the framework.
PyPI publish only on Ravi's explicit go.

Afterwards the same kind of threat should come back **covered**: say which catalog
entry makes it so.

## Rules

- Read-only against Sentinel except `run` (which Ravi asked for). Never approve,
  reject or change HIL cases; decisions are made in k9x-hil by Ravi.
- Sentinel stays internal; GitHub actions stay `dry_run` (his decision). Don't propose
  going live, Keycloak SSO, or k9x-hil auth changes unless he asks.
- Commands on PowerAI: give them one at a time, never a reboot in the same step.
