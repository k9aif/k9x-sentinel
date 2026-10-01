# CLAUDE.md — K9X Sentinel

Read `k9-aif-framework/CLAUDE.md` and `k9x-ecosystem/CLAUDE.md` first; this
file covers only what's specific to Sentinel. README.md has the full picture.

## What it is

A K9-AIF solution (SBBs on `k9_aif_abb`) that reads threat-intelligence
sources daily, compares each new threat with the framework's capability
catalog (`k9_aif_abb/k9_security/capabilities.yaml`), and raises gaps to
k9x-hil (`hil.requests.framework_security_updates`). Approved findings
become a GitHub draft advisory or issue (dry_run by default).

## Rules to keep

- **One item per assess flow.** `RequiresHIL` halts a flow, so each finding
  needs its own; the runner (entry point) drives `sentinel.assess` per item.
- **Every model call goes through `llm_invoke`** (`SentinelAgent.ask`).
- **Screen and label, never withhold, at ingress** (`ContentScreenAgent`).
  Attack write-ups contain injection text by nature; withholding them blinds
  Sentinel. Containment is: no tools, JSON-only answer, `validate()` against
  the catalog, human review.
- **GapAnalysisAgent's egress is Shield only.** Guardian blocks accurate
  attack analyses as harmful (verified live 2026-10-01). Don't "fix" this by
  adding Guardian back; there's a test pinning it.
- **The catalog is the framework's, not Sentinel's.** New controls are added
  to `capabilities.yaml` in the framework repo (its test enforces it), never
  to a local copy here.
- **Findings are private.** No public tunnel for the UI; HIL cases minimal by
  default; gaps go to *draft* advisories. See the README's k9x-hil note: any
  k9x-hil user can read every task and set any `actor`.
- **Fetch only public URLs** (`sources.public_url`, checked on every redirect hop).
- Agents call `self.enforce_governance()` first; orchestrators can't (it's a
  `BaseAgent` method).
- Status values live in `store.py`'s docstring; the UI tabs depend on them.
- **Storage is SQLAlchemy Core** (`store.py`): PostgreSQL when `SENTINEL_DB=postgres`
  (schema `k9sentinel`), SQLite otherwise. Never raw `sqlite3`. `audit_events` is
  append-only (DB trigger + hash chain, `verify_chain()`): record new facts with
  `store.audit(...)`, never update or delete an event. The event's `actor` column
  holds who did it; don't duplicate it in `detail`.
- **A model call is the last resort**: keep the `prefilter:` gate for broad feeds and
  the RetriageSquad path (re-send without re-assessing).

## Testing

`pytest -q` needs no network or models: `tests/test_flow.py` runs the real
framework HIL path (RequiresHIL → BaseHILOrchestrator → reply → resume)
with only the model and the Kafka bus faked.
