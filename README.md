# K9X Sentinel

**A daily threat-intelligence watch for the [K9-AIF](https://github.com/k9aif/k9-aif-framework) framework, built on the framework itself.**

Every morning Sentinel reads the sources security teams actually follow (Zscaler ThreatLabz, OWASP GenAI, MITRE ATLAS, CISA KEV, agent-security researchers, and OSV for the framework's own dependencies). It compares each new threat with what K9-AIF already defends against, and sends the ones the framework doesn't fully cover to a human for review. Approved findings become a private draft security advisory, or an issue for public dependency CVEs, on the framework repository. Sentinel never changes code.

![What K9X Sentinel does](web/architecture.svg)

## What it compares against

The framework ships a machine-readable **capability catalog**, `k9_aif_abb/k9_security/capabilities.yaml`. It lists every Shield check, Guardian risk, Zero Trust/identity component, the tool-result guard, router protections and HIL, mapped to OWASP Top 10 for LLM Applications 2025 (LLM01–10) and OWASP Top 10 for Agentic Applications 2026 (ASI01–10), plus the gaps the maintainers already know about. A framework test fails if a control is added without being listed, so Sentinel always judges against what the code actually does.

Sentinel reads the catalog from `SENTINEL_CATALOG_PATH`, else the installed `k9-aif` (1.14.1 and later ship it), else the framework's `main` branch. The UI shows which.

## Two tracks

| Track | Sources | How it decides |
|---|---|---|
| **Dependencies** | OSV | Deterministic, no model. Is the lowest version k9-aif *allows* (`requests>=2.28` → 2.28) affected by an advisory that has a fix? If so: "raise the floor to X". One finding per package and needed floor. |
| **Techniques** | ThreatLabz, OWASP GenAI, OWASP LLM Top 10 and MITRE ATLAS releases, CISA KEV (keyword-filtered), Simon Willison (prompt injection), Embrace The Red | The analysis model returns **covered / partial / gap / not relevant** with OWASP ids, the matching controls, a known-gap link, severity, confidence, rationale and a suggested fix. |

Only *gap* and *partial* findings that are relevant, at least medium severity and at least 0.5 confidence are raised (`config.yaml` → `sentinel.triage`). A threat that is an instance of a known gap is recorded against it, unless it's high severity or above. Everything else stays visible in the UI.

## Security of the bot itself

Sentinel spends its day reading attacker-written content, so it's built to survive that:

- **Fetching:** feeds are parsed with `defusedxml`. Article links are fetched only if every address the host resolves to is public, and every redirect hop is checked too, so a poisoned feed can't point Sentinel at the LAN. Responses are size-capped and reduced to plain text.
- **Screening labels, it doesn't withhold.** Most relevant articles contain live injection examples. Withholding them would blind Sentinel to exactly the threats it exists for. Content is screened with k9x Shield and Granite Guardian, the result is shown on the finding, and the model is told it's analysing (not obeying) flagged text.
- **Containment instead:** the analysis model has no tools. Its answer must be one JSON object, and every OWASP id, capability id and known-gap id is checked against the catalog (unknown ones are discarded). Every raised finding goes to a human.
- **Egress is Shield only.** Granite Guardian classifies *harmful content*, and an accurate analysis of a jailbreak technique reads as harmful to it. Verified live: it blocked every relevant assessment. The analysis agent's egress runs `OutputSanitizationCheck` (markup reaching the UI or GitHub) instead.
- **Private findings:** a gap is an unpatched weakness in a public framework. The UI requires a login, must never be put on a public tunnel, and approved gaps become **private draft** security advisories, not public issues.

## k9x-hil note (read before going live)

As of this writing, k9x-hil (also served publicly at hil.k9x.ai with a demo login) has two authorization gaps that matter here:

1. Any logged-in user can list and open **every** task (`/tasks` isn't filtered by application membership). Sentinel therefore sends **minimal** cases by default (`SENTINEL_HIL_DETAIL=minimal`): finding number, verdict, severity and a link to Sentinel's login-protected UI.
2. A decision's `actor` comes from the request body, not the login. Anyone logged in can decide **as anyone**. Sentinel acts only on decisions from `SENTINEL_HIL_APPROVERS` (others are ignored and the case is raised again), but that check is only as good as the actor k9x-hil records.

Until k9x-hil takes the actor from the authenticated user and checks membership, keep `SENTINEL_GITHUB_MODE=dry_run`. An approval then only records the exact advisory/issue request, and you create it yourself.

## Run it

```bash
cp .env.example .env              # set OLLAMA_BASE_URL, KAFKA_BROKER, SENTINEL_PASSWORD, ...
python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
./run.sh                          # pre-flight, then http://localhost:8114 (login from .env)
pytest -q                         # 44 tests, no network or models needed
```

On the Podman host (PowerAI): `ubuntu/build-run.sh all`, then `ubuntu/build-run.sh logs` for the pre-flight and `ubuntu/build-run.sh run` to trigger a run without waiting for 06:00. Port 8114, LAN only.

Prerequisites: Ollama with the analysis model (`SENTINEL_MODEL`, default `qwen3.8:27b`) and `granite4.1-guardian:8b` (mandatory, fails closed); Kafka/Redpanda and k9x-hil with the *Framework Security Updates* queue (seeded by k9x-hil at start-up) for HIL.

## Layout

```
sentinel/
  router/sentinel_router.py      SentinelRouter(K9EventRouter): in-process routing + HIL reply listener
  orchestrators/                 ScanOrchestrator, AssessOrchestrator (catches RequiresHIL)
  squads/sentinel_squads.yaml    CollectSquad, AssessSquad, DecisionSquad
  agents/                        collectors, ContentScreen / GapAnalysis / Triage, Decision (+ yaml/ roles)
  sources.py  osv.py             feed readers (SSRF-safe) and the dependency audit
  catalog.py                     loads the framework's capability catalog
  github_actions.py              draft advisory / issue (dry_run by default)
  store.py  runner.py  api.py    SQLite, the daily run + scheduler, FastAPI + login
web/index.html                   UI (plain JS, all model/feed text escaped)
ubuntu/                          Containerfile, build-run.sh
```

## License

Apache-2.0, like the framework.
