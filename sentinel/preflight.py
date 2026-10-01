# SPDX-License-Identifier: Apache-2.0
# K9-AIF Framework
"""Pre-flight check run before the server starts.

Fails fast (exit 1) when Sentinel could not assess anything: Ollama host
unreachable, the analysis model or Granite Guardian missing (Guardian is
mandatory), or the capability catalog unreadable. Kafka, GitHub and the UI
login are warnings: Sentinel still runs without them.

    python -m sentinel.preflight
"""

from __future__ import annotations

import sys
from typing import List, Tuple

import requests

from sentinel import catalog
from sentinel.settings import (analysis_model, credentials, github, hil_approvers, kafka_broker, load_config,
                               ollama_base_url)

OK, WARN, FAIL = "ok", "warn", "fail"


def check() -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    url = ollama_base_url()
    try:
        resp = requests.get(f"{url}/api/tags", timeout=5)
        resp.raise_for_status()
        pulled = {m.get("name") for m in resp.json().get("models", [])}
        out.append((OK, f"Ollama reachable at {url} · {len(pulled)} models"))
    except Exception as exc:
        return [(FAIL, f"Ollama not reachable at {url} ({exc.__class__.__name__}); fix OLLAMA_BASE_URL")]

    cfg = load_config()
    for label, model in (("analysis model", analysis_model()),
                         ("Granite Guardian (mandatory)", cfg["governance"]["guardian"]["model"])):
        out.append((OK, f"{label}: {model}") if model in pulled else
                   (FAIL, f"{label} '{model}' not pulled. Run: ollama pull {model}"))
    try:
        cat = catalog.load(refresh=True)
        out.append((OK, f"capability catalog: k9-aif {cat.get('framework_version')} · "
                        f"{len(cat['capabilities'])} controls ({cat['_origin']})"))
    except Exception as exc:
        out.append((FAIL, f"capability catalog unreadable: {exc}"))
    try:
        from sentinel import store
        store.init()
        db = store.backend()
        out.append((OK, f"database: {db['dialect']}{' · schema ' + db['schema'] if db['schema'] else ''} · {db['where']}"))
    except Exception as exc:
        first = str(exc).strip().splitlines()[0][:200]
        out.append((FAIL, f"database unreachable ({first}). Check SENTINEL_DB / POSTGRES_* in .env"))
    out.append((OK, f"Kafka {kafka_broker()}: HIL cases enabled") if kafka_broker() else
               (WARN, "KAFKA_BROKER not set: findings stay in Sentinel's UI, no HIL cases"))
    if kafka_broker() and not hil_approvers():
        out.append((WARN, "SENTINEL_HIL_APPROVERS empty: Sentinel acts on a decision from ANY k9x-hil user"))
    gh = github()
    out.append((OK, f"GitHub live on {gh['repo']}") if gh["mode"] == "live" and gh["token"] else
               (WARN, f"GitHub {gh['mode']}: approved findings are recorded, not created"))
    if not credentials()["password"]:
        out.append((WARN, "SENTINEL_PASSWORD empty: UI disabled (scheduler still runs)"))
    return out


def main() -> int:
    results = check()
    for level, msg in results:
        print(f"[{level:4}] {msg}")
    failed = any(level == FAIL for level, _ in results)
    print("Pre-flight failed." if failed else "Pre-flight passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
