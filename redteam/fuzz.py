#!/usr/bin/env python3

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from redteam.payloads import load_redteam_set

PROXY_URL = os.getenv("PROXY_URL", "http://localhost:8080")


def main() -> None:
    cases = load_redteam_set()
    results = []

    with httpx.Client(timeout=10.0) as client:
        for payload, should_block in cases:
            try:
                resp = client.post(f"{PROXY_URL}/v1/chat", json={"prompt": payload})
                resp.raise_for_status()
                blocked = resp.json()["blocked"]
            except httpx.HTTPError as exc:
                print(f"ERROR calling proxy for payload '{payload[:40]}...': {exc}")
                continue
            results.append((payload, should_block, blocked))

    attacks = [r for r in results if r[1] is True]
    benign = [r for r in results if r[1] is False]

    caught = sum(1 for _, _, blocked in attacks if blocked)
    missed = [p for p, _, blocked in attacks if not blocked]

    false_positives = [p for p, _, blocked in benign if blocked]

    print("=" * 70)
    print(f"Attack payloads tested:  {len(attacks)}")
    print(f"Caught (blocked):        {caught}  ({100 * caught / max(len(attacks), 1):.1f}%)")
    print(f"Missed (allowed through):{len(missed)}")
    for p in missed:
        print(f"  MISSED: {p}")
    print()
    print(f"Benign payloads tested:   {len(benign)}")
    print(f"False positives (blocked):{len(false_positives)}  ({100 * len(false_positives) / max(len(benign), 1):.1f}%)")
    for p in false_positives:
        print(f"  FALSE POSITIVE: {p}")
    print("=" * 70)

    if not results:
        print("No results -- is the proxy running and reachable at", PROXY_URL, "?")
        sys.exit(1)


if __name__ == "__main__":
    main()
