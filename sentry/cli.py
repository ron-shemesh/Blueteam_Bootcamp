# sentry/cli.py
import argparse
import json
import os
import time
from sentry.ingest import load_csv
from sentry.scoring import score_all


def _make_client(disabled: bool):
    """Build an AI client when a key is resolvable, unless explicitly disabled."""
    from sentry.apikey import load_api_key
    if disabled:
        return None
    key = load_api_key()
    if not key:
        return None
    os.environ["ANTHROPIC_API_KEY"] = key
    try:
        from sentry.ai_confirm import AnthropicClient
        return AnthropicClient()
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser(description="SENTRY blue-team detector")
    ap.add_argument("csv", help="path to process-command CSV")
    ap.add_argument("--target", type=int, default=20, help="known malicious count")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--no-ai", action="store_true",
                    help="force deterministic-only (skip AI even if a key is set)")
    ap.add_argument("--investigate", action="store_true",
                    help="run on-demand investigation (off the clock)")
    args = ap.parse_args()

    t0 = time.perf_counter()
    rows = load_csv(args.csv)
    scored = score_all(rows)
    client = _make_client(args.no_ai)
    from sentry.pipeline import run_full, candidate_count
    # AI only runs when the rules don't land on exactly `target` candidates.
    ai_ran = client is not None and candidate_count(scored, args.target) != args.target
    correlated, verdicts = run_full(scored, target=args.target, client=client)
    elapsed = time.perf_counter() - t0

    malicious = [v for v in verdicts if v.verdict == "malicious"]
    if args.json:
        print(json.dumps([v.__dict__ for v in malicious], indent=2))
    else:
        mode = ("AI-assisted" if ai_ran else
                "AI ready (not needed)" if client else "deterministic")
        print(f"Scan complete in {elapsed:.3f}s ({mode}) — {len(rows)} commands, "
              f"{len(malicious)} flagged malicious\n")
        for v in sorted(malicious, key=lambda v: v.confidence, reverse=True):
            print(f"  row {v.row_id:>3} | conf {v.confidence:.2f} | "
                  f"{v.mitre_technique or '-':<11} | {v.reason}")

    if getattr(args, "investigate", False):
        from sentry.investigate import (build_story, remediation_playbook,
                                        find_traps, infer_objective)
        from sentry.narrate import ai_narrative
        mal_ids = {v.row_id for v in malicious}
        mal_records = [s for s in correlated if s.command.row_id in mal_ids]
        print("\n" + "=" * 60 + "\nINVESTIGATION\n" + "=" * 60)
        print(build_story(mal_records))
        story = ai_narrative(mal_records, client)
        if story:
            print(f"\nAI analyst summary:\n{story}")
        print(f"\nInferred objective: {infer_objective(mal_records)}")
        print("\nRemediation playbook:")
        for step in remediation_playbook(mal_records):
            print(f"  - {step}")
        traps = find_traps(correlated, mal_ids)
        if traps:
            print(f"\nTrap detector: {len(traps)} decoy(s) cleared:")
            for t in traps:
                print(f"  - row {t['row_id']}: {t['command']}")


if __name__ == "__main__":
    main()
