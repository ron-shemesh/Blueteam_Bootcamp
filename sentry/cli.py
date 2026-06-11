# sentry/cli.py
import argparse
import json
import time
from sentry.ingest import load_csv
from sentry.scoring import score_all


def main():
    ap = argparse.ArgumentParser(description="SENTRY blue-team detector")
    ap.add_argument("csv", help="path to process-command CSV")
    ap.add_argument("--target", type=int, default=20, help="known malicious count")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--ai", action="store_true", help="enable AI confirmation")
    ap.add_argument("--investigate", action="store_true",
                    help="run on-demand investigation (off the clock)")
    args = ap.parse_args()

    t0 = time.perf_counter()
    rows = load_csv(args.csv)
    scored = score_all(rows)
    client = None
    if args.ai:
        from sentry.ai_confirm import AnthropicClient
        client = AnthropicClient()
    from sentry.pipeline import run_full
    correlated, verdicts = run_full(scored, target=args.target, client=client)
    elapsed = time.perf_counter() - t0

    malicious = [v for v in verdicts if v.verdict == "malicious"]
    if args.json:
        print(json.dumps([v.__dict__ for v in malicious], indent=2))
    else:
        print(f"Scan complete in {elapsed:.3f}s — {len(rows)} commands, "
              f"{len(malicious)} flagged malicious\n")
        for v in sorted(malicious, key=lambda v: v.confidence, reverse=True):
            print(f"  row {v.row_id:>3} | conf {v.confidence:.2f} | "
                  f"{v.mitre_technique or '-':<11} | {v.reason}")

    if getattr(args, "investigate", False):
        from sentry.investigate import (build_story, remediation_playbook,
                                        find_traps, infer_objective)
        mal_records = [s for s in correlated if s.command.row_id in
                       {v.row_id for v in malicious}]
        print("\n" + "=" * 60 + "\nINVESTIGATION\n" + "=" * 60)
        print(build_story(mal_records))
        print(f"\nInferred objective: {infer_objective(mal_records)}")
        print("\nRemediation playbook:")
        for step in remediation_playbook(mal_records):
            print(f"  - {step}")
        traps = find_traps(correlated)
        if traps:
            print(f"\nTrap detector: {len(traps)} decoy(s) cleared:")
            for t in traps:
                print(f"  - row {t['row_id']}: {t['command']}")


if __name__ == "__main__":
    main()
