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
    args = ap.parse_args()

    t0 = time.perf_counter()
    rows = load_csv(args.csv)
    from sentry.pipeline import run_deterministic
    scored = score_all(rows)
    _, verdicts = run_deterministic(scored, target=args.target)
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


if __name__ == "__main__":
    main()
