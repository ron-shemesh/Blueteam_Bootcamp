# sentry/ingest.py
import base64
import csv
import re
from sentry.models import CommandRecord

_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def load_csv(path: str) -> list[CommandRecord]:
    records = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            records.append(normalize(CommandRecord(
                row_id=i,
                process_name=(row.get("process_name") or "").strip(),
                command_line=(row.get("command_line") or "").strip(),
            )))
    return records


def normalize(rec: CommandRecord) -> CommandRecord:
    rec.normalized = rec.command_line.lower()
    decoded_parts = []
    for m in _B64.findall(rec.command_line):
        try:
            text = base64.b64decode(m + "=" * (-len(m) % 4)).decode("utf-8", "ignore")
            if text.isprintable() and len(text) > 2:
                decoded_parts.append(text)
        except Exception:
            pass
    rec.decoded = " ".join(decoded_parts)
    return rec
