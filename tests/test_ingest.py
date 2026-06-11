from sentry.ingest import load_csv, normalize

def test_load_csv_reads_rows_and_strips_label():
    rows = load_csv("tests/fixtures/mini.csv")
    assert len(rows) == 10
    assert rows[0].process_name == "cmd.exe"
    assert rows[0].command_line == "whoami"
    assert rows[0].row_id == 0

def test_normalize_lowercases_and_decodes_base64():
    # "SGVsbG8gV29ybGQgVGVzdA==" (22 b64 chars) decodes to "Hello World Test".
    # Threshold is intentionally high so ordinary words are not treated as base64.
    cmd = "powershell -enc SGVsbG8gV29ybGQgVGVzdA=="
    rec = normalize_record("powershell.exe", cmd)
    assert rec.normalized == cmd.lower()
    assert "hello world test" in rec.decoded.lower()

def normalize_record(proc, cmd):
    from sentry.models import CommandRecord
    r = CommandRecord(row_id=0, process_name=proc, command_line=cmd)
    return normalize(r)
