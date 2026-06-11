# sentry/webapp.py
import time
from flask import Flask, request, jsonify, render_template_string
from sentry.ingest import load_csv
from sentry.scoring import score_all
from sentry.pipeline import run_full
from sentry.investigate import (build_story, name_scenario, remediation_playbook,
                                find_traps, report_card)

app = Flask(__name__)
_STATE = {}

PAGE = """<!doctype html><html><head><title>SENTRY</title>
<style>
body{background:#0b0f14;color:#cdd6f4;font-family:monospace;margin:0;padding:20px}
h1{color:#89b4fa} .funnel{font-size:18px;margin:10px 0;color:#a6e3a1}
.mal{color:#f38ba8} .ben{color:#6c7086} table{width:100%;border-collapse:collapse}
td{padding:4px 8px;border-bottom:1px solid #1e2530} button{background:#89b4fa;border:0;
padding:10px 20px;color:#0b0f14;font-weight:bold;cursor:pointer;margin-top:10px}
#inv{margin-top:20px;white-space:pre-wrap;background:#11161d;padding:15px}
</style></head><body>
<h1>SENTRY — Process Command Threat Analyst</h1>
<input type="file" id="f"><button onclick="scan()">Scan</button>
<div class="funnel" id="funnel"></div>
<table id="rows"></table>
<button id="invbtn" style="display:none" onclick="investigate()">🔍 Investigate</button>
<div id="inv"></div>
<script>
let target=20;
async function scan(){
  let fd=new FormData(); fd.append('csv',document.getElementById('f').files[0]);
  let r=await fetch('/scan',{method:'POST',body:fd}); let d=await r.json();
  document.getElementById('funnel').textContent=
    `${d.total} in → ${d.cleared} cleared → ${d.malicious.length} MALICIOUS  (⏱ ${d.elapsed}s)`;
  let t=document.getElementById('rows'); t.innerHTML='';
  for(const v of d.malicious){t.innerHTML+=
    `<tr class=mal><td>row ${v.row_id}</td><td>${v.confidence}</td>`+
    `<td>${v.mitre_technique||'-'}</td><td>${v.reason}</td></tr>`;}
  document.getElementById('invbtn').style.display='inline';
}
async function investigate(){
  let r=await fetch('/investigate'); let d=await r.json();
  document.getElementById('inv').textContent=
    d.story+"\\n\\nRemediation:\\n"+d.playbook.join("\\n")+
    "\\n\\nReport card: "+JSON.stringify(d.report_card);
}
</script></body></html>"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/scan", methods=["POST"])
def scan():
    f = request.files["csv"]
    path = "/tmp/sentry_upload.csv"
    f.save(path)
    t0 = time.perf_counter()
    rows = load_csv(path)
    scored = score_all(rows)
    correlated, verdicts = run_full(scored, target=20)
    elapsed = round(time.perf_counter() - t0, 3)
    malicious = [v.__dict__ for v in verdicts if v.verdict == "malicious"]
    _STATE["correlated"] = correlated
    _STATE["malicious_ids"] = {v["row_id"] for v in malicious}
    return jsonify({"total": len(rows), "cleared": len(rows) - len(malicious),
                    "malicious": malicious, "elapsed": elapsed})


@app.route("/investigate")
def investigate():
    correlated = _STATE.get("correlated", [])
    mal_ids = _STATE.get("malicious_ids", set())
    mal = [s for s in correlated if s.command.row_id in mal_ids]
    return jsonify({
        "scenario": name_scenario(mal),
        "story": build_story(mal),
        "playbook": remediation_playbook(mal),
        "traps": find_traps(correlated, mal_ids),
        "report_card": report_card(mal_ids, mal_ids),  # vs ground truth when available
    })


if __name__ == "__main__":
    # 5050, not 5000: macOS AirPlay Receiver occupies 5000 by default.
    app.run(port=5050, debug=True)
