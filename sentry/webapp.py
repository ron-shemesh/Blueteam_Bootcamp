# sentry/webapp.py
import csv as _csv
import os
import time
from flask import Flask, request, jsonify
from sentry.ingest import load_csv
from sentry.scoring import score_all
from sentry.pipeline import run_full
from sentry.investigate import (name_scenario, remediation_playbook, find_traps,
                                report_card, infer_objective, order_by_killchain,
                                _tac, _technique)
from sentry.narrate import ai_narrative

app = Flask(__name__)
_STATE = {}


def _client():
    """AI client when a key is resolvable (env or apikey.txt/.env), else None."""
    from sentry.apikey import load_api_key
    key = load_api_key()
    if not key:
        return None
    os.environ["ANTHROPIC_API_KEY"] = key  # so AnthropicClient picks it up
    try:
        from sentry.ai_confirm import AnthropicClient
        return AnthropicClient()
    except Exception:
        return None


def _ground_truth(path):
    """Read malicious row indices from a 'label' column if the CSV has one."""
    truth = set()
    try:
        with open(path, newline="", encoding="utf-8") as f:
            for i, row in enumerate(_csv.DictReader(f)):
                if (row.get("label") or "").strip().lower() == "malicious":
                    truth.add(i)
    except Exception:
        pass
    return truth


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>SENTRY — SOC Console</title>
<style>
:root{--bg:#0b0f14;--panel:#11161d;--line:#1e2733;--txt:#cdd6f4;--mut:#7a8699;
--blue:#89b4fa;--green:#a6e3a1;--red:#f38ba8;--yellow:#f9e2af;--mauve:#cba6f7}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--txt);font-family:'SF Mono',Menlo,monospace;
margin:0;padding:0;line-height:1.5}
header{padding:18px 28px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:14px}
header h1{font-size:20px;margin:0;color:var(--blue);letter-spacing:1px}
header .sub{color:var(--mut);font-size:13px}
.chip{margin-left:auto;font-size:12px;padding:4px 10px;border-radius:20px;
border:1px solid var(--line)}
.chip.ai{color:var(--green);border-color:var(--green)}
.chip.det{color:var(--mut)}
main{padding:24px 28px;max-width:1100px;margin:0 auto}
.bar{display:flex;gap:12px;align-items:center;margin-bottom:18px}
input[type=file]{color:var(--mut)}
button{background:var(--blue);border:0;padding:10px 18px;color:#0b0f14;
font-weight:700;cursor:pointer;border-radius:6px;font-family:inherit}
button.ghost{background:transparent;color:var(--blue);border:1px solid var(--blue)}
button:disabled{opacity:.4;cursor:default}
.funnel{display:flex;gap:0;margin:18px 0;border:1px solid var(--line);border-radius:8px;
overflow:hidden}
.funnel div{flex:1;padding:14px;text-align:center}
.funnel .n{font-size:26px;font-weight:700}
.funnel .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:1px}
.funnel .in{background:#0e151d}.funnel .cl{background:#0e1a12;color:var(--green)}
.funnel .mal{background:#1c0f14;color:var(--red)}
.funnel .tm{background:#15101d;color:var(--mauve)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--mut);font-weight:400;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.tech{color:var(--yellow)}
.conf{display:inline-block;height:8px;background:var(--red);border-radius:4px;vertical-align:middle}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:18px 20px;margin:16px 0}
.card h3{margin:0 0 12px;font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--blue)}
.scenario{font-size:22px;color:var(--yellow);font-weight:700}
.ai-summary{border-left:3px solid var(--green);background:#0e1a12}
.ai-summary .tag{color:var(--green);font-size:11px;letter-spacing:1px}
.step{display:flex;gap:12px;padding:8px 0;border-bottom:1px dashed var(--line)}
.step:last-child{border-bottom:0}
.step .num{color:var(--mut);width:24px}
.tac{display:inline-block;font-size:11px;padding:2px 8px;border-radius:12px;
background:#15202e;color:var(--blue);margin-right:8px;white-space:nowrap}
.cmd{color:var(--txt);word-break:break-all}
.muted{color:var(--mut)}
.grade{font-size:64px;font-weight:800;line-height:1}
.gA{color:var(--green)}.gB{color:#94e2d5}.gC{color:var(--yellow)}.gD{color:#fab387}.gF{color:var(--red)}
.rc{display:flex;gap:24px;align-items:center}
li{margin:4px 0}
.hidden{display:none}
</style></head><body>
<header>
  <h1>🛡 SENTRY</h1><span class="sub">Process-Command Threat Analyst</span>
  <span id="mode" class="chip det">idle</span>
</header>
<main>
  <div class="bar">
    <input type="file" id="f" accept=".csv">
    <button onclick="scan()">Scan</button>
    <span id="status" class="muted"></span>
  </div>

  <div id="results" class="hidden">
    <div class="funnel">
      <div class="in"><div class="n" id="f_in">0</div><div class="l">commands in</div></div>
      <div class="cl"><div class="n" id="f_cl">0</div><div class="l">cleared benign</div></div>
      <div class="mal"><div class="n" id="f_mal">0</div><div class="l">flagged malicious</div></div>
      <div class="tm"><div class="n" id="f_tm">0s</div><div class="l">scan time</div></div>
    </div>
    <div class="card">
      <h3>Flagged commands</h3>
      <table><thead><tr><th>row</th><th>confidence</th><th>technique</th><th>why flagged</th></tr></thead>
      <tbody id="rows"></tbody></table>
    </div>
    <button id="invbtn" class="ghost" onclick="investigate()">🔍 Investigate</button>
  </div>

  <div id="inv" class="hidden">
    <div class="card"><h3>Scenario</h3><div class="scenario" id="i_scn"></div>
      <div class="muted" id="i_obj" style="margin-top:8px"></div></div>
    <div class="card" id="i_ai_card">
      <div class="tag" id="i_ai_tag"></div>
      <div id="i_ai" style="margin-top:8px"></div></div>
    <div class="card"><h3>Reconstructed kill chain</h3><div id="i_kc"></div></div>
    <div class="card"><h3>Trap detector</h3><div id="i_traps"></div></div>
    <div class="card"><h3>Remediation playbook</h3><ul id="i_pb"></ul></div>
    <div class="card"><h3>Red team report card</h3>
      <div class="rc"><div class="grade" id="i_grade">–</div>
        <div><div id="i_rc_line"></div><div class="muted" id="i_rc_cmt"></div></div></div></div>
  </div>
</main>
<script>
function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');}
async function scan(){
  const file=document.getElementById('f').files[0];
  if(!file){document.getElementById('status').textContent='choose a CSV first';return;}
  document.getElementById('status').textContent='scanning…';
  const fd=new FormData(); fd.append('csv',file);
  const d=await (await fetch('/scan',{method:'POST',body:fd})).json();
  document.getElementById('status').textContent='';
  const mode=document.getElementById('mode');
  mode.textContent = d.ai ? 'AI-assisted' : 'deterministic';
  mode.className = 'chip ' + (d.ai ? 'ai':'det');
  document.getElementById('f_in').textContent=d.total;
  document.getElementById('f_cl').textContent=d.cleared;
  document.getElementById('f_mal').textContent=d.malicious.length;
  document.getElementById('f_tm').textContent=d.elapsed+'s';
  const rows=d.malicious.slice().sort((a,b)=>b.confidence-a.confidence);
  document.getElementById('rows').innerHTML=rows.map(v=>
    `<tr><td>${v.row_id}</td>`+
    `<td><span class="conf" style="width:${Math.round(v.confidence*70)}px"></span> ${v.confidence}</td>`+
    `<td class="tech">${esc(v.mitre_technique)||'-'}</td>`+
    `<td>${esc(v.reason)}</td></tr>`).join('');
  document.getElementById('results').classList.remove('hidden');
  document.getElementById('inv').classList.add('hidden');
}
async function investigate(){
  const btn=document.getElementById('invbtn'); btn.textContent='Investigating…'; btn.disabled=true;
  const d=await (await fetch('/investigate')).json();
  btn.textContent='🔍 Investigate'; btn.disabled=false;
  document.getElementById('i_scn').textContent=d.scenario;
  document.getElementById('i_obj').textContent='Objective: '+d.objective;
  const aiCard=document.getElementById('i_ai_card');
  const aiTag=document.getElementById('i_ai_tag');
  if(d.ai_used){
    aiCard.className='card ai-summary';
    aiTag.style.color='var(--green)';
    aiTag.textContent='✦ AI ANALYST SUMMARY — generated live by Claude ('+(d.model||'')+')';
    document.getElementById('i_ai').textContent=d.ai_summary;
  }else{
    aiCard.className='card';
    aiTag.style.color='var(--mut)';
    aiTag.textContent='⚙ DETERMINISTIC — no LLM was called (no API key in apikey.txt, or the call failed)';
    document.getElementById('i_ai').textContent='Add your key to apikey.txt and re-Investigate to have Claude write the narrative.';
  }
  document.getElementById('i_kc').innerHTML=d.killchain.map(s=>
    `<div class="step"><span class="num">${s.step}</span>`+
    `<span><span class="tac">${esc(s.tactic)}</span>`+
    `<span class="tech">${esc(s.technique)||''}</span><br>`+
    `<span class="cmd">${esc(s.command)}</span></span></div>`).join('');
  document.getElementById('i_traps').innerHTML = d.traps.length
    ? d.traps.map(t=>`<div class="step"><span class="cmd">row ${t.row_id}: ${esc(t.command)}</span><br><span class="muted">${esc(t.why_cleared)}</span></div>`).join('')
    : '<span class="muted">No decoys — every suspicious-looking command was either confirmed or genuinely benign.</span>';
  document.getElementById('i_pb').innerHTML=d.playbook.map(p=>`<li>${esc(p)}</li>`).join('');
  const rc=d.report_card; const g=rc.grade;
  const ge=document.getElementById('i_grade'); ge.textContent=g; ge.className='grade g'+g;
  document.getElementById('i_rc_line').textContent=
    `Caught ${rc.caught} · Evaded ${rc.evaded} · Recall ${Math.round(rc.recall*100)}%`;
  document.getElementById('i_rc_cmt').textContent=rc.comment;
  document.getElementById('inv').classList.remove('hidden');
}
</script></body></html>"""


@app.route("/")
def index():
    return PAGE


@app.route("/scan", methods=["POST"])
def scan():
    f = request.files["csv"]
    path = "/tmp/sentry_upload.csv"
    f.save(path)
    client = _client()
    t0 = time.perf_counter()
    rows = load_csv(path)
    scored = score_all(rows)
    correlated, verdicts = run_full(scored, target=20, client=client)
    elapsed = round(time.perf_counter() - t0, 3)
    malicious = [v.__dict__ for v in verdicts if v.verdict == "malicious"]
    _STATE["correlated"] = correlated
    _STATE["malicious_ids"] = {v["row_id"] for v in malicious}
    _STATE["truth_ids"] = _ground_truth(path)
    return jsonify({"total": len(rows), "cleared": len(rows) - len(malicious),
                    "malicious": malicious, "elapsed": elapsed,
                    "ai": client is not None})


@app.route("/investigate")
def investigate():
    correlated = _STATE.get("correlated", [])
    mal_ids = _STATE.get("malicious_ids", set())
    truth = _STATE.get("truth_ids") or mal_ids  # use real labels when present
    mal = [s for s in correlated if s.command.row_id in mal_ids]
    ordered = order_by_killchain(mal)
    killchain = [{"step": i + 1, "tactic": _tac(s), "technique": _technique(s),
                  "command": s.command.command_line} for i, s in enumerate(ordered)]
    client = _client()
    ai_summary = ai_narrative(mal, client)
    return jsonify({
        "scenario": name_scenario(mal),
        "ai_summary": ai_summary,
        "ai_used": ai_summary is not None,
        "model": getattr(client, "model", None),
        "killchain": killchain,
        "objective": infer_objective(mal),
        "playbook": remediation_playbook(mal),
        "traps": find_traps(correlated, mal_ids),
        "report_card": report_card(mal_ids, truth),
    })


if __name__ == "__main__":
    # 5050, not 5000: macOS AirPlay Receiver occupies 5000 by default.
    app.run(port=5050, debug=True)
