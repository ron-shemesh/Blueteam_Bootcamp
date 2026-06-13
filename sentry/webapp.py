# sentry/webapp.py
import csv as _csv
import os
import time
from flask import Flask, request, jsonify
from sentry.ingest import load_csv
from sentry.scoring import score_all
from sentry.pipeline import run_full, candidate_count, ai_mode
from sentry.investigate import (name_scenario, remediation_playbook, find_traps,
                                infer_objective)
from sentry.narrate import ai_investigation

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
.spinner{display:inline-block;width:12px;height:12px;border:2px solid var(--line);
border-top-color:var(--blue);border-radius:50%;animation:spin .8s linear infinite;
vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}
.status{margin:-6px 0 14px;font-size:13px}
tr.cleared td{color:var(--mut);text-decoration:line-through}
.clearnote{color:var(--mut);text-decoration:none;font-size:11px;margin-left:8px}
.aitag{font-size:10px;padding:1px 6px;border-radius:10px;background:#0e1a12;
color:var(--green);margin-left:6px}
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
      <div class="tm"><div class="n" id="f_tm">–</div><div class="l">first hit → full scan</div></div>
    </div>
    <div id="ainote" class="status"></div>
    <div class="card">
      <h3>Confirmed by rules <span class="muted" style="text-transform:none">· high-confidence, shown instantly</span></h3>
      <table><thead><tr><th>row</th><th>confidence</th><th>technique</th><th>command</th></tr></thead>
      <tbody id="rows_rules"></tbody></table>
    </div>
    <div class="card hidden" id="ai_section">
      <h3 id="ai_section_h">Found by AI <span class="muted" style="text-transform:none">· full-context review</span></h3>
      <table><thead><tr><th>row</th><th>confidence</th><th>technique</th><th>command</th></tr></thead>
      <tbody id="rows_ai"></tbody></table>
    </div>
    <button id="invbtn" class="ghost hidden" onclick="investigate()">🔍 Investigate</button>
  </div>

  <div id="inv" class="hidden">
    <div class="card" id="i_ai_card">
      <div class="tag" id="i_ai_tag"></div>
      <h3 style="margin-top:8px">Scenario</h3>
      <div class="scenario" id="i_scn"></div>
      <div class="muted" id="i_obj" style="margin-top:8px"></div>
      <div id="i_sum" style="margin-top:10px"></div></div>
    <div class="card"><h3>Trap detector</h3><div id="i_traps"></div></div>
    <div class="card"><h3>Remediation playbook</h3><ul id="i_pb"></ul></div>
    <div class="card"><h3>Red team report card</h3>
      <div class="rc"><div class="grade" id="i_grade">–</div>
        <div><div id="i_rc_line"></div><div class="muted" id="i_rc_cmt"></div></div></div></div>
  </div>
</main>
<script>
function esc(s){return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');}
function rowHTML(v,opts){
  opts=opts||{};
  const clr = opts.cleared ? ' <span class="clearnote">— AI cleared as benign</span>' : '';
  const cls = opts.cleared ? ' class="cleared"' : '';
  return `<tr${cls} title="${esc(v.reason)}"><td>${v.row_id}</td>`+
    `<td><span class="conf" style="width:${Math.round(v.confidence*70)}px"></span> ${v.confidence}</td>`+
    `<td class="tech">${esc(v.technique)||'-'}</td>`+
    `<td class="cmd">${esc(v.command)}${clr}</td></tr>`;
}
async function scan(){
  const file=document.getElementById('f').files[0];
  if(!file){document.getElementById('status').textContent='choose a CSV first';return;}
  document.getElementById('status').textContent='';
  // reset
  document.getElementById('results').classList.remove('hidden');
  document.getElementById('inv').classList.add('hidden');
  document.getElementById('invbtn').classList.add('hidden');
  document.getElementById('ai_section').classList.add('hidden');
  document.getElementById('rows_rules').innerHTML='';
  document.getElementById('rows_ai').innerHTML='';
  document.getElementById('f_cl').textContent='–';
  document.getElementById('f_mal').textContent='–';
  document.getElementById('f_tm').textContent='–';
  const note=document.getElementById('ainote');
  const mode=document.getElementById('mode'); mode.textContent='scanning…'; mode.className='chip det';
  note.innerHTML='<span class="spinner"></span> Running high-confidence rules…'; note.style.color='var(--blue)';
  try{
    // PHASE 1 — instant high-confidence rule hits
    const t0=performance.now();
    const fd1=new FormData(); fd1.append('csv',file);
    const fast=await (await fetch('/scan_fast',{method:'POST',body:fd1})).json();
    const fastSec=((performance.now()-t0)/1000).toFixed(2);
    document.getElementById('f_in').textContent=fast.total;
    document.getElementById('f_tm').innerHTML=`${fastSec}s <span class="muted">→ …</span>`;
    document.getElementById('rows_rules').innerHTML =
      fast.rules_high.map(v=>rowHTML(v)).join('') ||
      '<tr><td colspan=4 class="muted">no high-confidence rule hits — AI is reviewing…</td></tr>';
    note.innerHTML=`<span class="spinner"></span> ⚡ ${fast.rules_high.length} high-confidence detection(s) in <b>${fastSec}s</b> — AI now reviewing all ${fast.total} commands…`;

    // PHASE 2 — full AI-reviewed result
    const fd2=new FormData(); fd2.append('csv',file);
    const d=await (await fetch('/scan',{method:'POST',body:fd2})).json();
    if(d.ai_ran){ mode.textContent='AI-assisted'; mode.className='chip ai'; }
    else { mode.textContent='deterministic'; mode.className='chip det'; }
    document.getElementById('f_cl').textContent=d.cleared;
    document.getElementById('f_mal').textContent=d.malicious_count;
    document.getElementById('f_tm').innerHTML=`${fastSec}s <span class="muted">→</span> ${d.elapsed}s`;
    const clearedN=d.rules_high.filter(v=>v.cleared).length;
    // rules section, now with any AI overrules marked in place
    document.getElementById('rows_rules').innerHTML =
      d.rules_high.map(v=>rowHTML(v,{cleared:v.cleared})).join('') ||
      '<tr><td colspan=4 class="muted">no high-confidence rule hits</td></tr>';
    // second section
    const extra=d.ai_found||[];
    document.getElementById('ai_section_h').innerHTML = (d.ai_ran?'Found by AI':'Other rule detections')+
      ' <span class="muted" style="text-transform:none">· '+(d.ai_ran?'full-context review':'medium confidence')+'</span>';
    if(extra.length){
      document.getElementById('ai_section').classList.remove('hidden');
      document.getElementById('rows_ai').innerHTML=extra.map(v=>rowHTML(v)).join('');
    }
    if(d.ai_ran){
      let msg=`✓ First high-confidence hits in <b>${fastSec}s</b>; full AI review complete in <b>${d.elapsed}s</b> — ${d.malicious_count} flagged. `+
        `Rules: ${d.rules_high.length-clearedN} high-confidence hit(s)`+
        (extra.length?`, AI added ${extra.length}`:'')+(clearedN?`, AI cleared ${clearedN} rule hit(s) as benign`:'')+'.';
      note.innerHTML=msg; note.style.color='var(--green)';
    } else {
      note.innerHTML='⚙ Deterministic only — add your key to apikey.txt to enable the AI review pass.';
      note.style.color='var(--mut)';
    }
    document.getElementById('invbtn').classList.remove('hidden');
  }catch(e){
    note.innerHTML='⚠ Scan failed: '+esc(String(e)); note.style.color='var(--red)';
  }
}
async function investigate(){
  const btn=document.getElementById('invbtn'); btn.textContent='Investigating…'; btn.disabled=true;
  const d=await (await fetch('/investigate')).json();
  btn.textContent='🔍 Investigate'; btn.disabled=false;
  document.getElementById('i_scn').textContent=d.scenario;
  document.getElementById('i_obj').textContent='Objective: '+d.objective;
  document.getElementById('i_sum').textContent=d.summary||'';
  const aiCard=document.getElementById('i_ai_card');
  const aiTag=document.getElementById('i_ai_tag');
  if(d.ai_used){
    aiCard.className='card ai-summary';
    aiTag.style.color='var(--green)';
    aiTag.textContent='✦ GENERATED LIVE BY CLAUDE ('+(d.model||'')+')';
  }else{
    aiCard.className='card';
    aiTag.style.color='var(--mut)';
    aiTag.textContent='⚙ DETERMINISTIC — no LLM was called (no API key in apikey.txt, or the call failed)';
  }
  document.getElementById('i_traps').textContent=d.trap_analysis;
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


HIGH_CONF = 0.9   # deterministic score at/above which a hit is "high-confidence"


@app.route("/scan_fast", methods=["POST"])
def scan_fast():
    """Phase 1: instant, deterministic-only — return the high-confidence rule hits."""
    f = request.files["csv"]
    path = "/tmp/sentry_fast.csv"
    f.save(path)
    rows = load_csv(path)
    correlated, verdicts = run_full(score_all(rows), target=20, client=None)
    score_by = {s.command.row_id: s.risk_score for s in correlated}
    cmd_by = {s.command.row_id: s.command.command_line for s in correlated}
    vt = {v.row_id: v for v in verdicts}
    hi = sorted((rid for rid, sc in score_by.items() if sc >= HIGH_CONF),
                key=lambda r: -score_by[r])
    hits = [{"row_id": rid, "command": cmd_by[rid], "confidence": round(score_by[rid], 3),
             "technique": vt[rid].mitre_technique} for rid in hi]
    return jsonify({"total": len(rows), "rules_high": hits})


@app.route("/scan", methods=["POST"])
def scan():
    """Phase 2: full pipeline. Returns the high-confidence rule hits (with any AI
    overrule marked) and the additional commands the AI surfaced."""
    f = request.files["csv"]
    path = "/tmp/sentry_upload.csv"
    f.save(path)
    client = _client()
    rows = load_csv(path)
    cand_count = candidate_count(score_all(rows), target=20)
    mode = ai_mode(score_all(rows), target=20)
    ai_ran = bool(client)

    t0 = time.perf_counter()
    correlated, verdicts = run_full(score_all(rows), target=20, client=client)
    elapsed = round(time.perf_counter() - t0, 3)

    score_by = {s.command.row_id: s.risk_score for s in correlated}
    cmd_by = {s.command.row_id: s.command.command_line for s in correlated}
    vt = {v.row_id: v for v in verdicts}
    final_mal = {v.row_id for v in verdicts if v.verdict == "malicious"}

    high_ids = sorted((rid for rid, sc in score_by.items() if sc >= HIGH_CONF),
                      key=lambda r: -score_by[r])
    high_set = set(high_ids)
    rules_high = [{"row_id": rid, "command": cmd_by[rid],
                   "confidence": round(score_by[rid], 3),
                   "technique": vt[rid].mitre_technique, "reason": vt[rid].reason,
                   "cleared": rid not in final_mal} for rid in high_ids]
    extra = sorted((v for v in verdicts if v.verdict == "malicious" and v.row_id not in high_set),
                   key=lambda v: -v.confidence)
    ai_found = [{"row_id": v.row_id, "command": cmd_by[v.row_id], "confidence": v.confidence,
                 "technique": v.mitre_technique, "reason": v.reason} for v in extra]

    _STATE["correlated"] = correlated
    _STATE["malicious_ids"] = final_mal
    _STATE["truth_ids"] = _ground_truth(path)
    return jsonify({"total": len(rows), "malicious_count": len(final_mal),
                    "cleared": len(rows) - len(final_mal), "elapsed": elapsed,
                    "ai": client is not None, "ai_ran": ai_ran,
                    "candidates": cand_count, "mode": mode,
                    "rules_high": rules_high, "ai_found": ai_found})


def _red_grade(evaded):
    """Grade the RED team on evasion: caught everything (0 evaded) => F."""
    return ("F" if evaded == 0 else "D" if evaded <= 2 else
            "C" if evaded <= 5 else "B" if evaded <= 9 else "A")


@app.route("/investigate")
def investigate():
    correlated = _STATE.get("correlated", [])
    mal_ids = _STATE.get("malicious_ids", set())
    truth = _STATE.get("truth_ids") or mal_ids  # real labels when present
    mal = [s for s in correlated if s.command.row_id in mal_ids]
    decoys = find_traps(correlated, mal_ids)
    caught = len(mal_ids & truth)
    evaded = len(truth - mal_ids)
    grade = _red_grade(evaded)

    client = _client()
    ai = ai_investigation(mal, decoys, caught, evaded, client)
    fallback_comment = ("Red team report card: total wipeout — we caught every single "
                        "command. Did you even try to hide?" if evaded == 0 else
                        f"Red team slipped {evaded} past us — not bad, but we still see you.")
    return jsonify({
        "scenario": ai["scenario"] if ai else name_scenario(mal),
        "objective": ai["objective"] if ai else infer_objective(mal),
        "summary": ai["summary"] if ai else None,
        "trap_analysis": ai["trap_analysis"] if ai else
            (f"{len(decoys)} decoy(s) cleared." if decoys else "No decoys were planted."),
        "playbook": ai["playbook"] if ai else remediation_playbook(mal),
        "report_card": {"caught": caught, "evaded": evaded, "grade": grade,
                        "comment": ai["report_comment"] if ai else fallback_comment},
        "ai_used": ai is not None,
        "model": getattr(client, "model", None),
    })


if __name__ == "__main__":
    # 5050, not 5000: macOS AirPlay Receiver occupies 5000 by default.
    app.run(port=5050, debug=True)
