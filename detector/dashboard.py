"""Generate a self-contained HTML dashboard (no server, no dependencies) from alerts."""
import json
from collections import Counter

TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Detection Dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0f1419;--card:#1a212b;--fg:#e6edf3;--mut:#8b98a5;--bd:#2b3644;--critical:#ff5c5c;--high:#ff9f43;--medium:#f1c40f;--low:#5dade2}
@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--card:#fff;--fg:#1f2328;--mut:#59636e;--bd:#d0d7de}}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px}
.card h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:0 0 8px}
.big{font-size:28px;font-weight:700}
.bar{display:flex;align-items:center;gap:8px;margin:3px 0;font-size:13px}
.bar span.l{width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar i{display:block;height:10px;background:#4c9aff;border-radius:3px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd);font-size:13px;vertical-align:top}
tr.row{cursor:pointer}tr.row:hover{background:rgba(127,127,127,.12)}
.sev{padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#111}
.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}
pre{background:rgba(127,127,127,.12);padding:8px;border-radius:6px;overflow:auto;margin:6px 0 0;font-size:12px}
select{background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:6px;padding:4px}
.tl{display:flex;align-items:flex-end;gap:2px;height:60px}.tl i{flex:1;background:#4c9aff;min-height:2px;border-radius:2px 2px 0 0}
.wrap{overflow-x:auto}
</style></head><body>
<h1>Authentication Detection Dashboard</h1><div class="sub" id="sub"></div>
<div class="grid">
<div class="card"><h2>Alerts</h2><div class="big" id="total"></div><div id="sevs"></div></div>
<div class="card"><h2>By rule</h2><div id="byrule"></div></div>
<div class="card"><h2>Top source IPs</h2><div id="byip"></div></div>
<div class="card"><h2>Alerts per day</h2><div class="tl" id="tl"></div><div class="sub" id="tlr"></div></div>
</div>
<div class="card"><h2>Alert detail <select id="f"><option value="">all rules</option></select></h2>
<div class="wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>MITRE</th><th>Source</th><th>Why it fired</th></tr></thead><tbody id="rows"></tbody></table></div></div>
<script>
const A=__DATA__,META=__META__;
const $=id=>document.getElementById(id),esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
$('sub').textContent=META.events+' events analysed from '+META.source+' - '+A.length+' alerts';
$('total').textContent=A.length;
function bars(el,pairs){const m=Math.max(1,...pairs.map(p=>p[1]));el.innerHTML=pairs.map(p=>'<div class="bar"><span class="l" title="'+esc(p[0])+'">'+esc(p[0])+'</span><i style="width:'+(p[1]/m*100)+'px"></i>'+p[1]+'</div>').join('')}
const cnt=(k)=>{const c={};A.forEach(a=>{const v=k(a);c[v]=(c[v]||0)+1});return Object.entries(c).sort((x,y)=>y[1]-x[1])};
bars($('byrule'),cnt(a=>a.rule_id+' '+a.name));
bars($('byip'),cnt(a=>a.src_ip).slice(0,8));
$('sevs').innerHTML=cnt(a=>a.severity).map(p=>'<span class="sev '+p[0]+'">'+p[0]+' '+p[1]+'</span> ').join('');
const days=cnt(a=>a.ts.slice(0,10)).sort((x,y)=>x[0]<y[0]?-1:1),mx=Math.max(1,...days.map(d=>d[1]));
$('tl').innerHTML=days.map(d=>'<i title="'+d[0]+': '+d[1]+'" style="height:'+d[1]/mx*100+'%"></i>').join('');
$('tlr').textContent=days.length?days[0][0]+' to '+days[days.length-1][0]:'';
[...new Set(A.map(a=>a.rule_id))].sort().forEach(r=>{const o=document.createElement('option');o.value=r;o.textContent=r;$('f').appendChild(o)});
function draw(){const f=$('f').value;$('rows').innerHTML=A.filter(a=>!f||a.rule_id===f).map((a,i)=>
'<tr class="row" onclick="this.nextElementSibling.hidden=!this.nextElementSibling.hidden"><td>'+a.ts.replace('T',' ')+'</td><td><span class="sev '+a.severity+'">'+a.severity+'</span></td><td>'+a.rule_id+' '+esc(a.name)+'</td><td>'+a.mitre+'</td><td>'+esc(a.src_ip)+'</td><td>'+esc(a.reason)+'</td></tr>'+
'<tr hidden><td colspan="6"><b>Evidence ('+a.evidence.length+' log lines)</b><pre>'+esc(a.evidence.join('\\n'))+'</pre></td></tr>').join('')}
$('f').onchange=draw;draw();
</script></body></html>"""


def render(alerts, events_count, source):
    data = json.dumps([a.to_dict() for a in alerts]).replace("</", "<\\/")
    meta = json.dumps({"events": events_count, "source": source}).replace("</", "<\\/")
    return TEMPLATE.replace("__DATA__", data).replace("__META__", meta)
