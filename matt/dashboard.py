"""matt.dashboard -- a tiny local web dashboard for live findings.

Serves one page (and a findings JSON endpoint) from the standard library's
http.server, so it adds no dependency. It reads every matt_analysis.json under a
directory and shows the credentials as a live, auto-refreshing table -- point it
at the same directory `matt --watch` writes to and the page fills in as captures
land. Binds to localhost by default.
"""

from __future__ import annotations

import glob
import html
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = ["collect_findings", "PAGE", "serve"]


def collect_findings(root: str) -> dict:
    """Aggregate findings from every matt_analysis.json under ``root``. Returns
    {"generated": ..., "rows": [...]} with one row per credential, de-duplicated
    on (host, target, user, type, candidate)."""
    rows, seen = [], set()
    files = sorted(glob.glob(os.path.join(root, "**", "*analysis*.json"),
                             recursive=True), key=lambda p: -os.path.getmtime(p))
    for path in files[:200]:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        analysis = data.get("analysis", data)
        for f in analysis.get("findings", []):
            if not (f.get("credential_bearing") or f.get("hashcat_mode")
                    or f.get("kind") in ("tls-sni", "snmpv3", "quic")):
                continue
            secret = f.get("plaintext") or ""
            if not secret and not f.get("hashcat_mode"):
                cand, user = f.get("candidate", ""), f.get("username", "")
                secret = cand[len(user) + 1:] if user and cand.startswith(user + ":") else ""
            key = (f.get("host"), f.get("target"), f.get("username"),
                   f.get("kind"), f.get("candidate"))
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "host": f.get("host") or "the wire",
                "target": f.get("target") or "",
                "user": f.get("username") or "",
                "type": f.get("kind") or "",
                "secret": secret,
                "mode": f.get("hashcat_mode") or "",
                "source": os.path.basename(path),
            })
    return {"generated": _now(), "count": len(rows), "rows": rows}


def _now():
    import datetime
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>MATT - live findings</title><style>
:root{--bg:#0b0b0d;--fg:#e8e8ea;--mut:#8a8a92;--card:#15151a;--grn:#39d353;--red:#ff5b5b;--acc:#60a5fa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,Menlo,Consolas,monospace}
header{padding:14px 18px;border-bottom:1px solid #26262e;display:flex;gap:14px;align-items:baseline;flex-wrap:wrap}
h1{font-size:16px;margin:0;letter-spacing:.14em}.mut{color:var(--mut)}.acc{color:var(--acc)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 14px;border-bottom:1px solid #1e1e26;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:34ch}
th{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--bg)}
tr:hover td{background:#14141a}.grn{color:var(--grn);font-weight:600}.red{color:var(--red)}
.pill{font-size:11px;padding:1px 7px;border-radius:999px;background:#20202a;color:var(--mut)}
.empty{padding:40px;text-align:center;color:var(--mut)}</style></head><body>
<header><h1>M A T T</h1><span class=mut>live findings</span>
<span class=mut>count <b id=n class=acc>0</b></span>
<span class=mut>updated <span id=t>-</span></span>
<span class=mut>auto-refresh 3s</span></header>
<table><thead><tr><th>HOST</th><th>TARGET</th><th>USER</th><th>TYPE</th><th>SECRET / CRACKED</th></tr></thead>
<tbody id=b></tbody></table><div id=e class=empty>waiting for captures...</div>
<script>
const esc=s=>(s||'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function tick(){try{const r=await fetch('findings.json',{cache:'no-store'});const d=await r.json();
document.getElementById('n').textContent=d.count;document.getElementById('t').textContent=d.generated;
const b=document.getElementById('b');const e=document.getElementById('e');
if(!d.rows.length){b.innerHTML='';e.style.display='block';return;}e.style.display='none';
b.innerHTML=d.rows.map(x=>{const sec=x.secret?`<span class=grn>${esc(x.secret)}</span>`:(x.mode?`<span class=red>-m ${esc(x.mode)}</span>`:'-');
return `<tr><td>${esc(x.host)}</td><td>${esc(x.target)}</td><td>${esc(x.user)}</td><td><span class=pill>${esc(x.type)}</span></td><td>${sec}</td></tr>`}).join('');
}catch(_){}}
tick();setInterval(tick,3000);
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    root = "."

    def log_message(self, *a):
        pass  # quiet

    def _send(self, code, body, ctype):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = re.sub(r"\?.*$", "", self.path)
        if path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif path == "/findings.json":
            self._send(200, json.dumps(collect_findings(self.root)),
                       "application/json")
        else:
            self._send(404, "not found", "text/plain")


def serve(root: str, port: int = 8899, host: str = "127.0.0.1"):
    """Serve the dashboard for findings under ``root`` until interrupted."""
    handler = type("Handler", (_Handler,), {"root": os.path.abspath(root)})
    httpd = ThreadingHTTPServer((host, port), handler)
    return httpd
