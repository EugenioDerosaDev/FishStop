"""
components/email_globe.py — Globo 3D interattivo del percorso email.

Visualizza la catena Received hop-by-hop su un mappamondo 3D rotante
costruito con D3.js (geoOrthographic) senza dipendenze Python aggiuntive.
Il globo ruota automaticamente, si può trascinare con il mouse e mostra
archi animati tra gli hop con popup dettagliati.

Utilizzo in app.py:
    from src.components.email_globe import render_email_globe

    with st.expander("🌍 Percorso geografico email", expanded=True):
        render_email_globe(soc, validator)
"""

import re
import json
from concurrent.futures import ThreadPoolExecutor

import streamlit as st
import streamlit.components.v1 as components


# ── Helpers ────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    return bool(re.match(
        r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1$|fc|fd)",
        ip or "",
    ))


def _score_to_risk(score) -> str:
    if score is None:
        return "unknown"
    s = int(score)
    if s >= 75:  return "high"
    if s >= 25:  return "medium"
    return "low"


def _risk_color(risk: str) -> str:
    return {
        "high":    "#E24B4A",
        "medium":  "#EF9F27",
        "low":     "#1D9E75",
        "unknown": "#888780",
    }[risk]


def _geo_coords(geo: dict):
    if geo.get("status") != "ok":
        return None
    lat, lon = geo.get("lat"), geo.get("lon")
    if lat is None or lon is None:
        return None
    return float(lat), float(lon)


# ── HTML del globo ─────────────────────────────────────────────────────────

def _build_globe_html(hops_data: list[dict]) -> str:
    """
    Genera l'HTML completo del globo D3 con i dati degli hop iniettati
    come JSON inline. Nessuna dipendenza Python oltre a streamlit.
    """

    # Serializza i dati hop per JavaScript
    js_hops = []
    for h in hops_data:
        coords = h["coords"]
        if coords is None:
            continue
        geo  = h["geo"]
        rep  = h["rep"]
        score = rep.get("abuseConfidenceScore") if rep.get("status") == "ok" else None
        risk  = _score_to_risk(score)
        hop   = h["hop"]

        js_hops.append({
            "lat":       coords[0],
            "lon":       coords[1],
            "role":      h["role"],
            "color":     _risk_color(risk),
            "risk":      risk,
            "ip":        hop.get("sender_ip") or "—",
            "fromHost":  hop.get("from_host") or "—",
            "byHost":    hop.get("by_host") or "—",
            "tls":       hop.get("tls_version") or "—",
            "city":      geo.get("city", ""),
            "country":   geo.get("country", ""),
            "isp":       geo.get("isp", ""),
            "isProxy":   bool(geo.get("is_proxy")),
            "isHosting": bool(geo.get("is_hosting")),
            "score":     score,
            "roleLabel": {
                "sender":    "Closest to sender",
                "injection": "Injection server",
                "relay":     "Relay intermedio",
                "recipient": "Closest to recipient",
            }.get(h["role"], h["role"]),
        })

    # I Received header sono in ordine inverso: [0]=recipient … [-1]=sender.
    # Invertiamo così gli archi sul globo vanno da sender → recipient,
    # che è il percorso reale dell'email.
    js_hops = list(reversed(js_hops))
    hops_json = json.dumps(js_hops)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#0d1117; font-family:sans-serif; overflow:hidden; }}
  #globe-wrap {{
    width:100%; height:520px;
    display:flex; align-items:center; justify-content:center;
    position:relative;
  }}
  canvas {{ cursor:grab; }}
  canvas:active {{ cursor:grabbing; }}

  #tooltip {{
    position:absolute; pointer-events:none;
    background:rgba(13,17,23,.92); border:1px solid rgba(255,255,255,.12);
    border-radius:8px; padding:10px 14px;
    font-size:12px; color:#e6edf3; line-height:1.7;
    max-width:240px; display:none; z-index:99;
  }}
  #tooltip .tt-title {{
    font-weight:600; font-size:13px;
    border-bottom:1px solid rgba(255,255,255,.12);
    padding-bottom:5px; margin-bottom:6px;
  }}
  #tooltip .tt-row {{ display:flex; gap:8px; }}
  #tooltip .tt-label {{ color:#8b949e; min-width:60px; }}
  #tooltip .risk-high    {{ color:#E24B4A; font-weight:600; }}
  #tooltip .risk-medium  {{ color:#EF9F27; font-weight:600; }}
  #tooltip .risk-low     {{ color:#1D9E75; font-weight:600; }}
  #tooltip .risk-unknown {{ color:#888780; }}

  #legend {{
    position:absolute; bottom:14px; left:14px;
    background:rgba(13,17,23,.8); border:1px solid rgba(255,255,255,.1);
    border-radius:7px; padding:8px 12px;
    font-size:11px; color:#8b949e; line-height:2;
  }}
  #legend span {{
    display:inline-block; width:9px; height:9px;
    border-radius:50%; margin-right:5px; vertical-align:middle;
  }}

  #controls {{
    position:absolute; bottom:14px; right:14px;
    display:flex; flex-direction:column; gap:6px;
  }}
  #controls button {{
    background:rgba(13,17,23,.8); border:1px solid rgba(255,255,255,.15);
    border-radius:6px; color:#c9d1d9; font-size:12px;
    padding:5px 10px; cursor:pointer; transition:background .15s;
  }}
  #controls button:hover {{ background:rgba(255,255,255,.08); }}
</style>
</head>
<body>
<div id="globe-wrap">
  <canvas id="globe"></canvas>
  <div id="tooltip"></div>
  <div id="legend">
    <div><span style="background:#E24B4A"></span>Alto rischio / origine</div>
    <div><span style="background:#EF9F27"></span>Medio rischio / relay</div>
    <div><span style="background:#1D9E75"></span>Pulito / destinatario</div>
    <div><span style="background:#888780"></span>Sconosciuto</div>
  </div>
  <div id="controls">
    <button id="btn-play" title="Pausa/riprendi rotazione">&#9646;&#9646;</button>
    <button id="btn-fit"  title="Centra sul percorso">&#x2316;</button>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js"></script>
<script>
const HOPS = {hops_json};

const W = document.getElementById('globe-wrap').offsetWidth;
const H = 520;
const R = Math.min(W, H) / 2 - 20;

const canvas = document.getElementById('globe');
canvas.width  = W;
canvas.height = H;
const ctx = canvas.getContext('2d');

const proj = d3.geoOrthographic()
  .scale(R)
  .translate([W/2, H/2])
  .clipAngle(90);

const path = d3.geoPath(proj, ctx);

let world = null;
let rotating = true;
let rotateSpeed = 0.18;
let lambda = 0, phi = 0;
let dragStart = null, dragLambda, dragPhi;
let hoverIdx = null;
let animFrame = null;

const tooltip  = document.getElementById('tooltip');
const btnPlay  = document.getElementById('btn-play');
const btnFit   = document.getElementById('btn-fit');

function toRad(d) {{ return d * Math.PI / 180; }}
function toDeg(r) {{ return r * 180 / Math.PI; }}

function greatCirclePoints(lon1, lat1, lon2, lat2, n) {{
  const pts = [];
  for (let i = 0; i <= n; i++) {{
    const t = i / n;
    const p = d3.geoInterpolate([lon1, lat1], [lon2, lat2])(t);
    pts.push(p);
  }}
  return pts;
}}

function drawGlobe() {{
  ctx.clearRect(0, 0, W, H);

  ctx.beginPath();
  path({{type:'Sphere'}});
  ctx.fillStyle = '#1a2332';
  ctx.fill();

  ctx.beginPath();
  path({{type:'Sphere'}});
  ctx.strokeStyle = 'rgba(255,255,255,.06)';
  ctx.lineWidth = 0.8;
  ctx.stroke();

  if (world) {{
    ctx.beginPath();
    path(topojson.feature(world, world.objects.land));
    ctx.fillStyle = '#243447';
    ctx.fill();

    ctx.beginPath();
    path(topojson.mesh(world, world.objects.countries, (a,b) => a !== b));
    ctx.strokeStyle = 'rgba(255,255,255,.08)';
    ctx.lineWidth = 0.4;
    ctx.stroke();
  }}

  ctx.beginPath();
  path(d3.geoGraticule()());
  ctx.strokeStyle = 'rgba(255,255,255,.04)';
  ctx.lineWidth = 0.3;
  ctx.stroke();

  // Archi tra hop consecutivi
  for (let i = 0; i < HOPS.length - 1; i++) {{
    const a = HOPS[i], b = HOPS[i+1];
    const pts = greatCirclePoints(a.lon, a.lat, b.lon, b.lat, 60);
    const geo = {{type:'LineString', coordinates: pts}};

    ctx.beginPath();
    path(geo);
    ctx.strokeStyle = a.color;
    ctx.lineWidth = 1.8;
    ctx.globalAlpha = 0.7;
    ctx.setLineDash([6, 10]);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.globalAlpha = 1;
  }}

  // Marker hop
  HOPS.forEach((h, i) => {{
    const px = proj([h.lon, h.lat]);
    if (!px) return;

    // Verifica se è sul lato visibile
    const visible = d3.geoContains(
      {{type:'Sphere', coordinates:[]}},
      [h.lon, h.lat]
    );
    if (!visible && dotProduct(h.lon, h.lat) < 0) return;

    const isHover = hoverIdx === i;
    const r = isHover ? 11 : 8;

    ctx.beginPath();
    ctx.arc(px[0], px[1], r + 3, 0, 2*Math.PI);
    ctx.fillStyle = h.color + '30';
    ctx.fill();

    ctx.beginPath();
    ctx.arc(px[0], px[1], r, 0, 2*Math.PI);
    ctx.fillStyle = h.color;
    ctx.fill();
    ctx.strokeStyle = 'rgba(255,255,255,.8)';
    ctx.lineWidth = isHover ? 2 : 1.5;
    ctx.stroke();

    // Etichetta
    const roleToLbl = {{sender:'S', injection:'I', relay:'R', recipient:'D'}};
    const lbl = roleToLbl[h.role] || String(i+1);

    ctx.fillStyle = '#fff';
    ctx.font = `bold ${{isHover ? 11 : 10}}px sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(lbl, px[0], px[1]);

    // City label
    if (h.city && isHover) {{
      const label = h.city + (h.country ? ', '+h.country : '');
      ctx.font = '11px sans-serif';
      ctx.fillStyle = '#e6edf3';
      ctx.textAlign = 'center';
      ctx.fillText(label, px[0], px[1] - r - 8);
    }}
  }});
}}

function dotProduct(lon, lat) {{
  const r = toRad;
  const [lam, ph] = proj.rotate();
  return Math.cos(r(lat)) * Math.cos(r(ph)) * Math.cos(r(lon) - r(-lam))
       + Math.sin(r(lat)) * Math.sin(r(ph));
}}

let lastTime = null;
let arcOffset = 0;

function animate(ts) {{
  if (!lastTime) lastTime = ts;
  const dt = ts - lastTime;
  lastTime = ts;

  if (rotating) {{
    lambda += rotateSpeed * dt / 16;
    proj.rotate([lambda, phi]);
  }}

  drawGlobe();
  animFrame = requestAnimationFrame(animate);
}}

// Drag
canvas.addEventListener('mousedown', e => {{
  rotating = false;
  dragStart = [e.clientX, e.clientY];
  const r = proj.rotate();
  dragLambda = r[0]; dragPhi = r[1];
}});

window.addEventListener('mousemove', e => {{
  if (dragStart) {{
    const dx = e.clientX - dragStart[0];
    const dy = e.clientY - dragStart[1];
    lambda = dragLambda + dx * 0.3;
    phi    = Math.max(-60, Math.min(60, dragPhi - dy * 0.3));
    proj.rotate([lambda, phi]);
  }} else {{
    // Hover detection
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    let found = -1;
    HOPS.forEach((h, i) => {{
      const px = proj([h.lon, h.lat]);
      if (!px) return;
      if (dotProduct(h.lon, h.lat) < 0) return;
      const d = Math.hypot(px[0]-mx, px[1]-my);
      if (d < 14) found = i;
    }});
    if (found !== hoverIdx) {{
      hoverIdx = found;
      if (found >= 0) {{
        const h = HOPS[found];
        const score = h.score !== null ? h.score+'/100' : 'N/D';
        const riskCls = 'risk-'+h.risk;
        const loc = [h.city, h.country].filter(Boolean).join(', ') || '—';
        const badges = (h.isProxy ? '<span style="color:#E24B4A"> ⚠ Proxy/VPN</span>' : '')
                     + (h.isHosting ? '<span style="color:#EF9F27"> ☁ Datacenter</span>' : '');
        tooltip.innerHTML = `
          <div class="tt-title">${{h.roleLabel}}</div>
          <div class="tt-row"><span class="tt-label">IP</span><span style="font-family:monospace">${{h.ip}}</span></div>
          <div class="tt-row"><span class="tt-label">From</span><span>${{h.fromHost}}</span></div>
          <div class="tt-row"><span class="tt-label">By</span><span>${{h.byHost}}</span></div>
          <div class="tt-row"><span class="tt-label">TLS</span><span>${{h.tls}}</span></div>
          <div class="tt-row"><span class="tt-label">Luogo</span><span>${{loc}}</span></div>
          <div class="tt-row"><span class="tt-label">ISP</span><span>${{h.isp||'—'}}</span></div>
          <div class="tt-row"><span class="tt-label">Abuse</span><span class="${{riskCls}}">${{score}}</span></div>
          ${{badges}}
        `;
        const px = proj([h.lon, h.lat]);
        const rect2 = canvas.getBoundingClientRect();
        let tx = px[0] + 16, ty = px[1] - 10;
        if (tx + 260 > W) tx = px[0] - 260;
        tooltip.style.left = tx+'px';
        tooltip.style.top  = ty+'px';
        tooltip.style.display = 'block';
      }} else {{
        tooltip.style.display = 'none';
      }}
    }}
  }}
}});

window.addEventListener('mouseup', e => {{
  if (dragStart) {{
    dragStart = null;
    rotating = true;
  }}
}});

// Touch support
canvas.addEventListener('touchstart', e => {{
  e.preventDefault();
  rotating = false;
  dragStart = [e.touches[0].clientX, e.touches[0].clientY];
  const r = proj.rotate();
  dragLambda = r[0]; dragPhi = r[1];
}}, {{passive:false}});

canvas.addEventListener('touchmove', e => {{
  e.preventDefault();
  if (!dragStart) return;
  const dx = e.touches[0].clientX - dragStart[0];
  const dy = e.touches[0].clientY - dragStart[1];
  lambda = dragLambda + dx * 0.4;
  phi    = Math.max(-60, Math.min(60, dragPhi - dy * 0.4));
  proj.rotate([lambda, phi]);
}}, {{passive:false}});

canvas.addEventListener('touchend', () => {{
  dragStart = null; rotating = true;
}});

// Pulsanti
btnPlay.addEventListener('click', () => {{
  rotating = !rotating;
  btnPlay.textContent = rotating ? '❚❚' : '▶';
}});

btnFit.addEventListener('click', () => {{
  if (HOPS.length === 0) return;
  const avgLon = HOPS.reduce((s,h)=>s+h.lon,0)/HOPS.length;
  const avgLat = HOPS.reduce((s,h)=>s+h.lat,0)/HOPS.length;
  lambda = -avgLon;
  phi    = -avgLat;
  proj.rotate([lambda, phi]);
}});

// Centra inizialmente sul percorso
if (HOPS.length > 0) {{
  const avgLon = HOPS.reduce((s,h)=>s+h.lon,0)/HOPS.length;
  const avgLat = HOPS.reduce((s,h)=>s+h.lat,0)/HOPS.length;
  lambda = -avgLon;
  phi    = -avgLat;
  proj.rotate([lambda, phi]);
}}

// Carica topologia mondo
d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json')
  .then(w => {{ world = w; }})
  .catch(() => {{ world = null; }});

requestAnimationFrame(animate);
</script>
</body>
</html>"""


# ── Entry point ────────────────────────────────────────────────────────────

def render_email_globe(soc: dict, validator) -> None:
    """
    Renderizza il globo 3D interattivo del percorso email in Streamlit.

    Sostituisce (o affianca) render_email_path_map in app.py:

        with st.expander("🌍 Percorso geografico email", expanded=True):
            render_email_globe(soc, validator)
    """
    hops = soc.get("received_hops", [])
    if not hops:
        st.info("Nessun header Received trovato: impossibile costruire il globo.")
        return

    # Assegna ruolo a ogni hop
    n = len(hops)
    roles = []
    for i in range(n):
        if i == 0:          roles.append("recipient")
        elif i == n - 1:    roles.append("sender")
        elif i == 1:        roles.append("injection")
        else:               roles.append("relay")

    # Geolocalizza + reputazione in parallelo
    def _fetch(hop: dict):
        ip = hop.get("sender_ip") or ""
        if not ip or _is_private(ip):
            return {"status": "skipped"}, {"status": "skipped"}
        return validator.geolocate_ip(ip), validator.check_ip_reputation(ip)

    with st.spinner("Geolocalizzazione hop in corso…"):
        with ThreadPoolExecutor(max_workers=min(n, 6)) as ex:
            results = list(ex.map(_fetch, hops))

    hops_data = [
        {
            "hop":    hop,
            "role":   role,
            "geo":    geo,
            "rep":    rep,
            "coords": _geo_coords(geo),
        }
        for hop, role, (geo, rep) in zip(hops, roles, results)
    ]

    located = [h for h in hops_data if h["coords"] is not None]

    if not located:
        st.info(
            "Tutti gli IP sono privati o non risolvibili. "
            "Il globo richiede almeno un IP pubblico geolocalizzabile."
        )
        return

    # Riepilogo card sopra il globo — ordine sender→recipient, coerente col globo
    hops_data_display = list(reversed(hops_data))
    cols = st.columns(max(n, 1))
    risk_icon = {"high": "🔴", "medium": "🟠", "low": "🟢", "unknown": "⚪"}
    role_label = {
        "sender": "Origine", "injection": "Iniezione",
        "relay": "Relay",    "recipient": "Destinatario",
    }
    for col, h in zip(cols, hops_data_display):
        ip     = h["hop"].get("sender_ip") or "—"
        city   = h["geo"].get("city", "")
        country= h["geo"].get("country", "")
        score  = h["rep"].get("abuseConfidenceScore") if h["rep"].get("status") == "ok" else None
        risk   = _score_to_risk(score)
        loc    = ", ".join(p for p in [city, country] if p) or ("IP privato" if not h["coords"] else "—")
        with col:
            st.markdown(
                f"**{risk_icon[risk]} {role_label.get(h['role'], h['role'])}**  \n"
                f"`{ip}`  \n"
                f"<span style='font-size:12px;color:gray'>{loc}</span>",
                unsafe_allow_html=True,
            )

    st.markdown("")
    # Render globo
    globe_html = _build_globe_html(hops_data)
    components.html(globe_html, height=530, scrolling=False)

    st.caption("Trascina per ruotare · ❚❚ pausa · ⌖ centra sul percorso · passa il mouse su un marker per i dettagli")