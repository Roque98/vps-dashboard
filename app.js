const C = window.VPS_CONFIG;
const PROY = window.PROYECTO === "abp" ? "abp" : "zia", Z = PROY === "zia";
const esAbp = (k) => /abp|duckdns|angel_test/i.test(String(k || ""));
const mio = (k) => esAbp(k) === !Z;
const COMPARTIDOS_ABP = ["nginx", "postgresql", "fail2ban"];
const svcMio = (k) => mio(k) || (!Z && COMPARTIDOS_ABP.includes(k)) || (Z && !esAbp(k));
const filtrarObj = (o, p) => Object.fromEntries(Object.entries(o || {}).filter(([k]) => p(k)));
function filtrarDatos(d) {
  d = structuredClone(d); const inst = d.instantanea ||= {}, mon = inst.monitoreo ||= {};
  d.servicios = (d.servicios || []).filter((s) => svcMio(s.nombre));
  inst.certificados = (inst.certificados || []).filter((c) => mio((c.dominios || []).join(" ") + c.nombre));
  inst.postgres = filtrarObj(inst.postgres, (k) => k === "postgres" || mio(k));
  inst.fail2ban = filtrarObj(inst.fail2ban, (k) => mio(k) || (Z && k === "sshd"));
  if (inst.nginx) inst.nginx.sitios = (inst.nginx.sitios || []).filter((x) => mio(x.archivo + (x.dominios || []).join(" ")));
  if (!Z) { inst.nodos = []; inst.ultimoDeploy = filtrarObj(inst.ultimoDeploy, esAbp); } else inst.ultimoDeploy = filtrarObj(inst.ultimoDeploy, (k) => !esAbp(k));
  mon.timers = (mon.timers || []).filter((t) => mio(t.nombre) || (Z && !esAbp(t.nombre)));
  mon.chequeos = filtrarObj(mon.chequeos, mio); mon.uptimeChequeos = filtrarObj(mon.uptimeChequeos, mio);
  if (mon.spark?.lat) mon.spark.lat = filtrarObj(mon.spark.lat, mio);
  mon.servicios = filtrarObj(mon.servicios, svcMio);
  mon.alertasActivas = (mon.alertasActivas || []).filter((a) => mio(a.clave));
  mon.incidentes = (mon.incidentes || []).filter((i) => mio(i.clave || i.objeto));
  return d;
}
function filtrarHistorial(h) {
  h = structuredClone(h);
  for (const p of h.puntos || []) { p.chk = filtrarObj(p.chk, mio); p.svc = filtrarObj(p.svc, svcMio); }
  h.incidentes = (h.incidentes || []).filter((i) => mio(i.clave || i.objeto));
  return h;
}
const REDIRECT = location.origin + location.pathname.replace(/index\.html$/, "");
const $ = (id) => document.getElementById(id);
const ss = sessionStorage;
const LENTO = matchMedia("(prefers-reduced-motion: reduce)").matches ? 3 : 1;
let historial = {}, rangoMetricas = "24h";
let datos = null, ultimoOk = 0, seleccion = null, tab = "arquitectura", ENLACES = [], NODOS = {};

/* =================== OIDC: código de autorización + PKCE =================== */
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const aleatorio = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
async function iniciarSesion() {
  const verifier = aleatorio(48), state = aleatorio(16);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  ss.setItem("pkce_verifier", verifier); ss.setItem("pkce_state", state);
  const q = new URLSearchParams({ client_id: C.clientId, redirect_uri: REDIRECT, response_type: "code", scope: C.scope,
    state, code_challenge: challenge, code_challenge_method: "S256", culture: "es", "ui-culture": "es" });
  location.assign(`${C.authority}/connect/authorize?${q}`);
}
async function procesarRetorno() {
  const p = new URLSearchParams(location.search);
  if (!p.has("code") && !p.has("error")) return;
  history.replaceState(null, "", REDIRECT);
  if (p.get("error")) throw new Error(`El servidor rechazó el inicio de sesión: ${p.get("error_description") || p.get("error")}`);
  if (p.get("state") !== ss.getItem("pkce_state")) throw new Error("El estado del inicio de sesión no coincide. Vuelve a intentarlo.");
  const r = await fetch(`${C.authority}/connect/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: p.get("code"), redirect_uri: REDIRECT, client_id: C.clientId, code_verifier: ss.getItem("pkce_verifier") }) });
  ss.removeItem("pkce_verifier"); ss.removeItem("pkce_state");
  if (!r.ok) throw new Error("No se pudo canjear el código por un token.");
  const t = await r.json();
  ss.setItem("access_token", t.access_token);
  ss.setItem("expira", String(Date.now() + (t.expires_in || 3600) * 1000));
  if (t.id_token) ss.setItem("id_token", t.id_token);
}
const token = () => (Number(ss.getItem("expira") || 0) > Date.now() + 30000 ? ss.getItem("access_token") : null);
function usuario() {
  try { const p = JSON.parse(atob(ss.getItem("access_token").split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); return p.preferred_username || p.unique_name || p.email || p.sub; } catch { return ""; }
}
function cerrarSesion() {
  const idt = ss.getItem("id_token"); ss.clear();
  const q = new URLSearchParams({ post_logout_redirect_uri: REDIRECT, client_id: C.clientId }); if (idt) q.set("id_token_hint", idt);
  location.assign(`${C.authority}/connect/endsession?${q}`);
}

/* =================== utilidades =================== */
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const bytes = (b) => { if (b == null) return "—"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (b >= 1024 && i < 4) { b /= 1024; i++; } return `${b.toFixed(i > 1 ? 1 : 0)} ${u[i]}`; };
const dur = (s) => { s = Math.max(0, Math.floor(s || 0)); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`; };
const hace = (iso) => iso ? dur((Date.now() - new Date(iso)) / 1000) : "—";
const fecha = (iso) => iso ? new Date(iso).toLocaleString("es-MX", { dateStyle: "short", timeStyle: "short" }) : "—";
const ORDEN = { mal: 3, warn: 2, ok: 1, gris: 0 };
const peor = (...e) => e.filter(Boolean).reduce((a, b) => (ORDEN[b] > ORDEN[a] ? b : a), "gris");
const peorConocido = (...e) => { const k = e.filter((x) => x && x !== "gris"); return k.length ? peor(...k) : "gris"; };
const umbral = (v, a, b) => v == null ? "gris" : v >= b ? "mal" : v >= a ? "warn" : "ok";
const TXT = { ok: "OK", warn: "DEGRADADO", mal: "FALLA", gris: "SIN DATO" };

const ICO = {
  cpu: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="4" y="4" width="8" height="8" rx="1"/><path d="M6 1.5v2M10 1.5v2M6 12.5v2M10 12.5v2M1.5 6h2M1.5 10h2M12.5 6h2M12.5 10h2"/></svg>',
  mem: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="1.5" y="4.5" width="13" height="7" rx="1"/><path d="M4 7v2M7 7v2M10 7v2M4 11.5v2M12 11.5v2"/></svg>',
  disk: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><ellipse cx="8" cy="4" rx="5.5" ry="2"/><path d="M2.5 4v8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V4M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2"/></svg>',
  con: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M2 5h10l-3-3M14 11H4l3 3"/></svg>',
  servidor: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="1.5" y="2" width="13" height="5" rx="1"/><rect x="1.5" y="9" width="13" height="5" rx="1"/><path d="M4 4.5h1M4 11.5h1"/></svg>',
  externo: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="8" cy="8" r="6.2"/><path d="M1.8 8h12.4M8 1.8c2 2 2 10.4 0 12.4M8 1.8c-2 2-2 10.4 0 12.4"/></svg>',
  usuarios: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="6" cy="5.5" r="2.5"/><path d="M1.5 14c0-2.5 2-4.5 4.5-4.5s4.5 2 4.5 4.5M11 3.2a2.4 2.4 0 010 4.6M12.5 9.8c1.3.7 2 2.3 2 4.2"/></svg>',
  nube: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M4.5 12.5h7.5a3 3 0 00.4-6A4.5 4.5 0 003.7 7 2.8 2.8 0 004.5 12.5z"/></svg>',
  bd: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><ellipse cx="8" cy="3.5" rx="5.5" ry="2"/><path d="M2.5 3.5v9c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2v-9M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2"/></svg>',
  escudo: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M8 1.5l5.5 2v4.2c0 3.3-2.3 5.8-5.5 6.8-3.2-1-5.5-3.5-5.5-6.8V3.5z"/></svg>',
  rama: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="4" cy="3.5" r="1.8"/><circle cx="4" cy="12.5" r="1.8"/><circle cx="12" cy="6" r="1.8"/><path d="M4 5.3v5.4M12 7.8c0 2.5-4 2-7 3.4"/></svg>',
  avion: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M14.5 2L1.5 7.3l5 1.6M14.5 2l-2.2 12-5.8-5.1M14.5 2L6.5 8.9v4.6l2.3-2.6"/></svg>',
  bomba: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="2" y="2" width="7" height="12.5" rx="1"/><path d="M3.5 5h4M9 6l3 2v4.5a1 1 0 002 0V6l-2-2"/></svg>',
  reloj: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><circle cx="8" cy="8" r="6.2"/><path d="M8 4.5V8l2.5 1.5"/></svg>',
  candado: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="3" y="7" width="10" height="7.5" rx="1"/><path d="M5 7V5a3 3 0 016 0v2"/></svg>',
  web: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="1.5" y="2.5" width="13" height="11" rx="1"/><path d="M1.5 5.5h13M3.5 4h.5M5.5 4h.5"/></svg>',
};
const met = (ico, txt, cls = "") => `<span class="${cls}">${ICO[ico]}${esc(txt)}</span>`;
document.querySelectorAll(".ico-l").forEach((e) => e.insertAdjacentHTML("afterbegin", ICO[e.dataset.i]));

/* =================== mini gráficas SVG =================== */
const COL = ["#a3e635", "#38bdf8", "#f59e0b", "#e879f9", "#f87171", "#34d399", "#fbbf24", "#a78bfa", "#fb7185", "#22d3ee"];
function spark(vals, color = "#a3e635", w = 120, h = 18) {
  const v = (vals || []).map((x) => (x == null ? null : +x));
  const ok = v.filter((x) => x != null);
  if (ok.length < 2) return `<svg viewBox="0 0 ${w} ${h}"><line x1="0" y1="${h - 1}" x2="${w}" y2="${h - 1}" stroke="#2a312d"/></svg>`;
  const mn = Math.min(...ok), mx = Math.max(...ok), r = mx - mn || 1;
  const pts = v.map((x, i) => x == null ? null : [(i / (v.length - 1)) * w, h - 2 - ((x - mn) / r) * (h - 4)]).filter(Boolean);
  const l = pts.map((p) => p.map((n) => n.toFixed(1)).join(",")).join(" ");
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none"><polygon points="0,${h} ${l} ${w},${h}" fill="${color}" opacity=".12"/><polyline points="${l}" fill="none" stroke="${color}" stroke-width="1.3" vector-effect="non-scaling-stroke"/><circle cx="${pts.at(-1)[0]}" cy="${pts.at(-1)[1]}" r="1.8" fill="${color}"/></svg>`;
}
function grafica(titulo, ts, series, o = {}) {
  const W2 = o.w || 440, H2 = o.h || 150, pl = 40, pr = 8, pt = 8, pb = 18;
  const todos = series.flatMap((x) => x.v).filter((x) => x != null);
  let mx = o.max ?? Math.max(1e-9, ...todos), mn = o.min ?? Math.min(0, ...todos);
  if (o.max == null) mx = mx * 1.1;
  const X = (i) => pl + (ts.length > 1 ? (ts[i] - ts[0]) / (ts.at(-1) - ts[0] || 1) : 0) * (W2 - pl - pr);
  const Y = (v) => pt + (1 - (v - mn) / (mx - mn || 1)) * (H2 - pt - pb);
  const fmt = o.fmt || ((v) => (Math.abs(v) >= 100 ? v.toFixed(0) : v.toFixed(1)));
  let g = "";
  for (let k = 0; k <= 3; k++) { const v = mn + (mx - mn) * k / 3, y = Y(v); g += `<line x1="${pl}" x2="${W2 - pr}" y1="${y}" y2="${y}" stroke="#1d2420"/><text x="${pl - 5}" y="${y + 3}" fill="#6b7770" font-size="9" text-anchor="end">${fmt(v)}</text>`; }
  if (ts.length) { const f = (t) => new Date(t * 1000).toLocaleString("es-MX", (ts.at(-1) - ts[0]) > 172800 ? { day: "2-digit", month: "2-digit" } : { hour: "2-digit", minute: "2-digit", hour12: false });
    for (let k = 0; k <= 4; k++) { const i = Math.round((ts.length - 1) * k / 4); g += `<text x="${X(i)}" y="${H2 - 4}" fill="#6b7770" font-size="9" text-anchor="${k === 0 ? "start" : k === 4 ? "end" : "middle"}">${f(ts[i])}</text>`; } }
  for (const [si, s2] of series.entries()) {
    const c = s2.c || COL[si % COL.length]; let d = "", abierto = false;
    s2.v.forEach((v, i) => { if (v == null) { abierto = false; return; } d += `${abierto ? "L" : "M"}${X(i).toFixed(1)},${Y(v).toFixed(1)}`; abierto = true; });
    if (series.length === 1 && d) g += `<path d="${d}L${X(ts.length - 1)},${Y(mn)}L${X(0)},${Y(mn)}Z" fill="${c}" opacity=".08"/>`;
    g += `<path d="${d}" fill="none" stroke="${c}" stroke-width="1.4"/>`;
  }
  for (const m of o.marcas || []) { if (!ts.length || m.t < ts[0]) continue; const x = X(0) + (m.t - ts[0]) / (ts.at(-1) - ts[0] || 1) * (W2 - pl - pr); g += `<line x1="${x}" x2="${x}" y1="${pt}" y2="${H2 - pb}" stroke="#ef4444" stroke-dasharray="2 3" opacity=".7"/>`; }
  const ult = series[0]?.v.filter((x) => x != null).at(-1);
  return `<div class="grafica"><div class="g-tit"><span>${esc(titulo)}</span><b>${ult != null ? esc(fmt(ult)) + (o.unidad || "") : "—"}</b></div>
    <svg viewBox="0 0 ${W2} ${H2}">${g}</svg>${series.length > 1 ? `<div class="ley">${series.map((s2, i) => `<span><i style="background:${s2.c || COL[i % COL.length]}"></i>${esc(s2.n)}</span>`).join("")}</div>` : ""}</div>`;
}

/* =================== modelo a partir de la API =================== */
function modelo(d) {
  const inst = d.instantanea || {};
  const mon = inst.monitoreo || {};
  const chq = mon.chequeos || {}, sp = mon.spark || {}, upc = mon.uptimeChequeos || {}, msv = mon.servicios || {}, act = mon.actividad || {};
  const srv = Object.fromEntries((d.servicios || []).map((s) => [s.nombre, s]));
  const estSrv = (n) => { const s = srv[n]; if (!s) return "gris"; return s.estado === "active" ? "ok" : s.estado === "activating" || s.estado === "reloading" ? "warn" : s.estado === "desconocido" ? "gris" : "mal"; };
  const estChk = (c) => !c ? "gris" : c.ok ? (c.ms > 1500 ? "warn" : "ok") : c.fallosSeguidos >= 2 ? "mal" : "warn";
  const pct = (x) => x == null ? "—" : `${x >= 99.995 ? "100" : x.toFixed(2)}%`;
  const certs = inst.certificados || [];
  const certDe = (dom) => certs.find((c) => (c.dominios || []).includes(dom.split("/")[0]));
  const sitios = (inst.nginx || {}).sitios || [];
  const memPct = d.memoriaTotalBytes ? 100 * (1 - d.memoriaDisponibleBytes / d.memoriaTotalBytes) : null;
  const raiz = (d.discos || []).find((x) => x.montaje === "/") || (d.discos || [])[0];
  const discoPct = raiz ? 100 * (1 - raiz.libreBytes / raiz.totalBytes) : null;
  const f2b = inst.fail2ban || {};
  const bansAhora = Object.values(f2b).reduce((a, j) => a + (j.baneadosAhora || 0), 0);
  const bans24 = Object.values(f2b).reduce((a, j) => a + (j.baneos24h || 0), 0);
  const edad = d.edadInstantaneaSegundos;
  const N = {};
  const add = (id, capa, o) => (N[id] = { id, capa, met: [], det: [], ...o });
  const svcDet = (n) => { const s = srv[n] || {}, m = msv[n]; return [["Estado systemd", s.estado ? `${s.estado} · ${s.subEstado}` : "sin dato"], ["Activo desde", s.activoDesdeUtc ? `${fecha(s.activoDesdeUtc)} (hace ${hace(s.activoDesdeUtc)})` : "—"], ["Memoria", bytes(s.memoriaBytes)], ["Reinicios", s.reinicios ?? "—"],
    ...(m ? [["Uptime 24h / 7d / 30d", `${pct(m.uptime?.["24h"])} · ${pct(m.uptime?.["7d"])} · ${pct(m.uptime?.["30d"])}`], ["Último incidente", m.ultimoIncidente ? `${m.ultimoIncidente.titulo} · ${fecha(m.ultimoIncidente.inicio * 1000)}${m.ultimoIncidente.fin ? "" : " (ACTIVO)"}` : "ninguno registrado"]] : [])]; };
  const servicio = (id, capa, nombre, st, extra = {}) => {
    const s = srv[nombre] || {}, m = msv[nombre], c = chq["local:" + nombre];
    add(id, capa, { tit: nombre, st, tag: "SERVICIO", ico: "servidor", est: peor(estSrv(nombre), c ? estChk(c) : "gris"), uptime: m?.uptime?.["24h"],
      met: [...(c ? [met("reloj", `${c.ms} ms`, c.ms > 1500 ? "warn" : "")] : []), met("mem", bytes(s.memoriaBytes)), met("con", `${s.reinicios ?? "—"} reinic.`, s.reinicios > 3 ? "warn" : "")],
      sparks: [...(c ? [{ lbl: "LAT", v: (sp.lat || {})["local:" + nombre], fmt: (x) => `${x} ms` }] : []), ...(m ? [{ lbl: "MEM", v: m.spark, fmt: (x) => `${x} MB`, c: "#38bdf8" }] : [])],
      det: [...svcDet(nombre), ...(c ? [["Chequeo local", `${c.url.replace(/^http:\/\/127\.0\.0\.1/, "")} → HTTP ${c.codigo} en ${c.ms} ms`]] : [])], ...extra });
  };

  // ---------- host (banda superior)
  const estHost = peor(umbral(d.cpuPorcentaje, 80, 95), umbral(memPct, 85, 95), umbral(discoPct, 80, 92));
  add("vps", "host", { tit: "VPS " + (d.host || ""), st: `157.x · ${d.nucleos} vCPU · uptime ${dur(d.uptimeSegundos)}`, tag: "SERVIDOR", ico: "servidor", est: estHost,
    met: [met("cpu", `${(d.cpuPorcentaje ?? 0).toFixed(0)}%`, umbral(d.cpuPorcentaje, 80, 95)), met("mem", `${memPct?.toFixed(0) ?? "—"}%`, umbral(memPct, 85, 95)), met("disk", `${discoPct?.toFixed(0) ?? "—"}%`, umbral(discoPct, 80, 92)), met("con", `${bansAhora} bans`), met("reloj", `carga ${(d.cargaPromedio || [0])[0].toFixed(2)}`), met("con", `↓${bytes(act.rxBps)}/s ↑${bytes(act.txBps)}/s`)],
    sparks: sp.cpu ? [{ lbl: "CPU", v: sp.cpu, fmt: (x) => `${x}%` }, { lbl: "RAM", v: sp.mem, fmt: (x) => `${x}%`, c: "#38bdf8" }, { lbl: "REQ", v: sp.req, fmt: (x) => `${x}/min`, c: "#e879f9" }] : [],
    det: [["Host", d.host], ["Uptime", dur(d.uptimeSegundos)], ["CPU", `${(d.cpuPorcentaje ?? 0).toFixed(1)} % · carga ${(d.cargaPromedio || []).map((x) => x.toFixed(2)).join(" / ")}`], ["Memoria", `${bytes(d.memoriaTotalBytes - d.memoriaDisponibleBytes)} de ${bytes(d.memoriaTotalBytes)} (${memPct?.toFixed(0)} %)`], ["Swap", d.swapTotalBytes ? `${bytes(d.swapTotalBytes - d.swapLibreBytes)} de ${bytes(d.swapTotalBytes)}` : "sin swap"], ...(d.discos || []).map((x) => [`Disco ${x.montaje}`, `${bytes(x.totalBytes - x.libreBytes)} de ${bytes(x.totalBytes)}`]), ["Red", `↓ ${bytes(act.rxBps)}/s · ↑ ${bytes(act.txBps)}/s`]] });

  // ---------- EXTERNOS
  const nodos = inst.nodos || [];
  const lat = nodos.filter((n) => !n.revocado).map((n) => n.ultimoLatidoUtc ? (Date.now() - new Date(n.ultimoLatidoUtc)) / 1000 : Infinity);
  const enLinea = lat.filter((x) => x < 600).length;
  add("usuarios", "externos", { tit: "Usuarios", st: Z ? "clientes ZIA · navegador" : "usuarios del piloto", tag: "EXTERNO", ico: "usuarios", est: "ok", inferido: true,
    met: [met("con", `${act.reqMin ?? "—"} req/min`), met("disk", `${act.e5Min ?? 0} 5xx`, act.e5Min ? "warn" : "")],
    det: [["Estado", "Inferido: la API respondió a este panel a través de Cloudflare"], ["Peticiones nginx", `${act.reqMin ?? "—"} en el último minuto (${act.e5Min ?? 0} con 5xx)`]] });
  if (Z) add("gasolineras", "externos", { tit: "Gasolineras", st: `${nodos.length} nodo(s) de prueba · ${enLinea} en línea`, tag: "EXTERNO", ico: "bomba", est: !nodos.length ? "gris" : enLinea === lat.length ? "ok" : enLinea ? "warn" : "mal",
    met: [met("con", `${enLinea}/${lat.length} latido`), met("reloj", nodos.length ? "últ. " + hace(nodos.map((n) => n.ultimoLatidoUtc).filter(Boolean).sort().pop()) : "—")],
    det: nodos.map((n) => [n.equipo || "nodo", `${n.permiso} · v${n.version || "?"} · ${n.revocado ? "revocado" : n.ultimoLatidoUtc ? "latido hace " + hace(n.ultimoLatidoUtc) : "sin latido"}`]) });
  const deps = inst.ultimoDeploy || {};
  const ultDep = Object.values(deps).filter(Boolean).sort().pop();
  add("github", "externos", { tit: "GitHub Actions", st: "deploy.yml → SSH", tag: "EXTERNO", ico: "rama", est: ultDep ? "ok" : "gris",
    met: [met("reloj", ultDep ? "deploy hace " + hace(ultDep) : "sin deploy")], det: Object.entries(deps).map(([k, v]) => [`Último deploy ${k}`, `${fecha(v)} (hace ${hace(v)})`]) });

  // ---------- EDGE
  const dominios = Z ? [["d-landing", "ziacentro.mx", "landing estática"], ["d-console", "console.ziacentro.mx", "zia.console"], ["d-api", "api.ziacentro.mx", "igas-console :5010"], ["d-chat", "ziacentro.mx/api/chat", "zia-chatbot :5020"]]
    : [["d-abp-web", "inangelroque.duckdns.org", "sitio abp-template"], ["d-abp-api", "api.inangelroque.duckdns.org", "abp-template :5000"]];
  const NOMBRES = { landing: "Landing", consola: "zia.console", "p-api": "proxy api", "p-chat": "proxy /api/chat", "p-abp-api": "proxy api", "abp-sitio": "sitio abp-template" };
  const RUTAS = { "d-landing": ["landing"], "d-console": ["consola", "p-api", "igas-console"], "d-api": ["p-api", "igas-console", "db-igas_console"], "d-chat": ["p-chat", "zia-chatbot", "db-igas_console"],
    "d-abp-web": ["abp-sitio"], "d-abp-api": ["p-abp-api", "abp-template", ...Object.keys(inst.postgres || {}).filter((k) => /abp/.test(k)).map((k) => "db-" + k)] };
  for (const [id, dom, dest] of dominios) {
    const c = chq[dom], ce = certDe(dom), u = upc[dom];
    const estCert = ce ? umbral(-ce.diasRestantes, -30, -7) : "gris";
    add(id, "edge", { tit: dom, st: "→ " + dest, ruta: ["cloudflare", "nginx", ...RUTAS[id]], tag: "DOMINIO", ico: "web", sub: true, chk: dom, est: peorConocido(estChk(c), estCert), uptime: u?.["24h"],
      met: [met("con", `HTTP ${c?.codigo || "—"}`, c && !c.ok ? "mal" : ""), met("reloj", c ? `${c.ms} ms` : "—", c?.ms > 1500 ? "warn" : ""), met("candado", ce ? `${Math.floor(ce.diasRestantes)} d` : "—", ce ? estCert : "")],
      sparks: [{ lbl: "LAT", v: (sp.lat || {})[dom], fmt: (x) => `${x} ms` }],
      det: [["Chequeo (vía Cloudflare)", c ? `${c.url} → HTTP ${c.codigo || "sin respuesta"} en ${c.ms} ms` : "sin dato"], ["Uptime 24h / 7d / 30d", u ? `${pct(u["24h"])} · ${pct(u["7d"])} · ${pct(u["30d"])}` : "—"], ["Certificado", ce ? `${ce.nombre} · vence ${fecha(ce.venceUtc)} (${Math.floor(ce.diasRestantes)} d)` : "—"], ["Destino", dest], ["Ruta", [dom, Z ? "Cloudflare" : "DuckDNS", "nginx", ...RUTAS[id].map((x) => NOMBRES[x] || x.replace(/^db-/, ""))].join(" → ")]] });
  }
  const dPri = dominios[0][1];
  add("cloudflare", "edge", { tit: Z ? "Cloudflare" : "DuckDNS", st: Z ? "proxy · DNS · TLS de borde" : "DNS dinámico · TLS Let's Encrypt", tag: "EDGE", ico: "nube", est: Z ? "ok" : peorConocido(...dominios.map((x) => estChk(chq[x[1]]))), hijos: dominios.map((x) => x[0]),
    met: [met("candado", `cert ${certDe(dPri) ? Math.floor(certDe(dPri).diasRestantes) + " d" : "—"}`), met("con", `${dominios.length} dominios`)],
    det: [["Estado", "OK (inferido: esta respuesta llegó por Cloudflare)"], ["Origen", (mon.firewall || {}).nginxSoloCloudflare ? "nginx solo acepta IPs de Cloudflare (cloudflare-solo)" : "sin restricción detectada"]] });

  // ---------- WEB
  if (Z) { add("landing", "web", { tit: "Landing", st: "ziacentro.mx · /srv/zia/web", tag: "ESTÁTICO", ico: "web", sub: true, est: peorConocido(estSrv("nginx"), estChk(chq["ziacentro.mx"])), det: [["Contenido", "Sitio estático de ziacentro.mx"]] });
  add("consola", "web", { tit: "zia.console", st: "console.ziacentro.mx", tag: "ESTÁTICO", ico: "web", sub: true, est: peorConocido(estSrv("nginx"), estChk(chq["console.ziacentro.mx"])), det: [["Contenido", "SPA de la consola (/srv/igas-console/current/web)"]] }); }
  else add("abp-sitio", "web", { tit: "sitio abp-template", st: "inangelroque.duckdns.org", tag: "SITIO", ico: "web", sub: true, est: peorConocido(estSrv("nginx"), estChk(chq["inangelroque.duckdns.org"])), det: [["nginx", "sites-enabled/abp-template"], ["Dominios", sitios.map((x) => (x.dominios || []).join(", ")).join(" · ") || "—"]] });
  const proxy = (id, tit, st, svc, chk) => add(id, "web", { tit, st, tag: "PROXY", ico: "web", sub: true, est: peorConocido(estSrv("nginx"), estChk(chq[chk])), det: [["Proxy", st], ["Backend", svc]] });
  if (Z) { proxy("p-api", "proxy api", "api.ziacentro.mx → :5010", "igas-console", "api.ziacentro.mx"); proxy("p-chat", "proxy /api/chat", "ziacentro.mx/api/chat → :5020", "zia-chatbot", "ziacentro.mx/api/chat"); }
  else proxy("p-abp-api", "proxy api", "api.inangelroque… → :5000", "abp-template", "api.inangelroque.duckdns.org");
  add("nginx", "web", { tit: "nginx", st: Z ? ":80 · :443 · solo Cloudflare" : ":443 · host compartido con ZIA", tag: "PROXY", ico: "web", est: peor(estSrv("nginx"), (inst.nginx || {}).configValida === false ? "warn" : "ok"), hijos: Z ? ["landing", "consola", "p-api", "p-chat"] : ["abp-sitio", "p-abp-api"], uptime: msv.nginx?.uptime?.["24h"],
    met: [met("con", `${act.reqMin ?? "—"} req/min`), met("disk", `${act.e5Min ?? 0} 5xx`, act.e5Min ? "warn" : ""), met("mem", bytes((srv.nginx || {}).memoriaBytes))],
    sparks: [{ lbl: "REQ", v: sp.req, fmt: (x) => `${x}/min` }],
    det: [...svcDet("nginx"), ["nginx -t", (inst.nginx || {}).configValida ? "válida" : "con errores o sin dato"], ["Sitios", sitios.map((s) => s.archivo).join(", ") || "—"]] });

  // ---------- API / BACKEND
  if (Z) servicio("igas-console", "api", "igas-console", "127.0.0.1:5010 · ABP + OpenIddict");
  if (!Z) servicio("abp-template", "api", "abp-template", "127.0.0.1:5000 · api.inangelroque.duckdns.org");

  // ---------- BOTS
  const bot = mon.bot || {};
  if (Z) { servicio("zia-chatbot", "bots", "zia-chatbot", "127.0.0.1:5020 · chat de la landing");
  add("worker", "bots", { tit: "ChatLeadTelegramWorker", st: "dentro de igas-console", tag: "WORKER", ico: "reloj", sub: false, est: estSrv("igas-console"), inferido: true,
    det: [["Qué hace", "Avisa por Telegram de los prospectos que deja el chat"], ["Proceso", "igas-console (estado inferido del servicio)"]] });
  add("bot-monitor", "bots", { tit: "@VpsIngAngelMonitor_bot", st: "alertas VPS · leads", tag: "BOT", ico: "avion", est: bot.t ? (bot.ok ? "ok" : "mal") : "gris",
    met: [met("reloj", bot.t ? `getMe hace ${dur(Date.now() / 1000 - bot.t)}` : "sin dato", bot.t && !bot.ok ? "mal" : "")],
    det: [["Token", bot.t ? (bot.ok ? "válido (getMe OK)" : "getMe falló") : "sin dato"], ["Chat de alertas", bot.chatConfigurado ? "configurado (grupo VPS)" : "no configurado"], ["Usuario", bot.usuario ? "@" + bot.usuario : "—"]] });
  add("telegram", "bots", { tit: "Telegram API", st: "api.telegram.org", tag: "EXTERNO", ico: "externo", est: bot.t ? (bot.ok ? "ok" : "mal") : "gris", det: [["Estado", "Medido con getMe del bot de alertas cada 10 min"]] }); }
  else { add("bot-abp", "bots", { tit: "@angel_test_98_bot", st: "bot de abp-template", tag: "BOT", ico: "avion", est: estSrv("abp-template") === "ok" ? "ok" : "gris", inferido: true,
    det: [["Estado", "Inferido de abp-template (su token no se lee desde el panel)"]] });
  add("telegram", "bots", { tit: "Telegram API", st: "api.telegram.org", tag: "EXTERNO", ico: "externo", est: "gris", inferido: true, det: [["Estado", "Sin medición propia del piloto"]] }); }

  // ---------- DATOS
  const pg = inst.postgres || {};
  const dbIds = [];
  for (const [db, b] of Object.entries(pg).sort((a, b) => b[1] - a[1])) {
    if (db === "postgres") continue;
    add("db-" + db, "datos", { tit: db, st: bytes(b), tag: "BD", ico: "bd", sub: true, est: estSrv("postgresql"), det: [["Tamaño", bytes(b)]] });
    dbIds.push("db-" + db);
  }
  add("postgres", "datos", { tit: "PostgreSQL", st: `127.0.0.1:5432 · v${(inst.postgresVersion || "?").split(" ")[0]}`, tag: "BASE DE DATOS", ico: "bd", est: estSrv("postgresql"), hijos: dbIds, uptime: msv.postgresql?.uptime?.["24h"],
    met: [met("disk", bytes(Object.values(pg).reduce((a, b) => a + b, 0) || d.baseDeDatosBytes)), met("mem", bytes((srv.postgresql || {}).memoriaBytes))],
    sparks: msv.postgresql ? [{ lbl: "MEM", v: msv.postgresql.spark, fmt: (x) => `${x} MB`, c: "#38bdf8" }] : [], det: [...svcDet("postgresql"), ...Object.entries(pg).map(([k, v]) => [`Base ${k}`, bytes(v)])] });
  const hp = mon.historialPuntos || {};
  if (Z) add("historial", "datos", { tit: "Historial", st: "monitoreo-historial.json · 30 d", tag: "SERIE", ico: "disk", est: edad == null ? "mal" : edad < 150 ? "ok" : edad < 600 ? "warn" : "mal",
    met: [met("disk", bytes(mon.historialBytes)), met("con", `${hp.minuto ?? 0} + ${hp.agregado ?? 0} pts`), met("reloj", edad != null ? `hace ${Math.round(edad)} s` : "—")],
    det: [["Contenido", "Muestras por minuto (24 h), agregados de 10 min (30 d) e incidentes"], ["Tamaño", bytes(mon.historialBytes)], ["Última muestra", edad != null ? `hace ${Math.round(edad)} s` : "nunca"], ["Lo sirve", "igas-console · GET /historial"], ["Alertas", "las envía el colector por @VpsIngAngelMonitor_bot"]] });

  // ---------- CRON / TAREAS
  const ahora = Date.now() / 1000;
  const timers = mon.timers || [];
  for (const t of timers) {
    const fallo = t.resultado !== "success" || t.codigo !== 0;
    const atrasado = t.proximo && t.proximo < ahora - 300;
    const est = fallo ? "mal" : !t.ultimo ? "gris" : atrasado ? "warn" : "ok";
    add("t-" + t.nombre, "cron", { tit: t.nombre, st: t.descripcion, tag: "TIMER", ico: "reloj", est, compacto: true,
      met: [met("reloj", t.ultimo ? `últ. ${dur(ahora - t.ultimo)}` : "nunca"), met("con", t.nombre === "igas-monitoreo-vps" ? "cada 1 min" : t.proximo ? `próx. ${dur(t.proximo - ahora)}` : "—"), ...(fallo ? [met("disk", `código ${t.codigo}`, "mal")] : [])],
      det: [["Qué hace", t.descripcion], ["Última ejecución", t.ultimo ? `${fecha(t.ultimo * 1000)} (hace ${dur(ahora - t.ultimo)})` : "nunca"], ["Próxima", t.proximo ? `${fecha(t.proximo * 1000)} (en ${dur(t.proximo - ahora)})` : t.nombre === "igas-monitoreo-vps" ? "cada minuto" : "—"], ["Resultado", `${t.resultado} · código ${t.codigo}`], ["Duración", t.duracion != null ? `${t.duracion} s` : "—"]] });
  }

  // ---------- SEGURIDAD
  const jails = Object.entries(f2b).map(([j, v]) => { const id = "jail-" + j;
    add(id, "seguridad", { tit: j, st: `${v.baneadosAhora} ahora · ${v.baneos24h}/24h`, tag: "JAIL", ico: "escudo", sub: true, est: v.baneadosAhora > 20 ? "warn" : "ok",
      det: [["Baneadas ahora", v.baneadosAhora], ["Baneos 1 h / 24 h", `${v.baneos1h} / ${v.baneos24h}`], ["Total baneos / fallos", `${v.baneadosTotal} / ${v.fallosTotal}`]] }); return id; });
  add("fail2ban", "seguridad", { tit: "fail2ban", st: `${jails.length} jails`, tag: "IPS", ico: "escudo", est: estSrv("fail2ban"), hijos: jails, uptime: msv.fail2ban?.uptime?.["24h"],
    met: [met("con", `${bansAhora} ban · ${bans24}/24h`, bansAhora > 20 ? "warn" : "")], det: svcDet("fail2ban") });
  if (Z) add("ssh", "seguridad", { tit: "ssh", st: ":22 · " + (inst.ssh ? (inst.ssh.soloLlave ? "solo llave" : "¡acepta contraseña!") : "—"), tag: "ACCESO", ico: "candado", est: peor(estSrv("ssh"), inst.ssh && !inst.ssh.soloLlave ? "mal" : "ok"),
    met: [met("con", `${(f2b.sshd || {}).baneos24h ?? "—"} bans/24h`)], det: svcDet("ssh") });
  const fw = mon.firewall || {};
  if (Z) add("firewall", "seguridad", { tit: "Firewall", st: `UFW ${fw.ufwActivo ? "activo" : "¿inactivo?"} · ${fw.nginxSoloCloudflare ? "web solo Cloudflare" : "web abierta"}`, tag: "RED", ico: "escudo",
    est: !mon.firewall ? "gris" : fw.ufwActivo && fw.nginxSoloCloudflare ? "ok" : "warn", met: [met("con", (fw.ufwPermite || []).join(" · ") || "—")],
    det: [["UFW", fw.ufwActivo ? "activo" : "inactivo o sin dato"], ["Permite", (fw.ufwPermite || []).join(", ") || "—"], ["Web", fw.nginxSoloCloudflare ? "nginx responde 403 a quien no venga de Cloudflare" : "sin restricción"], ["SSH", "solo llave; fail2ban vigila sshd"]] });

  for (const a of mon.alertasActivas || []) { const [tipo, obj] = a.clave.split(":"); const id = tipo === "timer" ? "t-" + obj : obj; if (obj && N[id]) N[id].est = "mal"; }

  // ---------- enlaces
  const E = [];
  const l = (a, b, tipo = "medido", via) => E.push({ a, b, tipo, via });
  l("usuarios", "cloudflare", "inferido"); if (Z) l("gasolineras", "cloudflare", "inferido");
  const TINTE = { "d-landing": "#a3e635", "d-console": "#38bdf8", "d-api": "#c084fc", "d-chat": "#2dd4bf", "d-abp-web": "#a3e635", "d-abp-api": "#c084fc" };
  const rl = (a, b, t, et) => { l(a, b); Object.assign(E.at(-1), { tinte: t, etiqueta: et }); };
  if (Z) { rl("d-landing", "landing", TINTE["d-landing"]); rl("d-console", "consola", TINTE["d-console"]); rl("d-api", "p-api", TINTE["d-api"]); rl("d-chat", "p-chat", TINTE["d-chat"]);
    rl("p-api", "igas-console", TINTE["d-api"], ":5010");
    l("consola", "p-api", "inferido"); Object.assign(E.at(-1), { tinte: TINTE["d-console"], etqVertical: "navegador → api" }); rl("p-chat", "zia-chatbot", TINTE["d-chat"], ":5020"); }
  else { rl("d-abp-web", "abp-sitio", TINTE["d-abp-web"]); rl("d-abp-api", "p-abp-api", TINTE["d-abp-api"]); rl("p-abp-api", "abp-template", TINTE["d-abp-api"], ":5000"); }
  l("igas-console", "worker"); l("worker", "bot-monitor", "medido", { lado: "derecha" }); l("bot-monitor", "telegram", "medido", { lado: "derecha", carril: 1 });
  l("abp-template", "bot-abp", "inferido"); l("bot-abp", "telegram", "inferido", { lado: "derecha" });
  l("igas-console", "db-igas_console"); l("zia-chatbot", "db-igas_console", "inferido");
  for (const id of dbIds.filter((x) => x.startsWith("db-abp"))) l("abp-template", id);
  const tl = (t, b, tipo = "medido") => N["t-" + t] && l("t-" + t, b, tipo, { dirA: -1 });
  tl("igas-monitoreo-vps", "historial"); tl("igas-monitoreo-vps", "bot-monitor"); tl("igas-console-backup", "db-igas_console"); 
  tl("igas-console-restore-check", "postgres", "inferido"); tl("abp-template-restore-check", "postgres", "inferido");
  for (const id of dbIds.filter((x) => x.startsWith("db-abp"))) tl("abp-template-backup", id);
  l("historial", "igas-console", "medido");
  if (N["t-cf-actualizar-ips"]) l("t-cf-actualizar-ips", "firewall", "inferido");
  if (N["t-certbot"]) l("t-certbot", "firewall", "inferido");
  l("github", "ssh", "inferido", { bajo: 0 });
  l("fail2ban", "ssh", "medido", { lado: "derecha" });

  const reqMin = act.reqMin ?? 0;
  const latDe = (id) => { const n = N[id]; return n?.chk ? chq[n.chk]?.ms : chq["local:" + id]?.ms; };
  for (const e of E) {
    if (e.b === "telegram" || e.a.startsWith("t-")) e.inverso = false;
    const latv = latDe(e.b) ?? latDe(e.a);
    const carga = Math.min(1, Math.log10(1 + reqMin) / 3);
    e.dur = Math.max(0.9, Math.min(6, (latv ? 1.2 + latv / 400 : 2.2) * (1.4 - carga * 0.8) * (e.tipo === "inferido" ? 1.8 : 1)));
    e.particulas = e.tipo === "inferido" ? 1 : 1 + Math.round(carga * 2);
    e.brillo = 0.55 + carga * 0.45;
    const ea = N[e.a]?.est ?? "gris", eb = N[e.b]?.est ?? "gris";
    e.est = e.tipo === "planeado" ? "gris" : (ea === "mal" || eb === "mal") ? "mal" : peorConocido(ea, eb);
  }
  return { N, E: E.filter((e) => N[e.a] && N[e.b]), mon, resumen: { servicios: d.servicios || [], srvOk: (d.servicios || []).filter((s) => s.estado === "active").length, certs, estHost } };
}

const CAPAS = [["externos", "EXTERNOS"], ["edge", "EDGE"], ["web", "WEB"], ["api", "API / BACKEND"], ["bots", "BOTS"], ["datos", "DATOS"], ["cron", "CRON / TAREAS"], ["seguridad", "SEGURIDAD"]];
const COLW = 184, GAP = 64, COLP = COLW + GAP, COLX0 = 16, TOP = 128;

/* =================== render del diagrama =================== */
function sparksHtml(n) {
  return (n.sparks || []).filter((x) => x.v && x.v.length).map((x) => { const u = x.v.filter((y) => y != null).at(-1);
    return `<div class="spark-fila"><span class="lbl">${x.lbl}</span>${spark(x.v, x.c)}<b>${u != null ? esc(x.fmt(u)) : "—"}</b></div>`; }).join("");
}
function tarjeta(n, N) {
  const cls = ["nodo", n.sub ? "sub" : "", n.plan ? "plan" : "", n.compacto ? "compacto" : "", n.est].join(" ");
  const hijos = (n.hijos || []).map((h) => tarjeta(N[h], N)).join("");
  return `<div class="${cls}" data-id="${n.id}">
    <div class="n-cab"><span class="n-ico">${ICO[n.ico] || ""}</span><div class="n-cuerpo"><div class="n-tit">${esc(n.tit)}</div><div class="n-st">${esc(n.st)}</div></div>
    <div class="n-tag">${n.uptime != null ? `<span class="up ${n.uptime < 99 ? "mal" : n.uptime < 99.9 ? "warn" : ""}" title="uptime 24 h">${n.uptime >= 99.995 ? "100" : n.uptime.toFixed(1)}%</span>` : ""}${n.sub && n.uptime != null ? "" : esc(n.tag)} <i class="dot ${n.est}" title="${TXT[n.est]}"></i></div></div>
    ${n.met ? `<div class="metricas">${n.met.join("")}</div>` : ""}
    ${sparksHtml(n)}
    ${hijos ? `<div class="hijos">${hijos}</div>` : ""}
  </div>`;
}
function pintarDiagrama(M) {
  const { N } = M;
  const vps = N.vps;
  let html = `<div class="col" style="left:${COLX0}px;top:10px;width:${COLP * 8 - GAP}px"><div class="nodo host ${vps.est}" data-id="vps">
    <div class="host-fila"><div class="n-cab" style="min-width:260px"><span class="n-ico">${ICO.servidor}</span><div class="n-cuerpo"><div class="n-tit">${esc(vps.tit)}</div><div class="n-st">${esc(vps.st)}</div></div></div>
    <div class="metricas" style="border:0;margin:0;padding:0">${vps.met.join("")}</div><div class="host-sparks">${sparksHtml(vps)}</div><div class="n-tag">SERVIDOR <i class="dot ${vps.est}"></i></div></div></div></div>`;
  CAPAS.forEach(([capa, nombre], i) => {
    const x = COLX0 + i * COLP;
    const nodosCapa = Object.values(N).filter((n) => n.capa === capa);
    const tops = nodosCapa.filter((n) => !Object.values(N).some((p) => (p.hijos || []).includes(n.id)));
    const conocidos = nodosCapa.filter((n) => n.est !== "gris"), ok = conocidos.filter((n) => n.est === "ok").length;
    const e = conocidos.length ? peor(...conocidos.map((n) => n.est)) : "gris";
    html += `<div class="capa-fondo ${e}" style="left:${x - 6}px;width:${COLW + 12}px"></div>
      <div class="capa-head ${e}" style="left:${x}px;width:${COLW}px"><div class="c-nom">${nombre}</div><div class="c-sal"><i class="dot ${e}"></i>${{ ok: "OK", warn: "DEGRADADO", mal: "FALLA", gris: "SIN DATO" }[e]} <span>${ok}/${conocidos.length}</span></div></div>
      <div class="col capa-col" style="left:${x}px;top:${TOP}px;width:${COLW}px;gap:12px">${tops.map((n) => tarjeta(n, N)).join("")}</div>`;
  });
  $("nodos-diagrama").innerHTML = html;
  document.querySelectorAll("#nodos-diagrama .nodo").forEach((el) => { el.addEventListener("click", (ev) => { ev.stopPropagation(); seleccionar(el.dataset.id); });
    el.addEventListener("mouseenter", (ev) => { ev.stopPropagation(); resaltar(el.dataset.id); });
    el.addEventListener("mouseleave", () => { const p = el.parentElement.closest("[data-id]"); if (p) resaltar(p.dataset.id); else if (seleccion) resaltar(seleccion); else { $("lienzo").classList.remove("dim"); document.querySelectorAll(".rel,.sel").forEach((e) => e.classList.remove("rel", "sel")); } }); });
  ULTIMO_M = M;
  requestAnimationFrame(() => { distribuir(); trazarEnlaces(M); });
}
let ULTIMO_M = null, COL_ALTO = 0;
// reparte las tarjetas de cada capa a lo alto de la vista (sin dejar huecos abajo)
function distribuir() {
  const cols = [...document.querySelectorAll(".capa-col")]; if (!cols.length) return;
  cols.forEach((c) => (c.style.height = ""));
  const v = $("viewport"), vw = v.clientWidth, vh = v.clientHeight;
  const nat = Math.max(...cols.map((c) => c.scrollHeight));
  let alto = nat;
  if (vw >= 820 && vh > 0) alto = Math.max(nat, vh / Math.min(vw / W, 1.15) - TOP - 30);
  cols.forEach((c) => (c.style.height = alto + "px"));
  COL_ALTO = alto;
  // alinea cada destino con su origen (líneas casi rectas) sin invadir a sus vecinas
  const ALINEAR = [["nginx", "cloudflare"], ["igas-console", "p-api"], ["zia-chatbot", "p-chat"], ["abp-template", "p-abp-api"]];
  document.querySelectorAll(".capa-col > .nodo").forEach((el) => (el.style.top = ""));
  for (const [dst, src] of ALINEAR) {
    const el = document.querySelector(`.capa-col > [data-id="${dst}"]`), S = caja(src); if (!el || !S) continue;
    el.style.position = "relative";
    const D = caja(dst); let dy = S.y + S.h / 2 - (D.y + D.h / 2);
    const prev = el.previousElementSibling, next = el.nextElementSibling;
    const P = prev && caja(prev.dataset.id), Nx = next && caja(next.dataset.id);
    const minY = P ? P.y + P.h + 10 : TOP, maxY = (Nx ? Nx.y - 10 : TOP + alto) - D.h;
    dy = Math.max(minY - D.y, Math.min(maxY - D.y, dy));
    el.style.top = dy + "px";
  }
}

function caja(id) {
  const el = document.querySelector(`#nodos-diagrama [data-id="${id}"]`);
  if (!el) return null;
  let x = 0, y = 0, e = el;
  while (e && e.id !== "lienzo") { x += e.offsetLeft; y += e.offsetTop; e = e.offsetParent; }
  return { x, y, w: el.offsetWidth, h: el.offsetHeight };
}
function ruta(pts, r = 9) {
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 1; i < pts.length - 1; i++) {
    const [x0, y0] = pts[i - 1], [x1, y1] = pts[i], [x2, y2] = pts[i + 1];
    const d1 = Math.hypot(x1 - x0, y1 - y0), d2 = Math.hypot(x2 - x1, y2 - y1);
    const rr = Math.min(r, d1 / 2, d2 / 2);
    if (rr < 0.5) { d += ` L${x1},${y1}`; continue; }
    const ax = x1 - (x1 - x0) / d1 * rr, ay = y1 - (y1 - y0) / d1 * rr, bx = x1 + (x2 - x1) / d2 * rr, by = y1 + (y2 - y1) / d2 * rr;
    d += ` L${ax},${ay} Q${x1},${y1} ${bx},${by}`;
  }
  const u = pts[pts.length - 1];
  return d + ` L${u[0]},${u[1]}`;
}
function trazarEnlaces(M) {
  const svg = $("enlaces");
  const sal = {}, ent = {};
  for (const e of M.E) { (sal[e.a] ||= []).push(e); (ent[e.b] ||= []).push(e); }
  // anclajes repartidos a lo largo del borde de la tarjeta
  const yAnc = (lista, e, bx) => { const i = lista.indexOf(e), n = lista.length, paso = Math.min(16, (bx.h - 16) / Math.max(1, n)); return bx.y + bx.h / 2 + (i - (n - 1) / 2) * paso; };
  for (const k in sal) sal[k].sort((p, q) => (caja(p.b)?.y ?? 0) - (caja(q.b)?.y ?? 0));
  for (const k in ent) ent[k].sort((p, q) => (caja(p.a)?.y ?? 0) - (caja(q.a)?.y ?? 0));
  const fondo = Math.max(...[...document.querySelectorAll("#nodos-diagrama > .col > .nodo:not(.host)")].map((el) => { const b = caja(el.dataset.id); return b ? b.y + b.h : 0; }));
  const colDe = (id) => CAPAS.findIndex((c) => c[0] === M.N[id]?.capa);
  const gx = (g) => COLX0 + g * COLP + COLW + GAP / 2;
  const colEls = [...document.querySelectorAll(".capa-col")];
  const libres = (i) => { const bs = [...colEls[i].children].map((el) => caja(el.dataset.id)).filter(Boolean).sort((p, q) => p.y - q.y);
    const out = []; let y = TOP - 6; for (const bx of bs) { out.push([y, bx.y]); y = bx.y + bx.h; } out.push([y, fondo + 400]); return out; };
  const usoCanal = {};
  const canalY = (cols, yObj) => { // y libre de tarjetas en todas las columnas intermedias
    let ivs = libres(cols[0]);
    for (const c of cols.slice(1)) { const o = libres(c), r = []; for (const [a1, b1] of ivs) for (const [a2, b2] of o) { const lo = Math.max(a1, a2), hi = Math.min(b1, b2); if (hi - lo > 10) r.push([lo, hi]); } ivs = r; }
    if (!ivs.length) return fondo + 20;
    const [lo, hi] = ivs.sort((p, q) => Math.abs((p[0] + p[1]) / 2 - yObj) - Math.abs((q[0] + q[1]) / 2 - yObj))[0];
    const k = cols.join(",") + "@" + Math.round(lo), n = (usoCanal[k] = (usoCanal[k] ?? -1) + 1);
    const c = (lo + hi) / 2, paso = Math.min(8, (hi - lo - 8) / 6);
    return c + (n % 2 ? 1 : -1) * Math.ceil(n / 2) * paso;
  };
  // 1) esqueleto: los tramos verticales van en un canal (gutter) g; la x se asigna después por carriles
  const rutas = [], verts = {};
  // haces: varias salidas de una tarjeta hacia el mismo canal comparten tronco y luego se abren (igual en llegadas)
  const gut = (e) => { const ia = colDe(e.a), ib = colDe(e.b); if (e.via || ia === ib || ia < 0 || ib < 0) return null; const der = ib > ia; return { ga: der ? ia : ia - 1, gb: der ? ib - 1 : ib }; };
  const cuenta = {}, estH = {};
  const suma = (k, e) => { cuenta[k] = (cuenta[k] || 0) + 1; (estH[k] ||= new Set()).add(e.est + e.tipo); };
  for (const e of M.E) { const g = gut(e); if (!g) continue; suma("s" + e.a + g.ga, e); suma("t" + e.b + g.gb, e); }
  for (const k in cuenta) cuenta[k] = 1; // cada enlace en su propio carril (sin haces) // solo se agrupan enlaces del mismo estado y tipo
  const refs = {}; const ref = (k, g) => (refs[k] ||= { g });
  const cfB = caja("cloudflare"), busX = cfB ? cfB.x + cfB.w + 9 : 0;
  const nxB = caja("nginx"), yTr = cfB && nxB ? Math.max(cfB.y + 40, Math.min(cfB.y + cfB.h - 30, nxB.y + nxB.h / 2)) : 0;
  for (const e of M.E) {
    const A = caja(e.a), B = caja(e.b);
    if (!A || !B) continue;
    const ia = colDe(e.a), ib = colDe(e.b);
    let pts;
    if (e.via?.bus) { const ay = A.y + Math.min(A.h / 2, 22); pts = [[A.x + A.w, ay], [busX, ay], [busX, yTr]]; e.sinPunta = true; }
    else if (e.via?.tronco) { const ty = B.y + B.h / 2; pts = [[busX, yTr], [{ g: ia }, yTr], [{ g: ia }, ty], [B.x, ty]]; }
    else if (e.via?.bajo != null) {
      const sx = A.x + A.w, sy = yAnc(sal[e.a], e, A), tx = B.x, ty = yAnc(ent[e.b], e, B);
      const yb = fondo + 18 + e.via.bajo * 10, xa = A.x + A.w / 2, xr = B.x + B.w + 12, yt = B.y + B.h / 2;
      pts = [[xa, A.y + A.h], [xa, yb], [xr, yb], [xr, yt], [B.x + B.w, yt]];
    } else if (ia === ib || ia < 0 || ib < 0) {
      const ay = A.y + A.h / 2 + 6, by = B.y + B.h / 2 - 6;
      pts = [[A.x + A.w, ay], [{ g: ia }, ay], [{ g: ia }, by], [B.x + B.w, by]];
    } else {
      const der = ib > ia;
      const sx = der ? A.x + A.w : A.x, tx = der ? B.x : B.x + B.w;
      const ga = der ? ia : ia - 1, gb = der ? ib - 1 : ib;
      const hs = cuenta["s" + e.a + ga] > 1, ht = cuenta["t" + e.b + gb] > 1;
      const sy = hs ? A.y + A.h / 2 : yAnc(sal[e.a], e, A), ty = ht ? B.y + B.h / 2 : yAnc(ent[e.b], e, B);
      const Ga = hs ? ref("s" + e.a + ga, ga) : { g: ga }, Gb = ht ? ref("t" + e.b + gb, gb) : ga === gb ? Ga : { g: gb };
      if (ga === gb) { const G = hs ? Ga : Gb; pts = [[sx, sy], [G, sy], [G, ty], [tx, ty]]; }
      else { const cols = []; for (let c = Math.min(ia, ib) + 1; c < Math.max(ia, ib); c++) cols.push(c);
        const yc = canalY(cols, ty);
        pts = [[sx, sy], [Ga, sy], [Ga, yc], [Gb, yc], [Gb, ty], [tx, ty]]; }
    }
    for (let k = 1; k < pts.length - 1; k++) if (typeof pts[k][0] === "object" && typeof pts[k + 1][0] === "object" && pts[k + 1][0].g === pts[k][0].g) pts[k + 1][0] = pts[k][0];
    for (let k = 1; k < pts.length - 1; k++) if (typeof pts[k][0] === "object" && pts[k + 1] && pts[k + 1][0] === pts[k][0]) {
      const g = pts[k][0].g, y1 = pts[k][1], y2 = pts[k + 1][1];
      (verts[g] ||= []).push({ ref: pts[k][0], y1: Math.min(y1, y2), y2: Math.max(y1, y2), salida: pts[k - 1][0] });
    }
    rutas.push([e, pts]);
  }
  // 2) carriles: cada tramo vertical tiene su propio carril; el orden se elige para minimizar cruces
  const polil = (crudo) => crudo.map(([x, y]) => [typeof x === "object" ? x.x : x, y]);
  const cruces = (lista) => { // cruces entre tramos horizontales y verticales de distintas rutas
    const segs = lista.map((c) => { const p = polil(c), h = [], v = []; for (let i = 0; i < p.length - 1; i++) { const [x1, y1] = p[i], [x2, y2] = p[i + 1]; if (Math.abs(y1 - y2) < 0.5) h.push([Math.min(x1, x2), Math.max(x1, x2), y1]); else v.push([x1, Math.min(y1, y2), Math.max(y1, y2)]); } return { h, v }; });
    let n = 0;
    for (let i = 0; i < segs.length; i++) for (let j = 0; j < segs.length; j++) if (i !== j)
      for (const [xa, xb, y] of segs[i].h) for (const [x, ya, yb] of segs[j].v) if (x > xa + 1 && x < xb - 1 && y > ya + 1 && y < yb - 1) n++;
    return n;
  };
  const grupos = {};
  for (const g in verts) {
    const porRef = new Map(); for (const v of verts[g]) { const o = porRef.get(v.ref); if (o) { o.y1 = Math.min(o.y1, v.y1); o.y2 = Math.max(o.y2, v.y2); } else porRef.set(v.ref, { ...v }); }
    const vs = [...porRef.values()].sort((p, q) => p.y1 - q.y1 || p.y2 - q.y2);
    const n = vs.length, paso = Math.min(10, (GAP - 14) / Math.max(1, n - 1));
    const xs = vs.map((_, i) => gx(+g) + (i - (n - 1) / 2) * paso);
    vs.forEach((v, i) => (v.ref.x = xs[i]));
    grupos[g] = { vs, xs, rutasG: rutas.filter(([, c]) => c.some(([x]) => typeof x === "object" && vs.some((v) => v.ref === x))).map(([, c]) => c) };
  }
  const permutar = (arr) => arr.length <= 1 ? [arr] : arr.flatMap((x, i) => permutar([...arr.slice(0, i), ...arr.slice(i + 1)]).map((r) => [x, ...r]));
  const todas = rutas.map(([, c]) => c);
  for (let pasada = 0; pasada < 2; pasada++) for (const g in grupos) {
    const { vs, xs, rutasG } = grupos[g]; if (vs.length < 2 || vs.length > 7) continue;
    let mejor = null, mejorN = Infinity;
    for (const orden of permutar(vs.map((_, i) => i))) { orden.forEach((k, i) => (vs[k].ref.x = xs[i])); const c = cruces(rutasG); if (c < mejorN) { mejorN = c; mejor = orden; if (!c) break; } }
    mejor.forEach((k, i) => (vs[k].ref.x = xs[i]));
  }
  const tintes = [...new Set(M.E.map((e) => e.tinte).filter(Boolean))];
  let html = `<defs>${["ok", "warn", "mal", "gris"].map((k) => `<marker id="fl-${k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse" markerUnits="userSpaceOnUse"><path d="M0,0 L10,5 L0,10 z" class="punta ${k}"/></marker>`).join("")}${tintes.map((t) => `<marker id="fl-t${t.slice(1)}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse" markerUnits="userSpaceOnUse"><path d="M0,0 L10,5 L0,10 z" fill="${t}"/></marker>`).join("")}</defs>`;
  ENLACES = [];
  for (const [e, crudo] of rutas) {
    const pts = crudo.map(([x, y]) => [typeof x === "object" ? x.x : x, y]);
    const tin = e.tinte && e.est === "ok" ? e.tinte : null;
    const d = ruta(pts), activo = e.tipo !== "planeado" && e.est !== "gris";
    html += `<g class="g-enl" data-a="${e.a}" data-b="${e.b}">
      <path class="enl ${e.est} ${e.tipo} ${activo && e.tipo === "medido" ? "base" : ""} ${e.via?.tronco ? "tronco" : ""} ${e.via?.bus ? "stub" : ""}" d="${d}" ${tin ? `style="stroke:${tin}"` : ""} ${e.sinPunta ? "" : `${e.inverso ? "marker-start" : "marker-end"}="url(#fl-${tin ? "t" + tin.slice(1) : e.est})"`}/>
      ${e.etqVertical ? (() => { const v = pts.findIndex((p, i) => i && Math.abs(p[0] - pts[i - 1][0]) < 0.5), x = pts[v][0] + 4, y = (pts[v][1] + pts[v - 1][1]) / 2; return `<text class="enl-lbl" text-anchor="middle" transform="translate(${x + 5},${y}) rotate(90)" ${tin ? `style="fill:${tin}"` : ""}>${e.etqVertical}</text>`; })() : ""}
      ${e.etiqueta ? `<text class="enl-lbl" text-anchor="end" x="${pts.at(-1)[0] - 9}" y="${pts.at(-1)[1] - 5}" ${tin ? `style="fill:${tin}"` : ""}>${e.etiqueta}</text>` : ""}
      ${e.via?.tronco ? `<text class="tronco-lbl" text-anchor="middle" x="${(pts[0][0] + pts.at(-1)[0]) / 2 + 4}" y="${pts.at(-1)[1] - 16}">${M.mon.actividad?.reqMin ?? "—"}<tspan class="u" x="${(pts[0][0] + pts.at(-1)[0]) / 2 + 4}" dy="9">req/min</tspan></text>` : ""}
      ${activo ? `<path class="flujo ${e.est}" d="${d}" style="${tin ? `stroke:${tin};color:${tin};` : ""}animation-duration:${(e.dur * LENTO).toFixed(2)}s;opacity:${e.brillo};${e.inverso ? "animation-direction:reverse" : ""}"/>` : ""}
      ${activo ? Array.from({ length: e.particulas }, (_, k) => `<circle class="particula" r="${e.tipo === "medido" ? 2.6 : 2}" fill="${tin || (e.est === "ok" ? "#d9f99d" : e.est === "warn" ? "#fcd34d" : "#fca5a5")}" color="${e.est === "ok" ? "#a3e635" : e.est === "warn" ? "#f59e0b" : "#ef4444"}" opacity="${e.brillo}"><animateMotion dur="${(e.dur * 2.2 * LENTO).toFixed(2)}s" begin="-${((k / e.particulas) * e.dur * 2.2 * LENTO).toFixed(2)}s" repeatCount="indefinite" ${e.inverso ? 'keyPoints="1;0" keyTimes="0;1" calcMode="linear"' : ""} path="${d}"/></circle>`).join("") : ""}
      <circle class="extremo ${e.est}" cx="${pts[0][0]}" cy="${pts[0][1]}" r="2.6"/></g>`;
    ENLACES.push(e);
  }
  svg.innerHTML = html;
  H = Math.max(560, fondo + 50, TOP + COL_ALTO + 30); $("lienzo").style.height = H + "px";
  document.querySelectorAll(".capa-fondo").forEach((f) => (f.style.height = H - 70 + "px"));
  if (vista.ajustada) ajustar();
  if (seleccion) resaltar(seleccion);
}

/* =================== selección y panel =================== */
function relacionados(id) {
  const ids = new Set([id]);
  const padreDe = (x) => Object.values(NODOS).find((n) => (n.hijos || []).includes(x))?.id;
  const conHijos = (x) => [x, ...(NODOS[x]?.hijos || [])];
  const propios = new Set(conHijos(id));
  if (NODOS[id]?.ruta) { const r = new Set([id, ...NODOS[id].ruta]); r.forEach((x) => ids.add(x)); [...ids].forEach((x) => { const p = padreDe(x); if (p) ids.add(p); });
    return { ids, propios: r, soloRuta: true }; }

  for (const e of ENLACES) if (propios.has(e.a) || propios.has(e.b)) { ids.add(e.a); ids.add(e.b); }
  propios.forEach((x) => ids.add(x));
  [...ids].forEach((x) => { const p = padreDe(x); if (p) ids.add(p); });
  return { ids, propios };
}
function resaltar(id) {
  const { ids, propios } = relacionados(id);
  $("lienzo").classList.add("dim");
  document.querySelectorAll("#nodos-diagrama .nodo").forEach((el) => { el.classList.toggle("rel", ids.has(el.dataset.id)); el.classList.toggle("sel", el.dataset.id === id); });
  const r = relacionados(id);
  document.querySelectorAll(".g-enl").forEach((g) => g.classList.toggle("rel", r.soloRuta ? propios.has(g.dataset.a) && propios.has(g.dataset.b) : propios.has(g.dataset.a) || propios.has(g.dataset.b)));
}
function seleccionar(id) {
  seleccion = id; resaltar(id);
  const n = NODOS[id];
  const con = ENLACES.filter((e) => e.a === id || e.b === id);
  $("panel-cuerpo").innerHTML = `<div class="p-tag">${esc(n.tag)}</div><div class="p-tit">${esc(n.tit)}</div><div class="tenue">${esc(n.st)}</div>
    <div class="p-est"><i class="dot ${n.est}"></i>${TXT[n.est]}${n.inferido ? " · INFERIDO" : ""}</div>
    ${n.met ? `<div class="metricas" style="border:0;margin:0 0 6px;padding:0">${n.met.join("")}</div>` : ""}
    <table class="kv">${(n.det || []).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join("") || '<tr><td colspan="2" class="tenue">Sin detalle</td></tr>'}</table>
    ${con.length ? `<div class="p-sec">CONEXIONES (${con.length})</div>` + con.map((e) => { const o = NODOS[e.a === id ? e.b : e.a]; return `<div class="p-con"><i class="dot ${e.est}"></i>${e.a === id ? "→" : "←"} ${esc(o.tit)} <span class="tenue">· ${e.tipo}</span></div>`; }).join("") : ""}
    ${n.hijos?.length ? `<div class="p-sec">CONTIENE</div>` + n.hijos.map((h) => `<div class="p-con"><i class="dot ${NODOS[h].est}"></i>${esc(NODOS[h].tit)} <span class="tenue">· ${esc(NODOS[h].st)}</span></div>`).join("") : ""}`;
  $("panel-cuerpo").insertAdjacentHTML("beforeend", '<div id="panel-graficas"><div class="p-sec">CARGANDO HISTORIAL…</div></div>');
  $("panel").classList.add("abierto");
  graficasPanel(id);
}
async function obtenerHistorial(rango) {
  const c = historial[rango];
  if (c && Date.now() - c.en < 55000) return c.d;
  const r = await fetch(`${C.api}/historial?rango=${rango}`, { headers: { Authorization: `Bearer ${token()}`, Accept: "application/json" } });
  if (!r.ok) throw new Error("HTTP " + r.status);
  const d = filtrarHistorial(await r.json()); historial[rango] = { en: Date.now(), d }; return d;
}
const serie = (P, f) => P.map((p) => { try { const v = f(p); return v == null ? null : v; } catch { return null; } });
function graficasDeNodo(id, H) {
  const n = NODOS[id], P = H.puntos || [], ts = P.map((p) => p.t), o = { w: 330, h: 110 };
  const marcas = (H.incidentes || []).filter((i) => i.tipo !== "reinicio").map((i) => ({ t: i.inicio }));
  const lat = (k, t) => grafica(t || "LATENCIA " + k, ts, [{ n: k, v: serie(P, (p) => p.chk[k]?.[1]) }], { ...o, unidad: " ms", fmt: (v) => v.toFixed(0), marcas });
  const mem = (k) => grafica("MEMORIA " + k, ts, [{ n: k, v: serie(P, (p) => p.svc[k]?.[1]), c: "#38bdf8" }], { ...o, unidad: " MB" });
  if (id === "vps") return grafica("CPU %", ts, [{ n: "CPU", v: serie(P, (p) => p.cpu) }], { ...o, max: 100, unidad: "%" }) + grafica("RAM %", ts, [{ n: "RAM", v: serie(P, (p) => p.mem), c: "#38bdf8" }], { ...o, max: 100, unidad: "%" })
    + grafica("CARGA 1 MIN", ts, [{ n: "carga", v: serie(P, (p) => p.carga), c: "#f59e0b" }], o) + grafica("RED KB/S", ts, [{ n: "↓ rx", v: serie(P, (p) => p.rx / 1024) }, { n: "↑ tx", v: serie(P, (p) => p.tx / 1024), c: "#e879f9" }], o);
  if (n?.chk) return lat(n.chk, "LATENCIA (VÍA CLOUDFLARE)");
  if (id === "nginx" || id === "usuarios") return grafica("PETICIONES / " + (H.resolucionSegundos > 60 ? "10 MIN" : "MIN"), ts, [{ n: "req", v: serie(P, (p) => p.req) }, { n: "5xx", v: serie(P, (p) => p.e5), c: "#ef4444" }], o) + (id === "nginx" ? mem("nginx") : "");
  if (["igas-console", "zia-chatbot", "abp-template"].includes(id)) return lat("local:" + id, "LATENCIA LOCAL") + mem(id);
  if (id === "postgres" || id.startsWith("db-")) return mem("postgresql");
  if (id === "fail2ban" || id === "ssh") return grafica("BANEOS", ts, [{ n: "baneadas", v: serie(P, (p) => p.bans), c: "#f59e0b" }, { n: "nuevas", v: serie(P, (p) => p.nb), c: "#ef4444" }], o);
  if (id === "cloudflare") return grafica("LATENCIA PÚBLICA", ts, Object.keys(P.at(-1)?.chk || {}).filter((k) => !k.startsWith("local:")).map((k) => ({ n: k, v: serie(P, (p) => p.chk[k]?.[1]) })), { ...o, unidad: " ms", fmt: (v) => v.toFixed(0) });
  return "";
}
function incidentesHtml(lista) {
  if (!lista.length) return '<div class="tenue" style="grid-column:1/-1">Sin incidentes en el periodo.</div>';
  return lista.map((i) => `<div class="inc ${i.severidad} ${i.fin ? "cerrado" : ""}"><i class="dot ${i.fin ? (i.severidad === "info" ? "gris" : "ok") : i.severidad === "aviso" ? "warn" : "mal"}" style="margin-top:4px"></i>
    <div><div class="t">${esc(i.titulo)}</div><div class="d">${esc(i.detalle || i.tipo)}${i.fin && i.fin !== i.inicio ? ` · duró ${dur(i.fin - i.inicio)}` : i.fin ? "" : " · ACTIVO"}</div></div>
    <div class="h">${fecha(i.inicio * 1000)}<br>${i.fin ? (i.fin === i.inicio ? "evento" : "resuelto " + new Date(i.fin * 1000).toLocaleTimeString("es-MX", { hour: "2-digit", minute: "2-digit" })) : '<span style="color:var(--mal)">en curso</span>'}</div></div>`).join("");
}
async function graficasPanel(id) {
  const caja2 = $("panel-graficas"); if (!caja2) return;
  try {
    const H = await obtenerHistorial("24h"); if (seleccion !== id) return;
    const n = NODOS[id];
    const objs = new Set([id, n.chk, id === "postgres" ? "postgresql" : null, ...(id === "vps" ? ["/", "RAM"] : [])].filter(Boolean));
    const inc = (H.incidentes || []).filter((i) => objs.has(i.objeto));
    const g = graficasDeNodo(id, H);
    caja2.innerHTML = (g ? `<div class="p-sec">ÚLTIMAS 24 H</div>${g}` : "") + `<div class="p-sec">INCIDENTES RECIENTES (${inc.length})</div><div style="display:grid;gap:6px">${incidentesHtml(inc.slice(0, 8))}</div>`;
  } catch (e) { caja2.innerHTML = `<div class="tenue">Historial no disponible (${esc(e.message)}).</div>`; }
}
function deseleccionar() {
  seleccion = null; $("panel").classList.remove("abierto"); $("lienzo").classList.remove("dim");
  document.querySelectorAll(".rel,.sel").forEach((e) => e.classList.remove("rel", "sel"));
}
$("panel-cerrar").onclick = deseleccionar;

/* =================== pan / zoom =================== */
const vista = { s: 1, x: 0, y: 0, ajustada: true };
const W = COLX0 * 2 + COLP * 8 - GAP; let H = 860;
function aplicar() { $("lienzo").style.transform = `translate(${vista.x}px,${vista.y}px) scale(${vista.s})`; }
function ajustar() {
  const v = $("viewport"), vw = v.clientWidth, vh = v.clientHeight;
  const fit = Math.min(vw / W, vh / H);
  if (vw < 820) { vista.s = Math.max(fit, Math.min(0.5, vh / H)); vista.x = 8; vista.y = 4; }
  else { vista.s = Math.min(fit, 1.15); vista.x = (vw - W * vista.s) / 2; vista.y = Math.max(0, (vh - H * vista.s) / 2); }
  vista.ajustada = true; aplicar();
}
function zoom(f, cx, cy) {
  const v = $("viewport").getBoundingClientRect(); cx ??= v.width / 2; cy ??= v.height / 2;
  const s = Math.min(2.5, Math.max(0.2, vista.s * f)); f = s / vista.s;
  vista.x = cx - (cx - vista.x) * f; vista.y = cy - (cy - vista.y) * f; vista.s = s; vista.ajustada = false; aplicar();
}
(function panZoom() {
  const v = $("viewport"), ptrs = new Map(); let ini = null, movido = false;
  v.addEventListener("wheel", (e) => { e.preventDefault(); const r = v.getBoundingClientRect(); zoom(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top); }, { passive: false });
  v.addEventListener("pointerdown", (e) => { ptrs.set(e.pointerId, e); movido = false; ini = { x: e.clientX - vista.x, y: e.clientY - vista.y, d: null }; });
  v.addEventListener("pointermove", (e) => {
    if (!ptrs.has(e.pointerId)) return; ptrs.set(e.pointerId, e);
    if (ptrs.size === 2) {
      const [p, q] = [...ptrs.values()], d = Math.hypot(p.clientX - q.clientX, p.clientY - q.clientY), r = v.getBoundingClientRect();
      if (ini.d) zoom(d / ini.d, (p.clientX + q.clientX) / 2 - r.left, (p.clientY + q.clientY) / 2 - r.top);
      ini.d = d; movido = true; return;
    }
    const nx = e.clientX - ini.x, ny = e.clientY - ini.y;
    if (!movido && Math.hypot(nx - vista.x, ny - vista.y) < 4) return;
    if (!movido) v.setPointerCapture(e.pointerId);
    movido = true; v.classList.add("arrastrando"); vista.x = nx; vista.y = ny; vista.ajustada = false; aplicar();
  });
  const fin = (e) => { ptrs.delete(e.pointerId); v.classList.remove("arrastrando"); if (ptrs.size === 1) { const p = [...ptrs.values()][0]; ini = { x: p.clientX - vista.x, y: p.clientY - vista.y, d: null }; } };
  v.addEventListener("pointerup", fin); v.addEventListener("pointercancel", fin);
  v.addEventListener("click", (e) => { if (!movido && !e.target.closest(".nodo,.zoom")) deseleccionar(); }, true);
  $("z-mas").onclick = () => zoom(1.2); $("z-menos").onclick = () => zoom(1 / 1.2); $("z-fit").onclick = ajustar;
  let tRes; addEventListener("resize", () => { clearTimeout(tRes); tRes = setTimeout(() => { if (ULTIMO_M && !$("v-arquitectura").classList.contains("oculto")) { distribuir(); trazarEnlaces(ULTIMO_M); } else if (vista.ajustada) ajustar(); }, 120); });
})();

/* =================== pestañas de lista =================== */
const fila = (n, extra = "") => !n ? "" : tarjeta({ ...n, hijos: null }, NODOS).replace("</div>\n  </div>", `${extra}</div>\n  </div>`);
function pintarListas(d, M) {
  const inst = d.instantanea || {};
  $("v-servicios").innerHTML = `<h2>SERVIDOR</h2>${fila(NODOS.vps)}${fila(NODOS.postgres)}${fila(NODOS.historial)}${fila(NODOS.firewall)}<h2>TAREAS PROGRAMADAS</h2>${Object.values(NODOS).filter((n) => n.capa === "cron").map((n) => fila(n)).join("")}<h2>SERVICIOS SYSTEMD</h2>` +
    (d.servicios || []).map((s) => fila(NODOS[s.nombre] || { id: s.nombre, tit: s.nombre, st: s.descripcion, tag: "SERVICIO", ico: "servidor", est: s.estado === "active" ? "ok" : "mal",
      met: [met("mem", bytes(s.memoriaBytes)), met("reloj", s.activoDesdeUtc ? hace(s.activoDesdeUtc) : "—"), met("con", `${s.reinicios ?? "—"} reinic.`)] })).join("") +
    `<h2>DISCOS</h2>` + (d.discos || []).map((x) => { const u = 100 * (1 - x.libreBytes / x.totalBytes); const e = umbral(u, 80, 92);
      return `<div class="nodo sub ${e}"><div class="n-cab"><span class="n-ico">${ICO.disk}</span><div class="n-cuerpo"><div class="n-tit">${esc(x.montaje)}</div><div class="n-st">${bytes(x.totalBytes - x.libreBytes)} de ${bytes(x.totalBytes)} · ${u.toFixed(0)} %</div></div><div class="n-tag">DISCO <i class="dot ${e}"></i></div></div><div class="barra"><i style="width:${u}%"></i></div></div>`; }).join("");
  const f2b = inst.fail2ban || {};
  $("v-seguridad").innerHTML = `<h2>FAIL2BAN · BANEOS POR JAIL</h2>` + (Object.entries(f2b).map(([j, v]) => { const e = v.baneadosAhora > 20 ? "warn" : "ok";
      return `<div class="nodo ${e}"><div class="n-cab"><span class="n-ico">${ICO.escudo}</span><div class="n-cuerpo"><div class="n-tit">${esc(j)}</div><div class="n-st">${v.baneadosTotal} baneos totales · ${v.fallosTotal} fallos</div></div><div class="n-tag">JAIL <i class="dot ${e}"></i></div></div>
      <div class="metricas">${met("con", `${v.baneadosAhora} ahora`)}${met("reloj", `${v.baneos1h} en 1 h`)}${met("reloj", `${v.baneos24h} en 24 h`)}</div></div>`; }).join("") || `<div class="tenue">Sin datos del colector</div>`) +
    fila(NODOS.ssh) + `<h2>CERTIFICADOS TLS DE ORIGEN</h2>` +
    [...(inst.certificados || [])].sort((a, b) => a.diasRestantes - b.diasRestantes).map((c) => { const e = umbral(-c.diasRestantes, -30, -7);
      return `<div class="nodo sub ${e}"><div class="n-cab"><span class="n-ico">${ICO.candado}</span><div class="n-cuerpo"><div class="n-tit">${esc(c.nombre)}</div><div class="n-st">${esc((c.dominios || []).join(" · "))}</div></div><div class="n-tag">${Math.floor(c.diasRestantes)} DÍAS <i class="dot ${e}"></i></div></div>
      <div class="barra"><i style="width:${Math.min(100, c.diasRestantes / 90 * 100)}%;background:var(--${e === "ok" ? "lima" : e})"></i></div><div class="n-st" style="margin-top:5px">vence ${fecha(c.venceUtc)}</div></div>`; }).join("");
  const nodos = inst.nodos || [];
  $("v-nodos").innerHTML = `<h2>NODOS DE ESTACIÓN · LATIDO</h2>` + (nodos.map((n) => { const s = n.ultimoLatidoUtc ? (Date.now() - new Date(n.ultimoLatidoUtc)) / 1000 : Infinity; const e = n.revocado ? "mal" : s < 600 ? "ok" : s < 3600 ? "warn" : "mal";
      return `<div class="nodo ${e}"><div class="n-cab"><span class="n-ico">${ICO.bomba}</span><div class="n-cuerpo"><div class="n-tit">${esc(n.equipo || "nodo")}</div><div class="n-st">${esc(n.permiso)}</div></div><div class="n-tag">NODO <i class="dot ${e}"></i></div></div>
      <div class="metricas">${met("reloj", n.ultimoLatidoUtc ? "latido hace " + hace(n.ultimoLatidoUtc) : "sin latido", e)}${met("con", `cola ${n.colaPendiente}`)}${met("servidor", "v" + (n.version || "?"))}</div></div>`; }).join("") || `<div class="tenue">No hay nodos registrados.</div>`) + `<h2>DESPLIEGUES</h2>${fila(NODOS.github)}`;
}

async function pintarMetricas() {
  const v = $("v-metricas"); v.classList.add("metricas-v");
  const botones = ["1h", "6h", "24h", "7d", "30d"].map((r) => `<button data-r="${r}" class="${r === rangoMetricas ? "activo" : ""}">${r.toUpperCase()}</button>`).join("");
  if (!v.querySelector(".rango")) v.innerHTML = `<div class="rango">${botones}<span class="tenue" id="m-info"></span></div><div id="m-cuerpo" style="display:contents"></div>`;
  v.querySelectorAll(".rango button").forEach((b) => { b.classList.toggle("activo", b.dataset.r === rangoMetricas); b.onclick = () => { rangoMetricas = b.dataset.r; pintarMetricas(); }; });
  let H; try { H = await obtenerHistorial(rangoMetricas); } catch (e) { $("m-cuerpo").innerHTML = `<div class="tenue">Historial no disponible (${esc(e.message)}).</div>`; return; }
  const P = H.puntos || [], ts = P.map((p) => p.t), agg = H.resolucionSegundos > 60;
  const marcas = (H.incidentes || []).filter((i) => i.tipo !== "reinicio").map((i) => ({ t: i.inicio }));
  const ult = P.at(-1) || { chk: {}, svc: {} };
  const pub = Object.keys(ult.chk).filter((k) => !k.startsWith("local:")), loc = Object.keys(ult.chk).filter((k) => k.startsWith("local:"));
  const disp = (k) => { let a = 0, t = 0; for (const p of P) { const x = p.chk[k]; if (!x) continue; a += x[0]; t += agg ? p.n : 1; } return t ? 100 * a / t : null; };
  $("m-info").textContent = `${P.length} puntos · resolución ${agg ? "10 min" : "1 min"} · líneas rojas = inicio de incidente`;
  $("m-cuerpo").innerHTML =
    grafica("CPU %", ts, [{ n: "promedio", v: serie(P, (p) => p.cpu) }, ...(agg ? [{ n: "máximo", v: serie(P, (p) => p.cpuMax), c: "#f59e0b" }] : [])], { max: 100, unidad: "%", marcas }) +
    grafica("RAM %", ts, [{ n: "RAM", v: serie(P, (p) => p.mem), c: "#38bdf8" }], { max: 100, unidad: "%", marcas }) +
    grafica("DISCO / %", ts, [{ n: "disco", v: serie(P, (p) => p.disco), c: "#e879f9" }], { max: 100, unidad: "%" }) +
    grafica("CARGA 1 MIN", ts, [{ n: "carga", v: serie(P, (p) => p.carga), c: "#f59e0b" }]) +
    grafica("RED KB/S", ts, [{ n: "↓ rx", v: serie(P, (p) => p.rx / 1024) }, { n: "↑ tx", v: serie(P, (p) => p.tx / 1024), c: "#e879f9" }]) +
    grafica(`PETICIONES NGINX / ${agg ? "10 MIN" : "MIN"}`, ts, [{ n: "peticiones", v: serie(P, (p) => p.req) }, { n: "5xx", v: serie(P, (p) => p.e5), c: "#ef4444" }], { marcas }) +
    grafica(Z ? "LATENCIA PÚBLICA (VÍA CLOUDFLARE) MS" : "LATENCIA PÚBLICA (DUCKDNS) MS", ts, pub.map((k) => ({ n: k, v: serie(P, (p) => p.chk[k]?.[1]) })), { unidad: " ms", fmt: (x) => x.toFixed(0), marcas }) +
    grafica("LATENCIA LOCAL MS", ts, loc.map((k) => ({ n: k.replace("local:", ""), v: serie(P, (p) => p.chk[k]?.[1]) })), { unidad: " ms", fmt: (x) => x.toFixed(0) }) +
    grafica("MEMORIA POR SERVICIO MB", ts, Object.keys(ult.svc).filter((k) => ult.svc[k][1] != null).map((k) => ({ n: k, v: serie(P, (p) => p.svc[k]?.[1]) })), { unidad: " MB" }) +
    grafica("FAIL2BAN · BANEOS", ts, [{ n: "baneadas ahora", v: serie(P, (p) => p.bans), c: "#f59e0b" }, { n: "nuevas", v: serie(P, (p) => p.nb), c: "#ef4444" }]) +
    `<div class="grafica"><div class="g-tit"><span>DISPONIBILIDAD EN EL RANGO</span><b>${rangoMetricas}</b></div><table class="kv">${[...pub, ...loc].map((k) => { const d2 = disp(k); return `<tr><td>${esc(k)}</td><td><span class="up ${d2 == null ? "" : d2 < 99 ? "mal" : d2 < 99.9 ? "warn" : ""}">${d2 == null ? "—" : d2.toFixed(2) + "%"}</span></td></tr>`; }).join("")}</table></div>` +
    `<div class="grafica"><div class="g-tit"><span>UPTIME DE SERVICIOS</span><b>24H · 7D · 30D</b></div><table class="kv">${Object.entries((datos.instantanea?.monitoreo || {}).servicios || {}).map(([k, m]) => `<tr><td>${esc(k)}</td><td>${["24h", "7d", "30d"].map((r) => `<span class="up ${m.uptime[r] < 99 ? "mal" : m.uptime[r] < 99.9 ? "warn" : ""}">${m.uptime[r] == null ? "—" : m.uptime[r].toFixed(2) + "%"}</span>`).join(" ")} <span class="tenue">· ${m.reinicios} reinic.</span></td></tr>`).join("")}</table></div>`;
}
function pintarIncidentes() {
  const mon = datos.instantanea?.monitoreo || {};
  const act = mon.alertasActivas || [];
  $("v-incidentes").innerHTML = `<h2>ALERTAS ACTIVAS (${act.length})</h2>` +
    (act.length ? act.map((a) => `<div class="inc critico"><i class="dot mal" style="margin-top:4px"></i><div><div class="t">${esc(a.titulo)}</div><div class="d">${esc(a.clave)}</div></div><div class="h">desde ${fecha(a.inicio * 1000)}<br>hace ${dur(Date.now() / 1000 - a.inicio)}</div></div>`).join("") : '<div class="inc"><i class="dot ok" style="margin-top:4px"></i><div><div class="t">Todo en orden</div><div class="d">No hay alertas activas</div></div></div>') +
    `<h2>REGISTRO DE INCIDENTES (30 DÍAS)</h2>${incidentesHtml(mon.incidentes || [])}` +
    `<h2>REGLAS DE ALERTA · TELEGRAM GRUPO VPS</h2><div class="reglas">${(mon.reglas || []).map((r) => "▸ " + esc(r)).join("<br>")}<br>Con deduplicación, recordatorio espaciado (3–24 h) y aviso de recuperación.</div>`;
}

/* =================== pills y pantallas =================== */
function pintarPills(M) {
  const enl = M.E.filter((e) => e.tipo !== "planeado"), enlOk = enl.filter((e) => e.est === "ok").length;
  const svcs = M.resumen.servicios, srvOk = M.resumen.srvOk;
  const certs = M.resumen.certs, certOk = certs.filter((c) => c.diasRestantes >= 30).length;
  const nucleo = Z ? ["vps", "nginx", "igas-console", "zia-chatbot", "postgres", "historial", "cloudflare"] : ["vps", "nginx", "abp-template", "postgres", "cloudflare"];
  const crit = Object.values(M.N).filter((n) => !n.plan && (!n.sub || nucleo.includes(n.id))).map((n) => (nucleo.includes(n.id) || n.est !== "mal" ? n.est : "warn"));
  const global = crit.includes("mal") ? "mal" : crit.includes("warn") || srvOk < svcs.length ? "warn" : "ok";
  const p = (v, t, e) => `<div class="pill ${e}"><b>${v}</b><small>${t}</small></div>`;
  $("pills").innerHTML = p({ ok: "OPERANDO", warn: "DEGRADADO", mal: "FALLA" }[global], "salud global", global) +
    p(`${srvOk}/${svcs.length}`, "servicios ok", srvOk === svcs.length ? "ok" : "mal") +
    p(`${enlOk}/${enl.length}`, "enlaces ok", enlOk === enl.length ? "ok" : enl.some((e) => e.est === "mal") ? "mal" : "warn") +
    p(`${certOk}/${certs.length}`, "certs ≥30d", certOk === certs.length ? "ok" : certs.some((c) => c.diasRestantes < 7) ? "mal" : "warn") +
    p((M.mon.alertasActivas || []).length, "alertas", (M.mon.alertasActivas || []).length ? "mal" : "ok");
}
function mostrar(v) {
  document.body.classList.toggle("sin-datos", !datos);
  for (const s of ["v-login", "v-error", "v-arquitectura", "v-servicios", "v-seguridad", "v-nodos", "v-metricas", "v-incidentes"]) $(s).classList.toggle("oculto", s !== v);
  const enPanel = v.startsWith("v-") && !["v-login", "v-error"].includes(v);
  $("tabs").style.visibility = $("pills").style.visibility = enPanel || datos ? "visible" : "hidden";
  $("leyenda").classList.toggle("oculto", v !== "v-arquitectura");
  if (v === "v-arquitectura") requestAnimationFrame(() => { if (ULTIMO_M) { distribuir(); trazarEnlaces(ULTIMO_M); } else if (vista.ajustada) ajustar(); });
}
function error(tag, titulo, texto) { $("err-tag").textContent = tag; $("err-titulo").textContent = titulo; $("err-texto").textContent = texto; mostrar("v-error"); }
function sesionUI() {
  $("sesion").innerHTML = token() ? `<span class="tenue">${esc(usuario())}</span> <button id="btn-cerrar">SALIR</button>` : "";
  if (token()) $("btn-cerrar").onclick = cerrarSesion;
}
document.querySelectorAll("#tabs button").forEach((b) => b.onclick = () => {
  tab = b.dataset.tab; deseleccionar(); document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("activo", x === b));
  if (datos) { mostrar("v-" + tab); if (tab === "metricas") pintarMetricas(); }
});

/* =================== ciclo de datos =================== */
async function cargar() {
  sesionUI();
  if (!token()) { datos = null; mostrar("v-login"); return; }
  let r;
  try { r = await fetch(C.api, { headers: { Authorization: `Bearer ${token()}`, Accept: "application/json", "Accept-Language": "es" } }); }
  catch { return datos ? marcarViejo() : error("SIN CONEXIÓN", "API no disponible", "No se pudo contactar a api.ziacentro.mx. Se reintentará en el próximo ciclo."); }
  if (r.status === 401) { ss.removeItem("access_token"); datos = null; sesionUI(); return mostrar("v-login"); }
  if (r.status === 403) { datos = null; return error("403 · SIN PERMISO", "Sin permiso",
    `Tu usuario (${usuario()}) no tiene el permiso «Ver el panel del VPS» (IgasConsole.Monitoreo.VerVps). Pide que te lo asignen en ZIA-Console › Administración › Roles, o entra con la cuenta admin.`); }
  if (!r.ok) return datos ? marcarViejo() : error(`HTTP ${r.status}`, "Error de la API", "La API respondió con un error. Se reintentará en el próximo ciclo.");
  datos = filtrarDatos(await r.json()); ultimoOk = Date.now();
  const M = modelo(datos); NODOS = M.N;
  historial = {}; pintarDiagrama(M); pintarListas(datos, M); pintarIncidentes(); pintarPills(M);
  if (tab === "metricas") pintarMetricas();
  const g = new Date(datos.generadoUtc);
  $("actualizado").textContent = innerWidth < 820 ? g.toLocaleTimeString("es-MX", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : g.toLocaleString("es-MX", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  $("live").classList.remove("off");
  $("nota").textContent = `colector hace ${datos.edadInstantaneaSegundos != null ? Math.round(datos.edadInstantaneaSegundos) + " s" : "—"} · refresco cada ${C.refreshSeconds} s · host ${datos.host}`;
  if ($("v-login").classList.contains("oculto") && $("v-error").classList.contains("oculto") && !document.querySelector(".vista:not(.oculto)")) mostrar("v-" + tab);
  else if (!$("v-login").classList.contains("oculto") || !$("v-error").classList.contains("oculto")) mostrar("v-" + tab);
  if (seleccion && NODOS[seleccion]) seleccionar(seleccion);
}
function marcarViejo() { $("live").classList.add("off"); }

if (!Z) { document.title = "ABP TEMPLATE · PILOTO"; document.querySelectorAll(".titulo").forEach((t) => (t.innerHTML = "ABP TEMPLATE · <b>PILOTO</b>")); }
document.querySelectorAll(".proy a").forEach((a) => a.classList.toggle("activo", a.dataset.p === PROY));
$("btn-login").onclick = iniciarSesion;
$("btn-reintentar").onclick = () => (token() ? cargar() : iniciarSesion());
$("btn-salir").onclick = cerrarSesion;
mostrar("v-login"); $("v-login").classList.add("oculto");
try { await procesarRetorno(); } catch (e) { error("OIDC", "No se pudo iniciar sesión", e.message); }
if ($("v-error").classList.contains("oculto")) await cargar();
setInterval(cargar, C.refreshSeconds * 1000);
setInterval(() => { if (ultimoOk && Date.now() - ultimoOk > (C.refreshSeconds + 30) * 1000) marcarViejo(); }, 5000);
