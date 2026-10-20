const C = window.VPS_CONFIG;
const REDIRECT = location.origin + location.pathname.replace(/index\.html$/, "");
const $ = (id) => document.getElementById(id);
const ss = sessionStorage;
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

/* =================== modelo a partir de la API =================== */
function modelo(d) {
  const inst = d.instantanea || {};
  const srv = Object.fromEntries((d.servicios || []).map((s) => [s.nombre, s]));
  const estSrv = (n) => { const s = srv[n]; if (!s) return "gris"; return s.estado === "active" ? "ok" : s.estado === "activating" || s.estado === "reloading" ? "warn" : s.estado === "desconocido" ? "gris" : "mal"; };
  const certs = inst.certificados || [];
  const certDe = (dom) => certs.find((c) => (c.dominios || []).includes(dom)) || certs.find((c) => (c.dominios || []).some((x) => x.startsWith("*.") && dom.endsWith(x.slice(1))));
  const sitios = (inst.nginx || {}).sitios || [];
  const memPct = d.memoriaTotalBytes ? 100 * (1 - d.memoriaDisponibleBytes / d.memoriaTotalBytes) : null;
  const raiz = (d.discos || []).find((x) => x.montaje === "/") || (d.discos || [])[0];
  const discoPct = raiz ? 100 * (1 - raiz.libreBytes / raiz.totalBytes) : null;
  const f2b = inst.fail2ban || {};
  const bansAhora = Object.values(f2b).reduce((a, j) => a + (j.baneadosAhora || 0), 0);
  const bans24 = Object.values(f2b).reduce((a, j) => a + (j.baneos24h || 0), 0);
  const edad = d.edadInstantaneaSegundos;
  const estColector = edad == null ? "mal" : edad < 150 ? "ok" : edad < 600 ? "warn" : "mal";
  const N = {};
  const add = (id, o) => (N[id] = { id, ...o });

  const svcDetalle = (n) => { const s = srv[n] || {}; return [["Estado systemd", s.estado ? `${s.estado} · ${s.subEstado}` : "sin dato"], ["Puerto", s.puerto || "—"], ["Activo desde", s.activoDesdeUtc ? `${fecha(s.activoDesdeUtc)} (hace ${hace(s.activoDesdeUtc)})` : "—"], ["Memoria", bytes(s.memoriaBytes)], ["Reinicios", s.reinicios ?? "—"], ["Descripción", s.descripcion || "—"]]; };
  const svcMet = (n) => { const s = srv[n] || {}; return [met("mem", bytes(s.memoriaBytes)), met("reloj", s.activoDesdeUtc ? hace(s.activoDesdeUtc) : "—"), met("con", `${s.reinicios ?? "—"} reinic.`, s.reinicios > 3 ? "warn" : "")]; };

  // --- externos
  const nodos = inst.nodos || [];
  const latidos = nodos.filter((n) => !n.revocado).map((n) => n.ultimoLatidoUtc ? (Date.now() - new Date(n.ultimoLatidoUtc)) / 1000 : Infinity);
  const enLinea = latidos.filter((x) => x < 600).length;
  const estGas = !nodos.length ? "gris" : enLinea === latidos.length ? "ok" : enLinea > 0 ? "warn" : "mal";
  add("usuarios", { tit: "Usuarios", st: "Clientes ZIA", tag: "EXTERNO", ico: "usuarios", est: "ok", inferido: true,
    det: [["Qué es", "Personas que usan la consola, la API y la landing"], ["Estado", "Inferido: la API respondió a este panel a través de Cloudflare"]] });
  add("gasolineras", { tit: "Gasolineras", st: `${nodos.length} nodo(s) · ${enLinea} en línea`, tag: "EXTERNO", ico: "bomba", est: estGas,
    met: [met("con", `${enLinea}/${latidos.length} latido`), met("reloj", nodos[0] ? "últ. " + hace(nodos.map((n) => n.ultimoLatidoUtc).sort().pop()) : "—")],
    det: nodos.map((n) => [n.equipo || "nodo", `${n.permiso} · v${n.version || "?"} · ${n.revocado ? "revocado" : n.ultimoLatidoUtc ? "latido hace " + hace(n.ultimoLatidoUtc) : "sin latido"}`]) });
  const deps = inst.ultimoDeploy || {};
  const ultDep = Object.values(deps).filter(Boolean).sort().pop();
  add("github", { tit: "GitHub Actions", st: "deploy.yml → SSH", tag: "EXTERNO", ico: "rama", est: ultDep ? "ok" : "gris",
    met: [met("reloj", ultDep ? "hace " + hace(ultDep) : "sin deploy")],
    det: Object.entries(deps).map(([k, v]) => [`Último deploy ${k}`, `${fecha(v)} (hace ${hace(v)})`]) });
  add("telegram", { tit: "Telegram", st: "api.telegram.org", tag: "EXTERNO", ico: "avion", est: "gris",
    det: [["Uso", "Bots de alertas de igas-console y avisos de zia-chatbot"], ["Estado", "Sin medición directa desde el VPS (enlace inferido)"]] });

  // --- Cloudflare y dominios
  const dominios = [
    ["d-landing", "ziacentro.mx", "landing", "Landing estática"],
    ["d-console", "console.ziacentro.mx", "consola", "Consola Angular"],
    ["d-api", "api.ziacentro.mx", "igas-console", "igas-console :5010"],
    ["d-app", "app.ziacentro.com", "zia-chatbot", "zia-chatbot :5020"],
    ["d-legacy", "console.igasmorelia.com", "igas-console", "legado → igas-console"],
    ["d-legacy-api", "api.console.igasmorelia.com", "igas-console", "legado → API"],
  ];
  const abpSitio = sitios.find((s) => s.archivo === "abp-template");
  const abpDom = abpSitio ? abpSitio.dominios.find((x) => x.startsWith("api.")) || abpSitio.dominios[0] : null;
  if (abpDom) dominios.push(["d-abp", abpDom, "abp-template", "abp-template"]);
  const hijosCf = [];
  for (const [id, dom, destino, etiqueta] of dominios) {
    const c = certDe(dom);
    const estCert = c ? umbral(-c.diasRestantes, -30, -7) : "gris";
    const enNginx = sitios.some((s) => s.dominios.includes(dom));
    const back = destino === "landing" || destino === "consola" ? estSrv("nginx") : estSrv(destino);
    add(id, { tit: dom, st: etiqueta, tag: "DOMINIO", ico: "web", sub: true, est: enNginx || !sitios.length ? peor(estCert, back) : "mal", legado: id.startsWith("d-legacy"),
      met: [met("candado", c ? `${Math.floor(c.diasRestantes)} d` : "sin cert", c ? estCert : "")],
      det: [["Certificado", c ? `${c.nombre} · vence ${fecha(c.venceUtc)}` : "no encontrado"], ["Días restantes", c ? Math.floor(c.diasRestantes) : "—"], ["Sitio nginx", (sitios.find((s) => s.dominios.includes(dom)) || {}).archivo || "—"], ["Destino", etiqueta], ["Proxy Cloudflare", "sí (inferido)"]] });
    hijosCf.push(id);
  }
  add("cloudflare", { tit: "Cloudflare", st: "proxy · DNS · TLS de borde", tag: "EXTERNO", ico: "nube", est: "ok", hijos: hijosCf, ancho: true,
    met: [met("candado", `${certs.length} certs origen`), met("con", `${dominios.length} dominios`)],
    det: [["Estado", "OK (inferido: esta respuesta llegó por Cloudflare)"], ["Origen", "Solo IPs de Cloudflare hacia nginx"], ["Certificados de origen", certs.map((c) => `${c.nombre}: ${Math.floor(c.diasRestantes)} d`).join(" · ") || "—"]] });

  // --- VPS
  const svcIds = [];
  add("nginx", { tit: "nginx", st: ":80 · :443", tag: "SERVICIO", ico: "web", sub: true, est: peor(estSrv("nginx"), (inst.nginx || {}).configValida === false ? "warn" : "ok"), alto: true,
    met: [met("mem", bytes((srv.nginx || {}).memoriaBytes)), met("con", `${sitios.length} sitios`)],
    det: [...svcDetalle("nginx"), ["nginx -t", (inst.nginx || {}).configValida ? "válida" : (inst.nginx ? "con errores" : "sin dato")], ["Sitios", sitios.map((s) => s.archivo).join(", ") || "—"]] });
  for (const [id, n, port, desc] of [["igas-console", "igas-console", ":5010", "API ABP + OpenIddict"], ["zia-chatbot", "zia-chatbot", ":5020", "asistente de la landing"], ["abp-template", "abp-template", (abpSitio?.proxyA[0] || "").replace(/^https?:\/\/[^:]+/, "") || "local", "plantilla ABP"]]) {
    add(id, { tit: n, st: `127.0.0.1${port} · ${desc}`, tag: "SERVICIO", ico: "servidor", sub: true, est: estSrv(n), met: svcMet(n), det: svcDetalle(n) });
    svcIds.push(id);
  }
  add("landing", { tit: "Landing / consola web", st: "estático servido por nginx", tag: "SITIO", ico: "web", sub: true, est: estSrv("nginx"), det: [["Contenido", "ziacentro.mx y la SPA de console.ziacentro.mx"], ["Servidor", "nginx (archivos estáticos)"]] });
  svcIds.push("landing");
  add("fail2ban", { tit: "fail2ban", st: Object.keys(f2b).join(" · ") || "jails", tag: "SEGURIDAD", ico: "escudo", sub: true, est: inst.fail2ban ? estSrv("fail2ban") : peor(estSrv("fail2ban"), "gris"),
    met: [met("con", `${bansAhora} ban · ${bans24}/24h`, bansAhora > 20 ? "warn" : "")],
    det: [...svcDetalle("fail2ban"), ...Object.entries(f2b).map(([j, v]) => [`Jail ${j}`, `${v.baneadosAhora} ahora · ${v.baneos1h} en 1 h · ${v.baneos24h} en 24 h · ${v.baneadosTotal} total`])] });
  add("ssh", { tit: "ssh", st: ":22 · " + (inst.ssh ? (inst.ssh.soloLlave ? "solo llave" : "¡acepta contraseña!") : "—"), tag: "SEGURIDAD", ico: "candado", sub: true,
    est: peor(estSrv("ssh"), inst.ssh && !inst.ssh.soloLlave ? "warn" : "ok"), met: [met("con", `${(f2b.sshd || {}).baneos24h ?? "—"} bans/24h`)], det: svcDetalle("ssh") });
  const estHost = peor(umbral(d.cpuPorcentaje, 80, 95), umbral(memPct, 85, 95), umbral(discoPct, 80, 92));
  add("vps", { tit: "VPS " + (d.host || ""), st: `157.x · ${d.nucleos} vCPU · uptime ${dur(d.uptimeSegundos)}`, tag: "SERVIDOR", ico: "servidor",
    est: peor(estHost, ...["nginx", "igas-console", "abp-template", "zia-chatbot", "fail2ban", "ssh"].map((x) => N[x].est === "mal" ? "warn" : N[x].est)),
    met: [met("cpu", `${(d.cpuPorcentaje ?? 0).toFixed(0)}%`, umbral(d.cpuPorcentaje, 80, 95)), met("mem", `${memPct?.toFixed(0) ?? "—"}%`, umbral(memPct, 85, 95)), met("disk", `${discoPct?.toFixed(0) ?? "—"}%`, umbral(discoPct, 80, 92)), met("con", `${bansAhora} bans`)],
    det: [["Host", d.host], ["Uptime", dur(d.uptimeSegundos)], ["CPU", `${(d.cpuPorcentaje ?? 0).toFixed(1)} % · carga ${(d.cargaPromedio || []).map((x) => x.toFixed(2)).join(" / ")}`], ["Memoria", `${bytes(d.memoriaTotalBytes - d.memoriaDisponibleBytes)} de ${bytes(d.memoriaTotalBytes)} (${memPct?.toFixed(0)} %)`], ["Swap", d.swapTotalBytes ? `${bytes(d.swapTotalBytes - d.swapLibreBytes)} de ${bytes(d.swapTotalBytes)}` : "sin swap"], ...(d.discos || []).map((x) => [`Disco ${x.montaje}`, `${bytes(x.totalBytes - x.libreBytes)} de ${bytes(x.totalBytes)}`])] });

  // --- datos y monitoreo
  const pg = inst.postgres || {};
  const dbIds = [];
  for (const [db, b] of Object.entries(pg).sort((a, b) => b[1] - a[1])) {
    if (db === "postgres") continue;
    const id = "db-" + db;
    add(id, { tit: db, st: bytes(b), tag: "BD", ico: "bd", sub: true, est: estSrv("postgresql"), det: [["Tamaño", bytes(b)], ["Servidor", "PostgreSQL " + (inst.postgresVersion || "")]] });
    dbIds.push(id);
  }
  add("postgres", { tit: "PostgreSQL", st: `127.0.0.1:5432 · v${(inst.postgresVersion || "?").split(" ")[0]}`, tag: "BASE DE DATOS", ico: "bd", est: estSrv("postgresql"), hijos: dbIds,
    met: [met("disk", bytes(Object.values(pg).reduce((a, b) => a + b, 0) || d.baseDeDatosBytes)), met("mem", bytes((srv.postgresql || {}).memoriaBytes)), met("con", `${Object.keys(pg).length} bases`)],
    det: [...svcDetalle("postgresql"), ...Object.entries(pg).map(([k, v]) => [`Base ${k}`, bytes(v)])] });
  add("colector", { tit: "Colector", st: "igas-monitoreo-vps.timer · 60 s", tag: "MONITOREO", ico: "reloj", est: estColector,
    met: [met("reloj", edad != null ? `hace ${Math.round(edad)} s` : "sin datos", estColector)],
    det: [["Qué hace", "Lee fail2ban, certificados, nginx, Postgres y latidos como root (solo lectura) y deja un JSON para la API"], ["Última muestra", edad != null ? `hace ${Math.round(edad)} s` : "nunca"]] });
  add("respaldo", { tit: "Respaldo remoto", st: "backup-remoto.sh (planeado)", tag: "PLANEADO", ico: "disk", est: "gris", plan: true,
    det: [["Estado", "Planeado: copia externa de la base"], ["Medición", "Aún no reporta al panel"]] });

  // --- enlaces: [origen, destino, tipo]
  const E = [];
  const l = (a, b, tipo = "medido", via) => E.push({ a, b, tipo, via });
  ["d-landing", "d-console", "d-api", "d-app"].forEach((x) => l("usuarios", x, "inferido"));
  l("usuarios", "d-legacy", "inferido");
  l("gasolineras", "d-api", "inferido");
  for (const [id, , destino] of dominios) l(id, "nginx", "medido");
  l("nginx", "igas-console"); l("nginx", "zia-chatbot"); l("nginx", "abp-template"); l("nginx", "landing");
  l("igas-console", "db-igas_console");
  for (const id of dbIds.filter((x) => x.startsWith("db-abp"))) l("abp-template", id);
  l("colector", "igas-console", "medido", { dirA: -1, dirB: -1 });
  l("telegram", "igas-console", "inferido", { bajo: 2 });
  l("telegram", "zia-chatbot", "inferido", { bajo: 1 });
  l("github", "ssh", "inferido", { bajo: 0 });
  l("ssh", "fail2ban", "medido");
  l("postgres", "respaldo", "planeado", { lado: "abajo" });
  for (const e of E) {
    const ea = N[e.a]?.est ?? "gris", eb = N[e.b]?.est ?? "gris";
    e.est = e.tipo === "planeado" ? "gris" : (ea === "mal" || eb === "mal") ? "mal" : peorConocido(ea, eb);
  }
  return { N, E: E.filter((e) => N[e.a] && N[e.b]), resumen: { servicios: d.servicios || [], srvOk: (d.servicios || []).filter((s) => s.estado === "active").length, certs, estHost } };
}

/* =================== render del diagrama =================== */
function tarjeta(n, N) {
  const cls = ["nodo", n.sub ? "sub" : "", n.plan ? "plan" : "", n.est].join(" ");
  const hijos = (n.hijos || []).map((h) => tarjeta(N[h], N)).join("");
  return `<div class="${cls}" data-id="${n.id}">
    <div class="n-cab"><span class="n-ico">${ICO[n.ico] || ""}</span><div class="n-cuerpo"><div class="n-tit">${esc(n.tit)}</div><div class="n-st">${esc(n.st)}</div></div>
    <div class="n-tag">${esc(n.tag)} <i class="dot ${n.est}" title="${TXT[n.est]}"></i></div></div>
    ${n.met ? `<div class="metricas">${n.met.join("")}</div>` : ""}
    ${hijos ? `<div class="hijos">${n.id === "cloudflare" ? hijosCloudflare(n, N) : hijos}</div>` : ""}
  </div>`;
}
function hijosCloudflare(n, N) {
  const act = n.hijos.filter((h) => !N[h].legado), leg = n.hijos.filter((h) => N[h].legado);
  return act.map((h) => tarjeta(N[h], N)).join("") + (leg.length ? `<div class="seccion">LEGADO · IGASMORELIA</div>` + leg.map((h) => tarjeta(N[h], N)).join("") : "");
}
function pintarDiagrama(M) {
  const { N } = M;
  const col = (x, y, w, h, html, extra = "") => `<div class="col" style="left:${x}px;top:${y}px;width:${w}px;${h ? `height:${h}px;` : ""}${extra}">${html}</div>`;
  const t = (id) => tarjeta(N[id], N);
  const vps = N.vps;
  const vpsHtml = `<div class="nodo ${vps.est}" data-id="vps">
    <div class="n-cab"><span class="n-ico">${ICO.servidor}</span><div class="n-cuerpo"><div class="n-tit">${esc(vps.tit)}</div><div class="n-st">${esc(vps.st)}</div></div><div class="n-tag">SERVIDOR <i class="dot ${vps.est}"></i></div></div>
    <div class="metricas">${vps.met.join("")}</div>
    <div class="vps-cuerpo"><div class="hijos" style="margin-top:0">${t("nginx").replace('class="nodo', 'style="flex:1;display:flex;flex-direction:column;justify-content:center" class="nodo')}<div class="seccion">SEGURIDAD</div>${t("ssh")}${t("fail2ban")}</div>
      <div class="hijos" style="margin-top:0">${["igas-console", "zia-chatbot", "abp-template", "landing"].map(t).join("")}</div></div>
  </div>`;
  $("nodos-diagrama").innerHTML =
    col(30, 50, 230, 700, ["usuarios", "gasolineras", "github", "telegram"].map(t).join(""), "justify-content:space-around") +
    col(330, 50, 280, 0, t("cloudflare")) +
    col(670, 50, 570, 0, vpsHtml) +
    col(1300, 50, 310, 0, t("postgres") + '<div style="height:26px"></div>' + t("colector") + '<div style="height:44px"></div>' + t("respaldo"));
  document.querySelectorAll("#nodos-diagrama .nodo").forEach((el) => el.addEventListener("click", (ev) => { ev.stopPropagation(); seleccionar(el.dataset.id); }));
  requestAnimationFrame(() => trazarEnlaces(M));
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
  const yAnc = (lista, e, bx) => { const i = lista.indexOf(e), n = lista.length, paso = Math.min(9, (bx.h - 14) / Math.max(1, n)); return bx.y + bx.h / 2 + (i - (n - 1) / 2) * paso; };
  // orden de llegada para que no se crucen: por y del otro extremo
  for (const k in sal) sal[k].sort((p, q) => (caja(p.b)?.y ?? 0) - (caja(q.b)?.y ?? 0));
  for (const k in ent) ent[k].sort((p, q) => (caja(p.a)?.y ?? 0) - (caja(q.a)?.y ?? 0));
  const fondo = Math.max(...[...document.querySelectorAll("#nodos-diagrama > .col > .nodo")].map((el) => { const b = caja(el.dataset.id); return b ? b.y + b.h : 0; }));
  let html = "", carril = {};
  ENLACES = [];
  for (const e of M.E) {
    const A = caja(e.a), B = caja(e.b);
    if (!A || !B) continue;
    let pts;
    if (e.via?.lado === "abajo") {
      const x = A.x + A.w / 2; pts = [[x, A.y + A.h], [x, B.y]];
    } else {
      const dirA = e.via?.dirA ?? 1;
      const sx = dirA > 0 ? A.x + A.w : A.x, sy = yAnc(sal[e.a], e, A);
      const tx = dirA > 0 ? B.x : B.x + B.w, ty = yAnc(ent[e.b], e, B);
      if (e.via?.bajo) {
        const yb = fondo + 18 + e.via.bajo * 10, xb = B.x - (e.b === "ssh" ? 22 : 14 + e.via.bajo * 8);
        pts = [[sx, sy], [sx + 18 + e.via.bajo * 8, sy], [sx + 18 + e.via.bajo * 8, yb], [xb, yb], [xb, ty], [tx, ty]];
      } else {
        const clave = Math.round(sx / 40) + ":" + Math.round(tx / 40);
        const n = (carril[clave] = (carril[clave] ?? -1) + 1);
        const base = sx + (tx - sx) * (e.b === "nginx" ? 0.55 : 0.5);
        const mx = Math.abs(sy - ty) < 1 ? base : base + ((n % 2 ? 1 : -1) * Math.ceil(n / 2) * 6);
        pts = Math.abs(sy - ty) < 1 ? [[sx, sy], [tx, ty]] : [[sx, sy], [mx, sy], [mx, ty], [tx, ty]];
      }
    }
    const d = ruta(pts), activo = e.tipo !== "planeado" && e.est !== "gris";
    html += `<g class="g-enl" data-a="${e.a}" data-b="${e.b}">
      <path class="enl ${e.est} ${e.tipo} ${activo && e.tipo === "medido" ? "base" : ""}" d="${d}"/>
      ${activo ? `<path class="flujo ${e.est}" d="${d}" style="animation-duration:${e.tipo === "medido" ? 1.1 : 2}s"/>` : ""}
      <circle class="extremo ${e.est}" cx="${pts[0][0]}" cy="${pts[0][1]}" r="2.6"/><circle class="extremo ${e.est}" cx="${pts.at(-1)[0]}" cy="${pts.at(-1)[1]}" r="2.6"/></g>`;
    ENLACES.push(e);
  }
  svg.innerHTML = html;
  H = Math.max(560, fondo + 60); $("lienzo").style.height = H + "px";
  if (vista.ajustada) ajustar();
  if (seleccion) resaltar(seleccion);
}

/* =================== selección y panel =================== */
function relacionados(id) {
  const ids = new Set([id]);
  const padreDe = (x) => Object.values(NODOS).find((n) => (n.hijos || []).includes(x))?.id;
  const conHijos = (x) => [x, ...(NODOS[x]?.hijos || [])];
  const propios = new Set(conHijos(id));
  if (id === "vps") ["nginx", "igas-console", "zia-chatbot", "abp-template", "landing", "fail2ban", "ssh"].forEach((x) => propios.add(x));
  for (const e of ENLACES) if (propios.has(e.a) || propios.has(e.b)) { ids.add(e.a); ids.add(e.b); }
  propios.forEach((x) => ids.add(x));
  [...ids].forEach((x) => { const p = padreDe(x); if (p) ids.add(p); });
  return { ids, propios };
}
function resaltar(id) {
  const { ids, propios } = relacionados(id);
  $("lienzo").classList.add("dim");
  document.querySelectorAll("#nodos-diagrama .nodo").forEach((el) => { el.classList.toggle("rel", ids.has(el.dataset.id)); el.classList.toggle("sel", el.dataset.id === id); });
  document.querySelectorAll(".g-enl").forEach((g) => g.classList.toggle("rel", propios.has(g.dataset.a) || propios.has(g.dataset.b)));
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
  $("panel").classList.add("abierto");
}
function deseleccionar() {
  seleccion = null; $("panel").classList.remove("abierto"); $("lienzo").classList.remove("dim");
  document.querySelectorAll(".rel,.sel").forEach((e) => e.classList.remove("rel", "sel"));
}
$("panel-cerrar").onclick = deseleccionar;

/* =================== pan / zoom =================== */
const vista = { s: 1, x: 0, y: 0, ajustada: true };
const W = 1640; let H = 860;
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
  addEventListener("resize", () => { if (vista.ajustada) ajustar(); });
})();

/* =================== pestañas de lista =================== */
const fila = (n, extra = "") => tarjeta({ ...n, hijos: null }, NODOS).replace("</div>\n  </div>", `${extra}</div>\n  </div>`);
function pintarListas(d, M) {
  const inst = d.instantanea || {};
  $("v-servicios").innerHTML = `<h2>SERVIDOR</h2>${fila(NODOS.vps)}${fila(NODOS.postgres)}${fila(NODOS.colector)}<h2>SERVICIOS SYSTEMD</h2>` +
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

/* =================== pills y pantallas =================== */
function pintarPills(M) {
  const enl = M.E.filter((e) => e.tipo !== "planeado"), enlOk = enl.filter((e) => e.est === "ok").length;
  const svcs = M.resumen.servicios, srvOk = M.resumen.srvOk;
  const certs = M.resumen.certs, certOk = certs.filter((c) => c.diasRestantes >= 30).length;
  const nucleo = ["vps", "nginx", "igas-console", "zia-chatbot", "abp-template", "postgres", "colector", "cloudflare"];
  const crit = Object.values(M.N).filter((n) => !n.plan && (!n.sub || nucleo.includes(n.id))).map((n) => (nucleo.includes(n.id) || n.est !== "mal" ? n.est : "warn"));
  const global = crit.includes("mal") ? "mal" : crit.includes("warn") || srvOk < svcs.length ? "warn" : "ok";
  const p = (v, t, e) => `<div class="pill ${e}"><b>${v}</b><small>${t}</small></div>`;
  $("pills").innerHTML = p({ ok: "OPERANDO", warn: "DEGRADADO", mal: "FALLA" }[global], "salud global", global) +
    p(`${srvOk}/${svcs.length}`, "servicios ok", srvOk === svcs.length ? "ok" : "mal") +
    p(`${enlOk}/${enl.length}`, "enlaces ok", enlOk === enl.length ? "ok" : enl.some((e) => e.est === "mal") ? "mal" : "warn") +
    p(`${certOk}/${certs.length}`, "certs ≥30 días", certOk === certs.length ? "ok" : certs.some((c) => c.diasRestantes < 7) ? "mal" : "warn");
}
function mostrar(v) {
  document.body.classList.toggle("sin-datos", !datos);
  for (const s of ["v-login", "v-error", "v-arquitectura", "v-servicios", "v-seguridad", "v-nodos"]) $(s).classList.toggle("oculto", s !== v);
  const enPanel = v.startsWith("v-") && !["v-login", "v-error"].includes(v);
  $("tabs").style.visibility = $("pills").style.visibility = enPanel || datos ? "visible" : "hidden";
  $("leyenda").classList.toggle("oculto", v !== "v-arquitectura");
  if (v === "v-arquitectura") requestAnimationFrame(() => { if (vista.ajustada) ajustar(); });
}
function error(tag, titulo, texto) { $("err-tag").textContent = tag; $("err-titulo").textContent = titulo; $("err-texto").textContent = texto; mostrar("v-error"); }
function sesionUI() {
  $("sesion").innerHTML = token() ? `<span class="tenue">${esc(usuario())}</span> <button id="btn-cerrar">SALIR</button>` : "";
  if (token()) $("btn-cerrar").onclick = cerrarSesion;
}
document.querySelectorAll("#tabs button").forEach((b) => b.onclick = () => {
  tab = b.dataset.tab; document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("activo", x === b));
  if (datos) mostrar("v-" + tab);
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
  datos = await r.json(); ultimoOk = Date.now();
  const M = modelo(datos); NODOS = M.N;
  pintarDiagrama(M); pintarListas(datos, M); pintarPills(M);
  const g = new Date(datos.generadoUtc);
  $("actualizado").textContent = innerWidth < 820 ? g.toLocaleTimeString("es-MX", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : g.toLocaleString("es-MX", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  $("live").classList.remove("off");
  $("nota").textContent = `colector hace ${datos.edadInstantaneaSegundos != null ? Math.round(datos.edadInstantaneaSegundos) + " s" : "—"} · refresco cada ${C.refreshSeconds} s · host ${datos.host}`;
  if ($("v-login").classList.contains("oculto") && $("v-error").classList.contains("oculto") && !document.querySelector(".vista:not(.oculto)")) mostrar("v-" + tab);
  else if (!$("v-login").classList.contains("oculto") || !$("v-error").classList.contains("oculto")) mostrar("v-" + tab);
  if (seleccion && NODOS[seleccion]) seleccionar(seleccion);
}
function marcarViejo() { $("live").classList.add("off"); }

$("btn-login").onclick = iniciarSesion;
$("btn-reintentar").onclick = () => (token() ? cargar() : iniciarSesion());
$("btn-salir").onclick = cerrarSesion;
mostrar("v-login"); $("v-login").classList.add("oculto");
try { await procesarRetorno(); } catch (e) { error("OIDC", "No se pudo iniciar sesión", e.message); }
if ($("v-error").classList.contains("oculto")) await cargar();
setInterval(cargar, C.refreshSeconds * 1000);
setInterval(() => { if (ultimoOk && Date.now() - ultimoOk > (C.refreshSeconds + 30) * 1000) marcarViejo(); }, 5000);
