import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
mermaid.initialize({ startOnLoad: false, theme: "dark", securityLevel: "strict" });

const C = window.VPS_CONFIG;
const REDIRECT = location.origin + location.pathname.replace(/index\.html$/, "");
const $ = (id) => document.getElementById(id);
const ss = sessionStorage;
let temporizador = null, ultimoDiagrama = "";

// ---------- OIDC: código de autorización + PKCE ----------
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
    body: new URLSearchParams({ grant_type: "authorization_code", code: p.get("code"), redirect_uri: REDIRECT,
      client_id: C.clientId, code_verifier: ss.getItem("pkce_verifier") }) });
  ss.removeItem("pkce_verifier"); ss.removeItem("pkce_state");
  if (!r.ok) throw new Error("No se pudo canjear el código por un token.");
  const t = await r.json();
  ss.setItem("access_token", t.access_token);
  ss.setItem("expira", String(Date.now() + (t.expires_in || 3600) * 1000));
  if (t.id_token) ss.setItem("id_token", t.id_token);
}

const token = () => (Number(ss.getItem("expira") || 0) > Date.now() + 30000 ? ss.getItem("access_token") : null);
function usuario() {
  try { const p = JSON.parse(atob(ss.getItem("access_token").split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))); return p.preferred_username || p.unique_name || p.email || p.sub; }
  catch { return ""; }
}
function cerrarSesion() {
  const idt = ss.getItem("id_token"); ss.clear();
  const q = new URLSearchParams({ post_logout_redirect_uri: REDIRECT, client_id: C.clientId }); if (idt) q.set("id_token_hint", idt);
  location.assign(`${C.authority}/connect/endsession?${q}`);
}

// ---------- Pantallas ----------
function mostrar(id) { for (const s of ["pantalla-login", "pantalla-error", "panel"]) $(s).classList.toggle("oculto", s !== id); }
function error(titulo, texto) { $("error-titulo").textContent = titulo; $("error-texto").textContent = texto; mostrar("pantalla-error"); }
function sesionUI() {
  const el = $("estado-sesion"); el.textContent = "";
  if (!token()) return;
  const s = document.createElement("span"); s.className = "tenue"; s.textContent = usuario() + "  ";
  const b = document.createElement("button"); b.textContent = "Cerrar sesión"; b.onclick = cerrarSesion;
  el.append(s, b);
}

// ---------- Formato ----------
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const bytes = (b) => { if (b == null) return "—"; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (b >= 1024 && i < 4) { b /= 1024; i++; } return `${b.toFixed(i ? 1 : 0)} ${u[i]}`; };
const dur = (s) => { s = Math.floor(s || 0); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`; };
const fecha = (iso) => iso ? new Date(iso).toLocaleString("es-MX", { dateStyle: "medium", timeStyle: "short" }) : "—";
const hace = (iso) => iso ? dur((Date.now() - new Date(iso)) / 1000) : "—";
const pill = (txt, cls) => `<span class="p ${cls}">${esc(txt)}</span>`;
const nivel = (pct, a = 75, b = 90) => pct >= b ? "mal" : pct >= a ? "warn" : "ok";
const color = { ok: "var(--ok)", warn: "var(--warn)", mal: "var(--mal)" };
const tabla = (id, cab, filas) => { $(id).innerHTML = `<tr>${cab.map((c) => `<th>${c}</th>`).join("")}</tr>` + (filas.length ? filas.join("") : `<tr><td colspan="${cab.length}" class="tenue">Sin datos</td></tr>`); };

// ---------- Datos ----------
async function cargar() {
  if (!token()) { mostrar("pantalla-login"); sesionUI(); return; }
  let r;
  try { r = await fetch(C.api, { headers: { Authorization: `Bearer ${token()}`, Accept: "application/json", "Accept-Language": "es" } }); }
  catch { return error("Sin conexión con la API", "No se pudo contactar a api.ziacentro.mx. Se reintentará en el próximo ciclo."); }
  if (r.status === 401) { ss.removeItem("access_token"); mostrar("pantalla-login"); sesionUI(); return; }
  if (r.status === 403) return error("Sin permiso",
    `Tu usuario (${usuario()}) no tiene el permiso «Ver el panel del VPS» (IgasConsole.Monitoreo.VerVps). Pide que te lo asignen en ZIA-Console › Administración › Roles, o entra con la cuenta admin.`);
  if (!r.ok) return error(`Error ${r.status}`, "La API respondió con un error. Se reintentará en el próximo ciclo.");
  pintar(await r.json());
}

function pintar(d) {
  mostrar("panel"); sesionUI();
  const inst = d.instantanea || {};
  $("actualizado").textContent = `Actualizado: ${fecha(d.generadoUtc)}` + (d.edadInstantaneaSegundos != null ? ` · recolector hace ${Math.round(d.edadInstantaneaSegundos)} s` : " · recolector sin datos");
  $("cuenta").textContent = `Siguiente en ${C.refreshSeconds} s`;

  const memUso = d.memoriaTotalBytes ? 100 * (1 - d.memoriaDisponibleBytes / d.memoriaTotalBytes) : 0;
  const raiz = (d.discos || []).find((x) => x.montaje === "/") || (d.discos || [])[0];
  const discoUso = raiz ? 100 * (1 - raiz.libreBytes / raiz.totalBytes) : 0;
  const activos = (d.servicios || []).filter((s) => s.estado === "active").length;
  const f2b = Object.values(inst.fail2ban || {});
  const certMin = Math.min(...(inst.certificados || []).map((c) => c.diasRestantes ?? 999));
  const tarj = [
    ["Servicios", `${activos}/${(d.servicios || []).length}`, "activos", activos === (d.servicios || []).length ? "ok" : "mal"],
    ["CPU", `${d.cpuPorcentaje.toFixed(1)} %`, `carga ${(d.cargaPromedio || []).map((x) => x.toFixed(2)).join(" · ")} · ${d.nucleos} núcleos`, nivel(d.cpuPorcentaje)],
    ["RAM", `${memUso.toFixed(0)} %`, `${bytes(d.memoriaTotalBytes - d.memoriaDisponibleBytes)} de ${bytes(d.memoriaTotalBytes)}`, nivel(memUso)],
    ["Disco /", `${discoUso.toFixed(0)} %`, raiz ? `${bytes(raiz.libreBytes)} libres` : "", nivel(discoUso, 80, 92)],
    ["Uptime", dur(d.uptimeSegundos), d.host, "ok"],
    ["Postgres", bytes(d.baseDeDatosBytes), "igas_console", "ok"],
    ["Baneos 24 h", f2b.reduce((a, j) => a + j.baneos24h, 0), `${f2b.reduce((a, j) => a + j.baneadosAhora, 0)} IPs baneadas ahora`, "ok"],
    ["Cert. más próximo", isFinite(certMin) ? `${Math.floor(certMin)} d` : "—", "para vencer", certMin < 15 ? "mal" : certMin < 30 ? "warn" : "ok"],
  ];
  $("tarjetas").innerHTML = tarj.map(([t, v, s, n]) => `<div class="tarjeta" style="border-top:3px solid ${color[n]}"><div class="t">${esc(t)}</div><div class="v">${esc(v)}</div><div class="s">${esc(s)}</div></div>`).join("");

  tabla("t-servicios", ["Servicio", "Estado", "Puerto", "Activo desde", "Memoria", "Reinicios"], (d.servicios || []).map((s) =>
    `<tr><td><b>${esc(s.nombre)}</b><br><span class="tenue">${esc(s.descripcion)}</span></td><td>${pill(s.estado + (s.subEstado ? " · " + s.subEstado : ""), s.estado === "active" ? "ok" : s.estado === "activating" ? "warn" : "mal")}</td><td>${esc(s.puerto || "—")}</td><td>${s.activoDesdeUtc ? "hace " + hace(s.activoDesdeUtc) : "—"}</td><td>${bytes(s.memoriaBytes)}</td><td>${s.reinicios ?? "—"}</td></tr>`));

  $("discos").innerHTML = (d.discos || []).map((x) => { const u = 100 * (1 - x.libreBytes / x.totalBytes); return `<div>${esc(x.montaje)} <span class="tenue">— ${bytes(x.totalBytes - x.libreBytes)} de ${bytes(x.totalBytes)} (${u.toFixed(0)} %)</span></div><div class="barra-uso"><i style="width:${u}%;background:${color[nivel(u, 80, 92)]}"></i></div>`; }).join("")
    + `<div class="tenue">RAM ${memUso.toFixed(0)} % · Swap ${d.swapTotalBytes ? bytes(d.swapTotalBytes - d.swapLibreBytes) + " de " + bytes(d.swapTotalBytes) : "sin swap"}</div>`;
  tabla("t-pg", ["Base", "Tamaño"], Object.entries(inst.postgres || {}).sort((a, b) => b[1] - a[1]).map(([n, b]) => `<tr><td>${esc(n)}</td><td>${bytes(b)}</td></tr>`));
  if (inst.postgresVersion) $("t-pg").insertAdjacentHTML("beforeend", `<tr><td class="tenue" colspan="2">PostgreSQL ${esc(inst.postgresVersion)}</td></tr>`);

  tabla("t-f2b", ["Jail", "Baneadas ahora", "Baneos 1 h", "Baneos 24 h", "Total baneos", "Fallos totales"], Object.entries(inst.fail2ban || {}).map(([n, j]) =>
    `<tr><td><b>${esc(n)}</b></td><td>${pill(j.baneadosAhora, j.baneadosAhora ? "warn" : "ok")}</td><td>${j.baneos1h}</td><td>${j.baneos24h}</td><td>${j.baneadosTotal}</td><td>${j.fallosTotal}</td></tr>`));
  if (inst.ssh) $("t-f2b").insertAdjacentHTML("beforeend", `<tr><td colspan="6" class="tenue">SSH: ${inst.ssh.soloLlave ? "solo con llave ✔" : "¡acepta contraseña!"}</td></tr>`);

  tabla("t-certs", ["Certificado", "Dominios", "Vence", "Días"], (inst.certificados || []).sort((a, b) => a.diasRestantes - b.diasRestantes).map((c) =>
    `<tr><td>${esc(c.nombre)}</td><td class="tenue">${esc((c.dominios || []).join(", "))}</td><td>${fecha(c.venceUtc)}</td><td>${pill(Math.floor(c.diasRestantes), c.diasRestantes < 15 ? "mal" : c.diasRestantes < 30 ? "warn" : "ok")}</td></tr>`));

  tabla("t-nginx", ["Sitio", "Dominios", "Escucha", "Proxy"], ((inst.nginx || {}).sitios || []).map((s) =>
    `<tr><td>${esc(s.archivo)}</td><td>${esc(s.dominios.join(" "))}</td><td class="tenue">${esc(s.escucha.join(" "))}</td><td class="tenue">${esc(s.proxyA.join(" ") || "estático")}</td></tr>`));
  if (inst.nginx) $("t-nginx").insertAdjacentHTML("beforeend", `<tr><td colspan="4" class="tenue">nginx -t: ${inst.nginx.configValida ? "configuración válida ✔" : "¡configuración con errores!"}</td></tr>`);

  tabla("t-deploy", ["Servicio", "Último deploy"], Object.entries(inst.ultimoDeploy || {}).map(([n, t]) => `<tr><td>${esc(n)}</td><td>${fecha(t)} <span class="tenue">(hace ${hace(t)})</span></td></tr>`));
  tabla("t-nodos", ["Nodo", "Versión", "Último latido", "Estado"], (inst.nodos || []).map((n) => {
    const edad = n.ultimoLatidoUtc ? (Date.now() - new Date(n.ultimoLatidoUtc)) / 1000 : Infinity;
    return `<tr><td>${esc(n.equipo || "—")}<br><span class="tenue">${esc(n.permiso)}</span></td><td>${esc(n.version || "—")}</td><td>${n.ultimoLatidoUtc ? "hace " + hace(n.ultimoLatidoUtc) : "nunca"}</td><td>${n.revocado ? pill("revocado", "mal") : edad < 600 ? pill("en línea", "ok") : pill("sin latido", "warn")}</td></tr>`;
  }));

  diagrama(d);
}

async function diagrama(d) {
  const a = d.arquitectura || {}, inst = d.instantanea || {};
  const est = Object.fromEntries((d.servicios || []).map((s) => [s.nombre, s.estado === "active"]));
  const id = (s) => "n" + s.replace(/[^a-z0-9]/gi, "");
  const q = (s) => `"${String(s).replace(/"/g, "'")}"`;
  let g = "flowchart LR\n";
  g += `  dns[${q("Dominios<br/>" + (a.dominios || []).join("<br/>"))}]\n  cf[${q(a.borde || "Cloudflare")}]\n  ng[${q("nginx :80/:443")}]\n  db[(${q("PostgreSQL :5432<br/>" + bytes(d.baseDeDatosBytes) + " igas_console")})]\n`;
  g += "  dns --> cf --> ng\n";
  for (const s of a.servicios || []) {
    const n = id(s.nombre);
    g += `  ${n}[${q(s.nombre + "<br/>" + s.destino)}]\n  ng -->|${q((s.dominios || []).join(", ") || "interno")}| ${n}\n`;
    if (!/estática|Angular/i.test(s.nombre)) g += `  ${n} --> db\n`;
    const unidad = (s.nombre.match(/^[a-z-]+/) || [""])[0];
    if (unidad in est) g += `  class ${n} ${est[unidad] ? "ok" : "mal"}\n`;
  }
  g += `  class db ${est.postgresql ? "ok" : "mal"}\n  class ng ${est.nginx ? "ok" : "mal"}\n`;
  g += "  f2b[" + q("fail2ban<br/>" + Object.keys(inst.fail2ban || {}).join(", ")) + "] -.vigila.-> ng\n";
  g += "  classDef ok stroke:#3fb950,stroke-width:2px\n  classDef mal stroke:#f85149,stroke-width:3px\n";
  $("arq-desc").textContent = a.descripcion || "";
  if (g === ultimoDiagrama) return;
  ultimoDiagrama = g;
  try { const { svg } = await mermaid.render("arq" + Date.now(), g); $("diagrama").innerHTML = svg; }
  catch (e) { $("diagrama").textContent = "No se pudo dibujar el diagrama."; }
}

// ---------- Arranque ----------
$("btn-login").onclick = iniciarSesion;
$("btn-reintentar").onclick = () => (token() ? cargar() : iniciarSesion());
$("btn-refrescar").onclick = cargar;
try { await procesarRetorno(); } catch (e) { error("No se pudo iniciar sesión", e.message); }
if ($("pantalla-error").classList.contains("oculto")) await cargar();
let seg = C.refreshSeconds;
temporizador = setInterval(() => { seg--; if (seg <= 0) { seg = C.refreshSeconds; cargar(); } else if (!$("panel").classList.contains("oculto")) $("cuenta").textContent = `Siguiente en ${seg} s`; }, 1000);
