"use strict";
// FOSC/TS viewer (cópia do painel do FOSC com a paleta BB). Everything that comes from a hunt (URLs, summaries, logs) is
// target-controlled data: it always goes through esc() before touching the DOM.

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEVS = ["critical", "high", "medium", "low", "info"];
const SEV_PT = { critical: "crítica", high: "alta", medium: "média", low: "baixa", info: "info" };
const STATUS_PT = { running: "Em execução", recon: "Reconhecimento", paused: "Pausada", sleeping: "Aguardando", finished: "Concluída", stopped: "Parada", crashed: "Falhou", idle: "Ociosa" };
const VERDICT_PT = { confirmed: "Confirmado", refuted: "Refutado", unverified: "Não verificado", duplicate: "Duplicado", rejected: "Rejeitado", inconclusive: "Inconclusivo", timeout: "Tempo esgotado", error: "Erro" };
const LIVE = ["running", "recon", "paused", "sleeping"];

const S = {
  view: "hunts", target: null, snap: null, overview: null, es: null,
  filter: "all", search: "", filtered: [], seen: null, kFilter: "all", knowledge: null,
  chatCtx: null, chatModel: "sonnet", chatData: null, chatTimer: null,
};

// ---------------------------------------------------------------- utils
async function redirectIfSignedOut() {
  if (window.FOSC_MOCK) return false;
  try {
    const r = await fetch("/api/session", { cache: "no-store" });
    if (r.status === 401) {
      window.location.assign("/auth/login");
      return true;
    }
  } catch { /* Preserve the page during a transient local connection failure. */ }
  return false;
}

async function api(path, body) {
  if (window.FOSC_MOCK) return window.FOSC_MOCK.api(path, body);
  const opts = body === undefined ? {} : {
    method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json", "X-FOSC": "1" },
  };
  const r = await fetch(path, opts);
  if (r.status === 401) {
    window.location.assign("/auth/login");
    return { ok: false, error: "authentication required" };
  }
  let data = {};
  try { data = await r.json(); } catch { /* ignore */ }
  if (!r.ok && data.ok === undefined) data.ok = false;
  return data;
}
const now = () => Date.now() / 1000;
function fmtDur(sec) {
  sec = Math.max(0, Math.floor(sec));
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  if (h) return `${h}h ${String(m).padStart(2, "0")}m`;
  if (m) return `${m}m ${String(s).padStart(2, "0")}s`;
  return `${s}s`;
}
function ago(ts) { return ts ? fmtDur(now() - ts) + " atrás" : "—"; }
function clock(ts) { return new Date(ts * 1000).toLocaleTimeString("pt-BR", { hour12: false }); }
const money = (v) => "US$ " + Number(v || 0).toLocaleString("pt-BR", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const sevBadge = (s) => s ? `<span class="sev sev-${esc(s)}">${esc(SEV_PT[s] || s)}</span>` : "";
const verdict = (v) => `<span class="v v-${esc(v)}">${esc(VERDICT_PT[v] || v)}</span>`;
function shortUrl(u) {
  try { const x = new URL(u); return x.pathname + x.search; } catch { return u || ""; }
}

function toast(title, msg = "", kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `<b>${esc(title)}</b>${esc(msg)}`;
  $("#toasts").appendChild(el);
  setTimeout(() => { el.style.transition = "opacity .4s"; el.style.opacity = "0"; }, 5200);
  setTimeout(() => el.remove(), 5700);
}

function chime() {
  if (localStorage.getItem("fosc.sound") !== "1") return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [880, 1320].forEach((f, i) => {
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.frequency.value = f; o.type = "sine";
      g.gain.setValueAtTime(0.0001, ctx.currentTime + i * 0.12);
      g.gain.exponentialRampToValueAtTime(0.18, ctx.currentTime + i * 0.12 + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + i * 0.12 + 0.35);
      o.connect(g).connect(ctx.destination); o.start(ctx.currentTime + i * 0.12); o.stop(ctx.currentTime + i * 0.12 + 0.4);
    });
  } catch { /* audio not available */ }
}

// tiny markdown renderer: escapes first, then a few safe constructs
function md(src) {
  const parts = String(src || "").split(/```[a-z]*\n?/);
  return parts.map((chunk, i) => {
    if (i % 2 === 1) return `<pre><code>${esc(chunk.replace(/\n$/, ""))}</code></pre>`;
    const lines = esc(chunk).split("\n");
    let html = "", list = null;
    const inline = (t) => t.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>").replace(/_([^_]+)_/g, "<i>$1</i>");
    const close = () => { if (list) { html += `</${list}>`; list = null; } };
    for (const l of lines) {
      let m;
      if ((m = l.match(/^(#{1,3})\s+(.*)/))) { close(); html += `<h${m[1].length}>${inline(m[2])}</h${m[1].length}>`; }
      else if ((m = l.match(/^\s*[-*]\s+(.*)/))) { if (list !== "ul") { close(); html += "<ul>"; list = "ul"; } html += `<li>${inline(m[1])}</li>`; }
      else if ((m = l.match(/^\s*\d+\.\s+(.*)/))) { if (list !== "ol") { close(); html += "<ol>"; list = "ol"; } html += `<li>${inline(m[1])}</li>`; }
      else if (!l.trim()) { close(); }
      else { close(); html += `<p>${inline(l)}</p>`; }
    }
    close();
    return html;
  }).join("");
}

// ---------------------------------------------------------------- routing
function route() {
  const h = location.hash || "#/";
  let view = "hunts", target = null;
  if (h.startsWith("#/t/")) target = decodeURIComponent(h.slice(4));
  else if (h === "#/chat") view = "chat";
  else if (h === "#/queue") view = "queue";
  else if (h === "#/knowledge") view = "knowledge";
  else if (h === "#/settings") view = "settings";
  S.view = view;
  $("#viewHunt").hidden = view !== "hunts";
  $("#viewChat").hidden = view !== "chat";
  $("#viewQueue").hidden = view !== "queue";
  $("#viewKnowledge").hidden = view !== "knowledge";
  $("#viewSettings").hidden = view !== "settings";
  $$(".nav-link").forEach((a) => a.classList.toggle("active", a.dataset.view === view));
  if (view !== "chat") stopChatPoll();
  if (view === "hunts" && !target && S.overview?.targets?.length && !S.target) {
    location.hash = "#/t/" + encodeURIComponent(S.overview.targets[0].target);
    return;
  }
  if (view === "hunts" && target !== S.target) {
    S.target = target; S.snap = null; S.seen = null; S.filter = "all";
    $("#feed").innerHTML = "";
    delete $("#feed").dataset.last;
  }
  if (view === "chat") loadChat();
  if (view === "queue") loadQueue();
  if (view === "knowledge") loadKnowledge();
  if (view === "settings") loadSettings();
  renderSidebar();
  renderHunt();
  connect();
}

// ---------------------------------------------------------------- chat
function fillChatCtx() {
  const sel = $("#chatCtx");
  const targets = S.overview?.targets?.map((t) => t.target) || [];
  if (S.chatCtx === null) S.chatCtx = S.target || "";
  // make sure a custom/typed target stays selectable even without a run yet
  if (S.chatCtx && !targets.includes(S.chatCtx)) targets.unshift(S.chatCtx);
  sel.innerHTML = `<option value="">Geral (sem alvo)</option>` +
    targets.map((t) => `<option value="${esc(t)}"${t === S.chatCtx ? " selected" : ""}>${esc(t)}</option>`).join("");
  sel.value = S.chatCtx;
}

function setChatTarget(t) {
  S.chatCtx = (t || "").trim();
  S.chatData = null;
  fillChatCtx();
  $("#chatTargetInput").hidden = true;
  $("#chatTargetInput").value = "";
  refreshChat(true);
}

async function loadChat() {
  fillChatCtx();
  $("#chatModel").value = S.chatModel;
  await refreshChat(true);
  startChatPoll();
}

async function refreshChat(forceScroll) {
  const t = S.chatCtx || "";
  const data = await api("/api/chat" + (t ? "?target=" + encodeURIComponent(t) : ""));
  if (S.view !== "chat") return;
  S.chatData = data;
  renderChat(data, forceScroll);
}

function chatBubble(role, text, cost, streaming) {
  const who = role === "user" ? "Você" : "FOSC/TS";
  const body = role === "user"
    ? `<p>${esc(text).replace(/\n/g, "<br>")}</p>`
    : md(text || (streaming ? "…" : ""));
  const tail = (cost ? ` <span class="chat-cost">${money(cost)}</span>` : "") +
    (streaming ? ` <span class="chat-typing">digitando…</span>` : "");
  return `<div class="chat-msg chat-${esc(role)}"><div class="chat-who">${who}${tail}</div><div class="chat-bubble">${body}</div></div>`;
}

function renderChat(data, forceScroll) {
  const log = $("#chatLog");
  const msgs = data.messages || [];
  const live = data.live || {};
  let html = msgs.map((m) => chatBubble(m.role, m.text, m.cost)).join("");
  if (live.running) html += chatBubble("assistant", live.text || "", 0, true);
  if (!html) {
    html = S.chatCtx
      ? `<div class="chat-empty"><b>Alvo em contexto: ${esc(S.chatCtx)}</b><p>Pergunte sobre os achados ou peça um teste ao vivo. Ex.: "dá pra bypassar o login?"</p></div>`
      : `<div class="chat-empty"><b>Qual alvo você quer investigar?</b><p>Clique em <b>+ alvo</b> para informar um alvo, ou escolha um da lista acima. Sem alvo, posso tirar dúvidas, escrever payloads e explicar técnicas.</p></div>`;
  }
  const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 90;
  log.innerHTML = html;
  const act = live.running && (live.activity || []).length ? live.activity : null;
  const a = $("#chatActivity");
  a.hidden = !act;
  if (act) a.innerHTML = act.map((x) => `<div>· ${esc(x)}</div>`).join("");
  $("#chatSend").disabled = !!live.running;
  $("#chatSend").textContent = live.running ? "…" : "Enviar";
  if (forceScroll || atBottom || live.running) log.scrollTop = log.scrollHeight;
}

async function sendChat(e) {
  if (e) e.preventDefault();
  const ta = $("#chatText");
  const msg = ta.value.trim();
  if (!msg) return;
  if (S.chatData?.live?.running) { toast("Aguarde", "a resposta anterior ainda está rodando", "err"); return; }
  const body = { message: msg, model: S.chatModel };
  if (S.chatCtx) body.target = S.chatCtx;
  ta.value = ""; autoGrow(ta);
  const r = await api("/api/chat", body);
  if (!r.ok) { toast("Erro", r.error || "", "err"); return; }
  await refreshChat(true);
}

function startChatPoll() {
  stopChatPoll();
  S.chatTimer = setInterval(() => {
    if (S.view === "chat") refreshChat(false); else stopChatPoll();
  }, 1000);
}
function stopChatPoll() { if (S.chatTimer) { clearInterval(S.chatTimer); S.chatTimer = null; } }

function autoGrow(ta) {
  ta.style.height = "auto";
  ta.style.height = Math.min(ta.scrollHeight, 160) + "px";
}

// ---------------------------------------------------------------- SSE
function connect() {
  const want = "/api/events" + (S.view === "hunts" && S.target ? "?target=" + encodeURIComponent(S.target) : "");
  if (S.es && S.es._url === want) return;
  if (S.es) S.es.close();
  const es = window.FOSC_MOCK ? window.FOSC_MOCK.events(want) : new EventSource(want);
  es._url = want;
  es.addEventListener("overview", (e) => {
    const first = !S.overview;
    S.overview = JSON.parse(e.data);
    renderSidebar();
    if (first && S.view === "hunts" && !S.target) route();
  });
  es.addEventListener("state", (e) => {
    const snap = JSON.parse(e.data);
    if (snap.target !== S.target) return;
    S.snap = snap;
    renderHunt();
  });
  // EventSource hides the HTTP status. Confirm a session before redirecting so
  // a temporary local network error does not log the operator out.
  es.onerror = () => { redirectIfSignedOut(); };
  S.es = es;
}

// ---------------------------------------------------------------- sidebar
function renderSidebar() {
  const ov = S.overview;
  if (!ov) return;
  $("#version").textContent = "Versão " + ov.version;
  $("#sideTotals").innerHTML = `
    <div class="t"><b>${ov.totals.live}</b><span>em execução</span></div>
    <div class="t"><b class="v-confirmed">${ov.totals.confirmed}</b><span>achados</span></div>
    <div class="t"><b>${money(ov.totals.cost)}</b><span>custo total</span></div>`;
  $("#targetList").innerHTML = ov.targets.length ? ov.targets.map((t) => `
    <a class="target-link ${t.target === S.target && S.view === "hunts" ? "active" : ""}" href="#/t/${encodeURIComponent(t.target)}" title="${esc(t.target)} · ${esc(STATUS_PT[t.status] || t.status)}">
      <span class="dot dot-${esc(t.status)}"></span>
      <span class="name">${esc(t.target)}</span>
      <span class="count ${t.confirmed ? "" : "zero"}">${t.confirmed}</span>
    </a>`).join("") : `<div class="idle">nenhum alvo ainda</div>`;
}

// ---------------------------------------------------------------- hunt view
function renderHunt() {
  const has = S.view === "hunts" && S.target;
  $("#emptyHunt").hidden = !!has;
  $("#huntContent").hidden = !has;
  if (!has || !S.snap) return;
  const s = S.snap, m = s.meta || {};

  $("#tTitle").textContent = s.target;
  const meta = [];
  if (m.round) meta.push(`<span>round ${esc(m.round)}</span>`);
  if (m.workers) meta.push(`<span>${esc(m.workers)} workers</span>`);
  meta.push(`<span>${m.continuous ? "contínua" : "passe único"}</span>`);
  if (m.scope) meta.push(`<span title="${esc(m.scope)}">escopo: ${esc(String(m.scope).slice(0, 70))}</span>`);
  $("#tMeta").innerHTML = meta.join("");

  const st = s.status;
  const pill = $("#tStatus");
  pill.className = "pill " + st;
  pill.innerHTML = `<span class="dot dot-${esc(st)}"></span>${esc(STATUS_PT[st] || st)}`;
  const live = LIVE.includes(st);
  $("#btnPause").hidden = !(live && st !== "paused");
  $("#btnResume").hidden = st !== "paused";
  $("#btnStop").hidden = !live;
  $("#btnRestart").hidden = live;

  // KPIs
  const total = s.surface_total || 0;
  const pct = total ? Math.min(100, (s.done / total) * 100) : 0;
  const sevTotal = SEVS.reduce((a, k) => a + (s.severity[k] || 0), 0);
  const sevbar = sevTotal ? SEVS.filter((k) => s.severity[k]).map((k) => `<i style="width:${(s.severity[k] / sevTotal) * 100}%;background:var(--sev-${k})"></i>`).join("") : "";
  const sevTxt = SEVS.filter((k) => s.severity[k]).map((k) => `${s.severity[k]} ${SEV_PT[k]}`).join(" · ") || "nenhum ainda";
  const activeN = Object.keys(s.active || {}).length;
  const elapsed = m.started_at ? ((LIVE.includes(st) ? now() : (m.finished_at || now())) - m.started_at) : 0;
  $("#kpis").innerHTML = `
    <div class="kpi"><div class="label">Endpoints testados</div><div class="value">${s.done}<small>/ ${total}</small></div><div class="bar"><i style="width:${pct}%"></i></div></div>
    <div class="kpi accent"><div class="label">Achados confirmados</div><div class="value">${s.confirmed_count}</div><div class="sub">${esc(sevTxt)}</div>${sevbar ? `<div class="sevbar">${sevbar}</div>` : ""}</div>
    <div class="kpi"><div class="label">Custo do modelo</div><div class="value">${money(m.cost_usd)}</div><div class="sub">${s.done ? money((m.cost_usd || 0) / s.done) + " / endpoint" : "—"}</div></div>
    <div class="kpi"><div class="label">Duração</div><div class="value" data-uptime="${esc(LIVE.includes(st) ? m.started_at || "" : "")}">${elapsed ? fmtDur(elapsed) : "—"}</div><div class="sub">${m.started_at ? "desde " + clock(m.started_at) : ""}</div></div>`;

  renderFeed(s.activity || []);
  renderInflight(s.active || {});
  renderSpark(s.results || []);
  renderFindings(s.confirmed || []);
  renderResults(s.results || [], s.verdicts || {});

  // toasts for newly confirmed findings
  const ids = new Set((s.confirmed || []).map((f) => f.id));
  if (S.seen) {
    for (const f of s.confirmed || []) {
      if (!S.seen.has(f.id)) {
        toast(`Confirmado: ${f.vuln_class || "achado"} (${SEV_PT[f.severity] || f.severity || "?"})`, shortUrl(f.url), "win");
        chime();
      }
    }
  }
  S.seen = ids;
}

function renderFeed(items) {
  const feed = $("#feed");
  const chron = [...items].reverse();
  const lastTs = Number(feed.dataset.last || 0);
  const fresh = chron.filter((a) => a.ts > lastTs);
  if (!fresh.length && feed.childElementCount) return;
  if (!lastTs) feed.innerHTML = "";
  for (const a of fresh) {
    const msg = a.msg || "";
    const cls = a.kind === "result" ? "result" : a.kind === "system" ? "system" : msg.startsWith("$ ") ? "cmd" : "";
    const who = a.url ? `<span class="who">${esc(shortUrl(a.url).slice(0, 38))}</span>` : "";
    const ln = document.createElement("div");
    ln.className = "ln " + cls;
    ln.innerHTML = `<span class="ts">${clock(a.ts)}</span><span class="msg">${who}${esc(msg)}</span>`;
    feed.appendChild(ln);
  }
  while (feed.childElementCount > 400) feed.firstElementChild.remove();
  if (chron.length) feed.dataset.last = chron[chron.length - 1].ts;
  if ($("#feedAuto").checked) feed.scrollTop = feed.scrollHeight;
}

function renderInflight(active) {
  const list = Object.values(active).sort((a, b) => a.started_at - b.started_at);
  $("#activeCount").textContent = list.length ? `${list.length} tarefa(s)` : "";
  $("#inflight").innerHTML = list.length ? list.map((t) => `
    <div class="task ${esc(t.phase)}">
      <div class="url" title="${esc(t.url)}">${esc(t.url)}</div>
      <div class="meta"><span>${t.phase === "reviewing" ? "revisão Opus" : "caçando"}</span><span data-start="${esc(t.started_at)}">${fmtDur(now() - t.started_at)}</span></div>
      
    </div>`).join("") : `<div class="idle">nenhuma tarefa em andamento</div>`;
}

function renderSpark(results) {
  const bucket = 600, n = 36, end = Math.ceil(now() / bucket) * bucket;
  const counts = new Array(n).fill(0), wins = new Array(n).fill(0);
  for (const r of results) {
    const i = n - 1 - Math.floor((end - r.ts) / bucket);
    if (i >= 0 && i < n) { counts[i]++; if (r.verdict === "confirmed") wins[i]++; }
  }
  const max = Math.max(1, ...counts), W = 600, H = 70, step = W / (n - 1);
  const pts = counts.map((c, i) => [i * step, H - 6 - (c / max) * (H - 14)]);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const dots = wins.map((w, i) => w ? `<circle cx="${pts[i][0].toFixed(1)}" cy="${pts[i][1].toFixed(1)}" r="3.5" fill="#fff" stroke="#1F6FB5" stroke-width="2"/>` : "").join("");
  $("#spark").innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <defs><linearGradient id="sg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2E8BDA" stop-opacity=".12"/><stop offset="1" stop-color="#2E8BDA" stop-opacity="0"/></linearGradient></defs>
    <path d="${line} L ${W} ${H} L 0 ${H} Z" fill="url(#sg)"/>
    <path d="${line}" fill="none" stroke="#2E8BDA" stroke-width="2" vector-effect="non-scaling-stroke"/>${dots}</svg>`;
}

function renderFindings(list) {
  $("#confCount").textContent = list.length ? `${list.length} achado(s)` : "";
  $("#findings").innerHTML = list.length ? list.map((f) => `
    <div class="finding" data-id="${esc(f.id)}" style="--sev: var(--sev-${esc((f.severity || "info").toLowerCase())})">
      <div class="ft"><div class="title">${esc(f.title || f.vuln_class || "Achado")}</div>${sevBadge((f.severity || "").toLowerCase())}</div>
      <div class="url" title="${esc(f.url)}">${esc(f.url)}</div>
      <div class="sum">${esc(f.summary || "")}</div>
    </div>`).join("") : `<div class="no-findings">Nada confirmado ainda. Achados só aparecem aqui depois de sobreviver à revisão do Opus.</div>`;
}

function renderResults(results, verdicts) {
  const order = ["all", "confirmed", "refuted", "unverified", "duplicate", "inconclusive", "rejected", "timeout", "error"];
  const total = Object.values(verdicts).reduce((a, b) => a + b, 0);
  $("#chips").innerHTML = order.filter((v) => v === "all" || verdicts[v]).map((v) =>
    `<button class="chip ${S.filter === v ? "on" : ""}" data-filter="${v}">${v === "all" ? "Todos" : esc(VERDICT_PT[v])}<b>${v === "all" ? total : verdicts[v]}</b></button>`).join("");
  const q = S.search.toLowerCase();
  S.filtered = results.filter((r) => (S.filter === "all" || r.verdict === S.filter) &&
    (!q || (r.url || "").toLowerCase().includes(q) || (r.vuln_class || "").toLowerCase().includes(q)));
  $("#resultsTable tbody").innerHTML = S.filtered.length ? S.filtered.map((r, i) => `
    <tr data-idx="${i}">
      <td>${verdict(r.verdict)}</td>
      <td>${esc(r.vuln_class || "—")}</td>
      <td class="url" title="${esc(r.url)}">${esc(shortUrl(r.url))}</td>
      <td class="sum" title="${esc(r.summary)}">${esc(r.summary || "")}</td>
      <td class="num">${r.cost ? money(r.cost) : "—"}</td>
      <td class="num">${clock(r.ts)}</td>
    </tr>`).join("") : `<tr><td colspan="6" class="idle">nenhum resultado ${S.filter !== "all" ? "com esse filtro" : "ainda"}</td></tr>`;
}

// ---------------------------------------------------------------- drawer
function openDrawer(headHtml, tabs) {
  $("#dHead").innerHTML = headHtml;
  $("#dTabs").innerHTML = tabs.map((t, i) => `<button class="tab ${i ? "" : "on"}" data-tab="${i}">${esc(t.name)}</button>`).join("");
  const show = async (i) => {
    $$(".tab", $("#dTabs")).forEach((b) => b.classList.toggle("on", Number(b.dataset.tab) === i));
    $("#dBody").innerHTML = `<div class="idle">carregando…</div>`;
    $("#dBody").innerHTML = await tabs[i].render();
  };
  $("#dTabs").onclick = (e) => { const b = e.target.closest(".tab"); if (b) show(Number(b.dataset.tab)); };
  show(0);
  $("#scrim").hidden = false;
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
}
function closeDrawer() {
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#scrim").hidden = true;
}
const codebox = (txt) => `<div class="codebox"><button class="btn btn-ghost btn-sm copy" data-copy="${esc(txt)}">copiar</button><pre>${esc(txt)}</pre></div>`;

async function logTab(itemId) {
  const r = await api(`/api/log?target=${encodeURIComponent(S.target)}&item_id=${encodeURIComponent(itemId)}`);
  if (!r.ok) return `<div class="idle">${esc(r.error || "log indisponível")}</div>`;
  let html = `<div class="section-t">Sessão de caça (Sonnet)</div><pre class="log">${esc(r.hunt || "(vazio)")}</pre>`;
  if (r.review) html += `<div class="section-t">Revisão adversarial (Opus)</div><pre class="log">${esc(r.review)}</pre>`;
  return html;
}

async function openFinding(id) {
  const r = await api(`/api/finding?target=${encodeURIComponent(S.target)}&id=${encodeURIComponent(id)}`);
  if (!r.ok) return toast("Erro", r.error || "achado não encontrado", "err");
  const f = r.finding, sev = (f.severity || "").toLowerCase();
  openDrawer(`
    <div>${sevBadge(sev)} ${f.cvss != null ? `<span class="muted small">CVSS ${esc(f.cvss)}</span>` : ""}</div>
    <h2>${esc(f.title || f.vuln_class || "Achado")}</h2>
    <div class="url">${esc(f.url)}</div>`, [
    { name: "Resumo", render: async () => `
      <dl class="kv">
        <dt>Classe</dt><dd>${esc(f.vuln_class || "—")}</dd>
        <dt>Severidade</dt><dd>${sevBadge(sev) || "—"}</dd>
        <dt>Padrão de rota</dt><dd class="mono">${esc(f.pattern || "—")}</dd>
        <dt>Encontrado</dt><dd>${f.ts ? new Date(f.ts * 1000).toLocaleString("pt-BR") : "—"}</dd>
        <dt>Relatório</dt><dd class="mono">${esc(f.report_path || "—")}</dd>
      </dl>
      <div class="section-t">Resumo</div><div class="md">${md(f.summary)}</div>
      ${f.impact ? `<div class="section-t">Impacto</div><div class="md">${md(f.impact)}</div>` : ""}
      ${(f.steps || []).length ? `<div class="section-t">Passos</div><div class="md"><ol>${f.steps.map((x) => `<li>${esc(x)}</li>`).join("")}</ol></div>` : ""}
      ${f.repro_curl ? `<div class="section-t">Reprodução</div>${codebox(f.repro_curl)}` : ""}
      ${f.evidence_marker ? `<div class="section-t">Evidência esperada</div><div class="md"><code>${esc(f.evidence_marker)}</code></div>` : ""}
      ${f.review ? `<div class="section-t">Revisão independente (Opus)</div><div class="md">${md(f.review)}</div>` : ""}` },
    ...(f.council ? [{ name: "Conselho", render: async () => councilTab(f.council) }] : []),
    { name: "Relatório", render: async () => r.report ? `<div class="md">${md(r.report)}</div>` : `<div class="idle">sem report.md</div>` },
    { name: "Log do agente", render: () => logTab(f.item_id) },
  ]);
}

const RISCO_PT = { nenhum: "Nenhum", baixo: "Baixo", medio: "Médio", alto: "Alto", critico: "Crítico" };

function councilTab(c) {
  const ok = c.aprovado;
  const head = `<div class="council-verdict ${ok ? "ap" : "veto"}">`
    + `<b>${ok ? "✓ APROVADO" : "⛔ VETADO"}</b> · ${c.cadeiras_ok || 0}/5 cadeiras</div>`;
  const kv = `<dl class="kv">
    <dt>Severidade corporativa</dt><dd>${sevBadge((c.severidade_final || "").toLowerCase()) || "—"}</dd>
    <dt>Confiança</dt><dd>${esc(cap(c.confianca_final))}</dd>
    <dt>Risco corporativo</dt><dd>${esc(RISCO_PT[c.risco_corporativo] || "—")}</dd>
    ${c.lgpd_dado_pessoal ? `<dt>LGPD</dt><dd>Envolve dado pessoal — avaliar comunicação (art. 48)</dd>` : ""}
    ${(c.cia_pilares || []).length ? `<dt>Tríade CIA</dt><dd>${esc((c.cia_pilares || []).join(", "))}</dd>` : ""}
  </dl>`;
  const vetos = (c.motivos_veto || []).length
    ? `<div class="section-t">Vetos</div><div class="md"><ul>${c.motivos_veto.map((v) =>
        `<li><b>${esc(v.cadeira)}</b> — ${esc(v.motivo || "")}</li>`).join("")}</ul></div>`
    : "";
  const pareceres = (c.pareceres || []).filter((p) => p.ok).map((p) =>
    `<div class="parecer${p.veto ? " veto" : ""}">
      <div class="parecer-h"><b>${esc(p.nome || p.cadeira)}</b>${p.veto ? ` <span class="tag-veto">veto</span>` : ""}</div>
      <div class="md">${md(p.parecer || "")}</div></div>`).join("");
  return head + kv + vetos + `<div class="section-t">Pareceres</div>` + (pareceres || `<div class="idle">sem pareceres</div>`);
}

function cap(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : "—"; }

function openResult(r) {
  openDrawer(`
    <div>${verdict(r.verdict)} ${r.severity ? sevBadge(r.severity) : ""}</div>
    <h2>${esc(r.vuln_class || "Resultado")}</h2>
    <div class="url">${esc(r.url)}</div>`, [
    { name: "Resumo", render: async () => `
      <dl class="kv">
        <dt>Veredito</dt><dd>${verdict(r.verdict)}</dd>
        <dt>Padrão</dt><dd class="mono">${esc(r.pattern || "—")}</dd>
        <dt>Custo</dt><dd>${r.cost ? money(r.cost) : "—"}</dd>
        <dt>Lições usadas</dt><dd>${esc(r.lessons_used ?? 0)}</dd>
        <dt>Quando</dt><dd>${new Date(r.ts * 1000).toLocaleString("pt-BR")}</dd>
      </dl>
      <div class="section-t">Resumo do agente</div><div class="md">${md(r.summary || "")}</div>
      ${r.review ? `<div class="section-t">Revisão (Opus)</div><div class="md">${md(r.review)}</div>` : ""}` },
    { name: "Log do agente", render: () => logTab(r.item_id) },
  ]);
}

// ---------------------------------------------------------------- modal
function openModal(prefill = "") {
  $("#fTarget").value = prefill;
  $("#modal").hidden = false;
  setTimeout(() => $("#fTarget").focus(), 30);
}
const closeModal = () => { $("#modal").hidden = true; };

async function submitHunt(e) {
  e.preventDefault();
  const body = {
    target: $("#fTarget").value.trim(), scope: $("#fScope").value.trim(),
    workers: $("#fWorkers").value, timeout: $("#fTimeout").value, max_items: $("#fMax").value || null,
    continuous: $("#fCont").checked, fresh: $("#fFresh").checked, no_nuclei: $("#fNoNuclei").checked,
  };
  const r = await api("/api/hunt", body);
  if (!r.ok) return toast("Não foi possível iniciar", r.error || "erro", "err");
  closeModal();
  toast("Caçada iniciada", body.target, "ok");
  location.hash = "#/t/" + encodeURIComponent(body.target);
}

async function control(action) {
  if (action === "stop" && !confirm(`Parar a caçada em ${S.target}? As tarefas em andamento terminam antes.`)) return;
  const r = await api("/api/control", { target: S.target, action });
  const msg = { pause: "Pausa solicitada", resume: "Caçada retomada", stop: "Parada solicitada" }[action];
  r.ok ? toast(msg, S.target, "ok") : toast("Erro", r.error || "", "err");
}

// ---------------------------------------------------------------- queue
async function loadQueue() {
  const d = await api("/api/queue");
  if (S.view !== "queue") return;
  renderQueue(d);
}
function renderQueue(d) {
  const jobs = d.jobs || [];
  const waiting = jobs.filter((j) => j.status === "queued").length;
  $("#queueKpis").innerHTML = `
    <div class="kpi accent"><div class="label">Em execução</div><div class="value">${d.running || 0}<small>/ ${d.cap}</small></div><div class="sub">limite global</div></div>
    <div class="kpi"><div class="label">Aguardando</div><div class="value">${waiting}</div></div>
    <div class="kpi"><div class="label">Backend</div><div class="value" style="font-size:18px">${esc(d.backend || "local")}</div><div class="sub">${d.backend === "sqs" ? "Amazon SQS FIFO" : "fila local"}</div></div>`;
  $("#queueTable tbody").innerHTML = jobs.length ? jobs.map((j) => j.status === "running" ? `
    <tr><td><span class="v v-confirmed">em execução</span></td><td class="url">${esc(j.target)}</td><td>${esc(j.priority)}</td><td>${esc(j.who || "—")}</td><td class="num">—</td></tr>` : `
    <tr><td><span class="muted">posição ${j.position}</span></td><td class="url">${esc(j.target)}</td><td>${esc(j.priority)}</td><td>${esc(j.who || "—")}</td><td class="num">${j.eta_s ? "~" + Math.round(j.eta_s / 60) + " min" : "—"}</td></tr>`).join("") : `<tr><td colspan="5" class="idle">fila vazia</td></tr>`;
}

// ---------------------------------------------------------------- knowledge
async function loadKnowledge() {
  S.knowledge = await api("/api/knowledge");
  renderKnowledge();
}
function renderKnowledge() {
  const k = S.knowledge;
  if (!k) return;
  const ls = k.lessons || [];
  const by = (kind) => ls.filter((l) => l.kind === kind).length;
  $("#kKpis").innerHTML = `
    <div class="kpi"><div class="label">Lições</div><div class="value">${k.stats.lessons}</div></div>
    <div class="kpi accent"><div class="label">Vitórias</div><div class="value">${by("win")}</div><div class="sub">técnicas que confirmaram</div></div>
    <div class="kpi"><div class="label">Falsos positivos</div><div class="value">${by("fp")}</div><div class="sub">padrões a evitar</div></div>
    <div class="kpi"><div class="label">Notas</div><div class="value">${by("note")}</div></div>
    <div class="kpi"><div class="label">Classes vistas</div><div class="value">${k.stats.by_class.length}</div></div>
    <div class="kpi"><div class="label">Playbook</div><div class="value">${(k.playbook || "").length ? Math.round(k.playbook.length / 100) / 10 + "k" : "—"}</div><div class="sub">caracteres</div></div>`;
  $("#kByClass").innerHTML = k.stats.by_class.length ? k.stats.by_class.map((r) => `
    <div class="rate-row"><span>${esc(r.vuln_class)}</span><div class="bar"><i style="width:${Math.max(2, r.hit_rate * 100)}%"></i></div>
    <span class="n">${r.wins}/${r.tries} · ${r.fps} fp</span></div>`).join("") : `<div class="idle">sem dados ainda</div>`;
  $("#kByTech").innerHTML = k.stats.by_tech.length ? k.stats.by_tech.map((r) => `
    <div class="rate-row"><span class="mono">${esc(r.tech)}</span><span>${esc(r.vuln_class)}</span><span class="n">${r.wins} vitória(s)</span></div>`).join("") : `<div class="idle">ainda sem vitórias registradas</div>`;
  if (document.activeElement !== $("#playbook")) $("#playbook").value = k.playbook || "";
  const kinds = ["all", "win", "fp", "note"], KPT = { all: "todas", win: "vitórias", fp: "falsos positivos", note: "notas" };
  $("#kChips").innerHTML = kinds.map((x) => `<button class="chip ${S.kFilter === x ? "on" : ""}" data-kfilter="${x}">${KPT[x]}</button>`).join("");
  const shown = ls.filter((l) => S.kFilter === "all" || l.kind === S.kFilter).slice(0, 150);
  $("#kLessons").innerHTML = shown.length ? shown.map((l) => `
    <div class="lesson">
      <span class="kind kind-${esc(l.kind)}">${esc(KPT[l.kind] || l.kind).replace(/s$/, "")}</span>
      <div><div>${esc(l.text)}</div><div class="meta">${esc(l.vuln_class || "—")} · ${esc((l.tech || []).join(", ") || "tech ?")} · ${esc(l.target || "")} · ${ago(l.ts)}</div></div>
      <button class="icon-btn" data-del="${esc(l.id)}" title="apagar lição">✕</button>
    </div>`).join("") : `<div class="idle">nenhuma lição ainda: elas aparecem conforme as caçadas rodam</div>`;
}

// ---------------------------------------------------------------- settings
async function loadSettings() {
  const c = await api("/api/config");
  const p = $("#tgStatus");
  p.className = "pill " + (c.telegram_configured ? "ok" : "");
  p.textContent = c.telegram_configured ? "configurado" : "não configurado";
  $("#tgChat").value = c.telegram_chat_id || "";
  $("#tgToken").placeholder = c.telegram_token_masked ? `atual: ${c.telegram_token_masked}` : "123456:ABC…";
  $("#soundToggle").checked = localStorage.getItem("fosc.sound") === "1";
}

// ---------------------------------------------------------------- wiring
function wire() {
  $("#btnNewHunt").onclick = () => openModal();
  $("#btnNewHunt2").onclick = () => openModal();
  $("#btnRestart").onclick = () => openModal(S.target || "");
  $("#mClose").onclick = closeModal;
  $("#mCancel").onclick = closeModal;
  $("#modal").addEventListener("click", (e) => { if (e.target.id === "modal") closeModal(); });
  $("#huntForm").addEventListener("submit", submitHunt);
  $("#btnPause").onclick = () => control("pause");
  $("#btnResume").onclick = () => control("resume");
  $("#btnStop").onclick = () => control("stop");
  $("#dClose").onclick = closeDrawer;
  $("#scrim").onclick = closeDrawer;
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { closeDrawer(); closeModal(); }
    if (e.key === "n" && !e.ctrlKey && !e.metaKey && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) { e.preventDefault(); openModal(); }
  });

  $("#findings").addEventListener("click", (e) => { const c = e.target.closest(".finding"); if (c) openFinding(c.dataset.id); });
  $("#resultsTable").addEventListener("click", (e) => { const tr = e.target.closest("tr[data-idx]"); if (tr) openResult(S.filtered[Number(tr.dataset.idx)]); });
  $("#chips").addEventListener("click", (e) => { const c = e.target.closest(".chip"); if (c) { S.filter = c.dataset.filter; renderResults(S.snap.results, S.snap.verdicts); } });
  $("#search").addEventListener("input", (e) => { S.search = e.target.value; if (S.snap) renderResults(S.snap.results, S.snap.verdicts); });
  $("#dBody").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-copy]");
    if (!b) return;
    try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = "copiado"; setTimeout(() => (b.textContent = "copiar"), 1400); }
    catch { toast("Não deu para copiar", "copie manualmente", "err"); }
  });

  $("#kChips").addEventListener("click", (e) => { const c = e.target.closest(".chip"); if (c) { S.kFilter = c.dataset.kfilter; renderKnowledge(); } });
  $("#kLessons").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-del]");
    if (!b || !confirm("Apagar essa lição? Ela deixa de ser usada nas próximas caçadas.")) return;
    const r = await api("/api/knowledge/delete", { id: b.dataset.del });
    r.ok ? (toast("Lição apagada", "", "ok"), loadKnowledge()) : toast("Erro", "não encontrada", "err");
  });
  $("#btnSavePlaybook").onclick = async () => {
    const r = await api("/api/knowledge/playbook", { text: $("#playbook").value });
    r.ok ? toast("Playbook salvo", "", "ok") : toast("Erro ao salvar", "", "err");
  };

  $("#chatForm").addEventListener("submit", sendChat);
  $("#chatText").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); }
  });
  $("#chatText").addEventListener("input", (e) => autoGrow(e.target));
  $("#chatCtx").addEventListener("change", (e) => { S.chatCtx = e.target.value; S.chatData = null; refreshChat(true); });
  $("#chatModel").addEventListener("change", (e) => { S.chatModel = e.target.value; });
  $("#chatSetTarget").addEventListener("click", () => {
    const inp = $("#chatTargetInput");
    inp.hidden = !inp.hidden;
    if (!inp.hidden) inp.focus();
  });
  $("#chatTargetInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); if (e.target.value.trim()) setChatTarget(e.target.value); }
    if (e.key === "Escape") { e.target.hidden = true; e.target.value = ""; }
  });

  $("#btnSaveTg").onclick = async () => {
    const body = { telegram_chat_id: $("#tgChat").value };
    if ($("#tgToken").value) body.telegram_token = $("#tgToken").value;
    const r = await api("/api/config", body);
    $("#tgToken").value = "";
    r.ok ? (toast("Telegram salvo", "", "ok"), loadSettings()) : toast("Erro", r.error || "", "err");
  };
  $("#btnTestTg").onclick = async () => {
    const r = await api("/api/telegram/test", {});
    r.ok ? toast("Mensagem enviada", "confira o Telegram", "ok") : toast("Falhou", r.error || "", "err");
  };
  $("#soundToggle").onchange = (e) => { localStorage.setItem("fosc.sound", e.target.checked ? "1" : "0"); if (e.target.checked) chime(); };

  // live timers without waiting for the next SSE push
  setInterval(() => {
    $$("[data-start]").forEach((el) => { el.textContent = fmtDur(now() - Number(el.dataset.start)); });
    $$("[data-uptime]").forEach((el) => { if (el.dataset.uptime) el.textContent = fmtDur(now() - Number(el.dataset.uptime)); });
  }, 1000);
  setInterval(() => { if (S.view === "knowledge") loadKnowledge(); }, 15000);
  setInterval(() => { if (S.view === "queue") loadQueue(); }, 4000);
  api("/api/queue").then((d) => { $("#navQueue").hidden = !(d && d.enabled); }).catch(() => {});

  window.addEventListener("hashchange", route);
}

wire();
if (window.FOSC_MOCK) $("#modeLabel").textContent = "Demo · dados de exemplo"; $("#modeLabel").classList.add("demo");
route();
