"use strict";
// FOSC/TS — modo demo. Imita a API do agente (fosc/webview.py) com dados de
// EXEMPLO, para o design rodar sem backend. Os campos têm os mesmos nomes da
// API real: quando plugar no agente, basta abrir com ?live (ou apagar este
// arquivo do index.html) e o app.js passa a usar /api/* e /api/events de verdade.
(function () {
  if (new URLSearchParams(location.search).has("live")) return;

  const T = Date.now() / 1000;
  const TARGET = "app-demo.bbts.local";
  const H = "https://" + TARGET;

  const confirmed = [
    { id: "f1", item_id: "i3", title: "SQL injection no login (bypass de autenticação)", vuln_class: "sqli", severity: "critical", cvss: 9.8,
      url: H + "/rest/user/login", pattern: "/rest/user/login",
      summary: "O campo email é concatenado na query SQL. O payload `' OR 1=1--` autentica como o primeiro usuário (admin) sem senha.",
      impact: "Tomada de conta administrativa sem credenciais.",
      steps: ["Enviar POST /rest/user/login com email `' OR 1=1--`", "Receber token JWT do admin"],
      repro_curl: `curl -s -X POST ${H}/rest/user/login -H 'Content-Type: application/json' -d '{"email":"\\' OR 1=1--","password":"x"}'`,
      evidence_marker: "\"email\":\"admin@", review: "Reproduzido de forma independente: o token devolvido pertence ao usuário id=1 (admin).",
      report_path: "pocs/f1/report.md", ts: T - 3400, mitre: [{ id: "T1190" }] },
    { id: "f2", item_id: "i7", title: "IDOR na cesta de compras", vuln_class: "idor", severity: "high", cvss: 7.5,
      url: H + "/rest/basket/2", pattern: "/rest/basket/{n}",
      summary: "Trocar o id da cesta devolve a cesta de outro usuário: o servidor não verifica o dono.",
      repro_curl: `curl -s ${H}/rest/basket/2 -H 'Authorization: Bearer <token-usuario-1>'`,
      evidence_marker: "\"UserId\":2", review: "Confirmado com dois usuários distintos.", report_path: "pocs/f2/report.md", ts: T - 2100 },
    { id: "f3", item_id: "i11", title: "XSS refletido na busca", vuln_class: "xss", severity: "medium", cvss: 6.1,
      url: H + "/#/search?q=<iframe src=javascript:alert(1)>", pattern: "/#/search?q=",
      summary: "O parâmetro q é renderizado sem escape; um iframe com javascript: executa no contexto da origem.",
      repro_curl: `curl -s '${H}/#/search?q=%3Ciframe%20src%3Djavascript:alert(1)%3E'`,
      review: "Executa em navegador headless; sem CSP.", report_path: "pocs/f3/report.md", ts: T - 900 },
  ];

  const paths = ["/api/Products", "/rest/products/search?q=", "/api/Users/{n}", "/rest/user/whoami", "/api/Feedbacks",
    "/rest/basket/{n}", "/api/Quantitys", "/rest/admin/application-configuration", "/api/Challenges", "/ftp/",
    "/rest/track-order/{id}", "/api/Recycles", "/rest/user/change-password", "/api/SecurityQuestions", "/rest/memories"];
  const verdictsCycle = ["rejected", "refuted", "unverified", "rejected", "duplicate", "inconclusive", "rejected", "timeout"];
  const classes = ["idor", "sqli", "ssrf", "auth-bypass", "info-disclosure", "xss", "path-traversal", "mass-assignment"];

  const results = [];
  paths.forEach((p, i) => results.push({
    ts: T - 3600 + i * 190, verdict: verdictsCycle[i % verdictsCycle.length], vuln_class: classes[i % classes.length],
    url: H + p.replace("{n}", 3 + i).replace("{id}", "5267-" + i), pattern: p, summary: "Testado; sem impacto demonstrável com as técnicas tentadas.", cost: 0.08 + (i % 5) * 0.03,
    item_id: "i" + (100 + i), lessons_used: i % 4,
  }));
  confirmed.forEach((f) => results.push({ ts: f.ts, verdict: "confirmed", vuln_class: f.vuln_class, url: f.url, pattern: f.pattern,
    summary: f.summary, cost: 0.42, item_id: f.item_id, severity: f.severity, review: f.review }));
  results.sort((a, b) => b.ts - a.ts);

  const lines = [
    "$ nmap -sV -p 80,443,3000 app-demo.bbts.local",
    "[HIPÓTESE] IDOR em /api/Users/{n} · critério de parada: 2 ids distintos",
    "$ ffuf -u https://app-demo.bbts.local/FUZZ -w raft-small-words.txt",
    "lendo bundle main.js (rotas da API)",
    "$ curl -s https://app-demo.bbts.local/rest/admin/application-configuration",
    "[BLOQUEADO] cdn.terceiro.com (fora do escopo autorizado)",
    "$ sqlmap -u 'https://app-demo.bbts.local/rest/products/search?q=a' --batch --level 2",
    "[APROVAÇÃO] solicitada: ação sensível (escrita) em /rest/user/change-password",
    "operador aprovou via Telegram",
    "$ nuclei -u https://app-demo.bbts.local -severity medium,high,critical",
    "[SCOPE] permitido *.bbts.local · exceto pagamentos.bbts.local",
    "[OPUS-REVIEW] revisão adversarial iniciada para achado sqli",
  ];
  const activity = [];
  for (let i = 0; i < 24; i++) activity.unshift({ ts: T - 600 + i * 22, msg: lines[i % lines.length], kind: i % 9 === 0 ? "system" : "", url: H + paths[i % paths.length].replace("{n}", 7 + i).replace("{id}", "5267-" + i) });

  const state = {
    target: TARGET, status: "running", surface_total: 64, done: results.length, confirmed_count: confirmed.length,
    severity: { critical: 1, high: 1, medium: 1 },
    meta: { round: 2, workers: 2, continuous: true, scope: "*.bbts.local, exceto pagamentos.bbts.local", cost_usd: 4.87,
      round_done: 11, round_total: 32, started_at: T - 3700 },
    active: {
      a1: { url: H + "/api/Users/14", phase: "hunting", started_at: T - 95 },
      a2: { url: H + "/rest/user/login", phase: "reviewing", started_at: T - 40 },
    },
    activity, results, confirmed,
    verdicts: results.reduce((m, r) => (m[r.verdict] = (m[r.verdict] || 0) + 1, m), {}),
  };

  const overview = () => ({
    version: "0.2.0-bb",
    totals: { live: 1, confirmed: state.confirmed_count + 2, cost: state.meta.cost_usd + 3.1 },
    targets: [
      { target: TARGET, status: state.status, confirmed: state.confirmed_count },
      { target: "intranet-hml.bbts.local", status: "finished", confirmed: 2 },
      { target: "api-parceiros.bbts.local", status: "paused", confirmed: 0 },
    ],
  });

  const knowledge = {
    stats: { lessons: 9,
      by_class: [{ vuln_class: "sqli", wins: 3, tries: 7, fps: 1, hit_rate: .43 }, { vuln_class: "idor", wins: 4, tries: 12, fps: 2, hit_rate: .33 },
        { vuln_class: "xss", wins: 2, tries: 9, fps: 3, hit_rate: .22 }, { vuln_class: "ssrf", wins: 0, tries: 5, fps: 1, hit_rate: 0 }],
      by_tech: [{ tech: "express", vuln_class: "sqli", wins: 3 }, { tech: "angular", vuln_class: "xss", wins: 2 }, { tech: "sequelize", vuln_class: "idor", wins: 4 }] },
    playbook: "# Playbook FOSC/TS (exemplo)\n\n- Express + Sequelize: testar concatenação em login/busca antes de fuzzing amplo.\n- IDOR: sempre provar com DOIS usuários distintos.\n- Rejeitar XSS sem execução real em navegador headless.\n",
    lessons: [
      { id: "l1", kind: "win", text: "Login aceita `' OR 1=1--` no email: SQLi clássico em Express/Sequelize.", vuln_class: "sqli", tech: ["express"], target: TARGET, ts: T - 3400 },
      { id: "l2", kind: "fp", text: "Status 200 em /api/Users/{n} não prova IDOR: a resposta era o próprio usuário.", vuln_class: "idor", tech: ["sequelize"], target: TARGET, ts: T - 2600 },
      { id: "l3", kind: "note", text: "WAF limita 30 req/min em /rest/user/*: reduzir workers.", vuln_class: null, tech: ["nginx"], target: TARGET, ts: T - 1800 },
    ],
  };

  const chat = { messages: [
    { role: "user", text: "Qual o achado mais grave até agora?" },
    { role: "assistant", text: "O **SQLi no login** (`/rest/user/login`), CVSS 9.8: autentica como admin sem senha.\n\n```\ncurl -s -X POST " + H + "/rest/user/login -d '{\"email\":\"\\' OR 1=1--\"}'\n```", cost: 0.06 },
  ], live: {} };

  const reports = {
    f1: "# SQL injection no login\n\n**Severidade:** crítica (CVSS 9.8) · **MITRE:** T1190\n\n## Passos\n1. POST /rest/user/login com email `' OR 1=1--`\n2. Token do admin é devolvido\n\n## Impacto\nTomada de conta administrativa.\n\n## Correção\nUsar consultas parametrizadas.",
  };

  // ---------------- governança (escopo / HITL / trilha de auditoria / HALT)
  const governance = {
    scope: { allowed: 142, blocked: 7 },
    audit: { intact: true, algorithm: "SHA-256" },
    approvals_pending: [
      { id: "ap1", action: "escrita em /rest/user/change-password", url: H + "/rest/user/change-password", target: TARGET },
    ],
  };

  // ---------------- API fake
  const clone = (o) => JSON.parse(JSON.stringify(o));
  async function api(path, body) {
    await new Promise((r) => setTimeout(r, 120));
    const u = new URL(path, location.href), p = u.pathname.replace(/^.*\/api\//, "/api/");
    if (body !== undefined) {
      if (p === "/api/chat") {
        chat.messages.push({ role: "user", text: body.message });
        chat.live = { running: true, text: "", activity: ["lendo achados do alvo", "$ curl -s " + H + "/rest/user/whoami"] };
        setTimeout(() => { chat.live = {}; chat.messages.push({ role: "assistant", text: "(modo demo) Resposta de exemplo do agente FOSC/TS.", cost: 0.03 }); }, 2500);
      }
      if (p === "/api/control" && body.action) {
        state.status = { pause: "paused", resume: "running", stop: "stopped", halt: "stopped" }[body.action] || state.status;
        if (body.action === "halt") { governance.approvals_pending = []; state.activity.unshift({ ts: Date.now() / 1000, msg: "[BLOQUEADO] HALT de emergência acionado pelo operador", kind: "system" }); }
      }
      if (p === "/api/approvals/decide") {
        governance.approvals_pending = governance.approvals_pending.filter((a) => a.id !== body.id);
        state.activity.unshift({ ts: Date.now() / 1000, msg: `[APROVAÇÃO] ${body.decision === "approve" ? "concedida" : "negada"} pelo operador`, kind: "system" });
      }
      return { ok: true };
    }
    if (p === "/api/overview") return overview();
    if (p === "/api/state") return clone(state);
    if (p === "/api/governance") return clone(governance);
    if (p === "/api/finding") { const f = confirmed.find((x) => x.id === u.searchParams.get("id")); return f ? { ok: true, finding: f, report: reports[f.id] || "" } : { ok: false, error: "não encontrado" }; }
    if (p === "/api/log") return { ok: true, hunt: lines.join("\n") + "\n\n(modo demo — log de exemplo)", review: "Revisão adversarial (Opus): tentativa de refutar… não refutado." };
    if (p === "/api/chat") return clone(chat);
    if (p === "/api/knowledge") return clone(knowledge);
    if (p === "/api/config") return { telegram_configured: true, telegram_chat_id: "123456789", telegram_token_masked: "1234…abcd" };
    return { ok: false, error: "rota não simulada: " + p };
  }

  // ---------------- SSE fake: empurra overview/state e anima o feed
  function events(url) {
    const listeners = {}, wantsState = url.includes("target=");
    const emit = (name, data) => (listeners[name] || []).forEach((fn) => fn({ data: JSON.stringify(data) }));
    let i = 0;
    const tick = () => {
      if (state.status === "running") {
        state.activity.unshift({ ts: Date.now() / 1000, msg: lines[i++ % lines.length], kind: i % 7 === 0 ? "system" : "", url: H + paths[i % paths.length].replace("{n}", 3 + i % 9).replace("{id}", "5267-" + i) });
        state.activity.length = Math.min(state.activity.length, 200);
        if (i % 5 === 0) { state.done = Math.min(state.surface_total, state.done + 1); state.meta.round_done++; state.meta.cost_usd += 0.11; }
      }
      emit("overview", overview());
      if (wantsState) emit("state", state);
    };
    const es = {
      _url: url,
      addEventListener(name, fn) { (listeners[name] = listeners[name] || []).push(fn); },
      close() { clearInterval(es._t); },
    };
    setTimeout(tick, 50);
    es._t = setInterval(tick, 2000);
    return es;
  }

  window.FOSC_MOCK = { api, events };
})();
