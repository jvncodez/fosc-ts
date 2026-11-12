/* FOSC/TS — lógica mínima do scaffold (vanilla JS, sem build).
   Renderiza os dados de exemplo e troca de aba. As designers evoluem/estilizam;
   a integração com a API real do agente entra depois (ver web/README.md). */
(function () {
  const D = window.FOSC_TS_DATA || {};

  // --- navegação por abas ---
  document.querySelectorAll(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      document.getElementById(tab.dataset.panel).classList.add("active");
    });
  });

  // --- escopo no topo ---
  const scope = document.getElementById("scope");
  if (scope && D.campanha) scope.textContent = "escopo: " + D.campanha.escopo;

  // --- KPIs ---
  const kpiWrap = document.getElementById("kpis");
  if (kpiWrap && D.kpis) {
    const labels = { testados: "endpoints testados", confirmados: "confirmados", criticos: "críticos", custo: "custo" };
    kpiWrap.innerHTML = Object.keys(D.kpis).map(k =>
      `<div class="kpi"><div class="v">${D.kpis[k]}</div><div class="l">${labels[k] || k}</div></div>`
    ).join("");
  }

  // --- achados ---
  const tbody = document.getElementById("findings-body");
  if (tbody && D.achados) {
    tbody.innerHTML = D.achados.map(f => `
      <tr>
        <td><span class="sev ${f.sev}">${f.sev}</span></td>
        <td>${f.classe}</td>
        <td><code>${f.url}</code></td>
        <td>${f.cvss ?? "—"}</td>
        <td>${f.confianca ?? "—"}</td>
        <td>${(f.mitre || []).join(", ")}</td>
      </tr>`).join("");
  }

  // --- trilha de auditoria ---
  const chain = document.getElementById("chain-status");
  if (chain && D.campanha) {
    chain.innerHTML = D.campanha.trilha_integra
      ? '<span class="chain-ok">● cadeia íntegra ✓</span>'
      : '<span style="color:var(--sev-critical)">● cadeia VIOLADA ✗</span>';
  }
  const audit = document.getElementById("audit-list");
  if (audit && D.trilha) {
    audit.innerHTML = D.trilha.map(e => `
      <div class="audit-row"><time>${e.hora}</time><span class="k">${e.tipo}</span><span>${e.detalhe}</span></div>`
    ).join("");
  }

  // --- aprovações (human-in-the-loop) ---
  const appr = document.getElementById("approvals-list");
  if (appr && D.aprovacoes) {
    appr.innerHTML = D.aprovacoes.length ? D.aprovacoes.map(a => `
      <div class="approval">
        <div class="ctx"><strong>${a.acao}</strong> <code>${a.id}</code><br><span>${a.contexto}</span></div>
        <button class="btn approve" disabled title="protótipo">✅ Aprovar</button>
        <button class="btn deny" disabled title="protótipo">❌ Negar</button>
      </div>`).join("") : "<p>Sem aprovações pendentes.</p>";
  }
})();
