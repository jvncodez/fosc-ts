/* Dados de EXEMPLO para a interface renderizar sem backend (abrir o index.html
   direto no navegador já funciona). Depois isso vem da API do agente
   (fosc/webview.py serve o estado real: snapshot, achados, trilha, aprovações).
   As designers podem editar livremente para testar layouts. */
window.FOSC_TS_DATA = {
  campanha: {
    alvo: "https://1.migbot.com.br/#/",
    escopo: "1.migbot.com.br [estrito]",
    status: "rodando",
    custo_usd: 1.26,
    trilha_integra: true
  },
  kpis: { testados: 73, confirmados: 2, criticos: 1, custo: "US$ 1.26" },
  achados: [
    { sev: "critical", classe: "SQL injection — auth bypass", url: "/rest/user/login", cvss: 9.8, confianca: "alta", mitre: ["T1190", "T1213"] },
    { sev: "medium",   classe: "IDOR / BOLA",                  url: "/api/Addresss/1", cvss: 6.5, confianca: "média", mitre: ["T1190", "T1213"] }
  ],
  aprovacoes: [
    { id: "e95cd253", acao: "active-hunt", contexto: "iniciar teste ATIVO de 3 endpoint(s) no escopo autorizado", status: "pendente" }
  ],
  trilha: [
    { hora: "12:28:01", tipo: "run_start",    detalhe: "escopo 1.migbot.com.br [estrito]" },
    { hora: "12:28:01", tipo: "proxy_start",  detalhe: "enforcement de escopo na rede ativo" },
    { hora: "12:28:18", tipo: "approval",     detalhe: "active-hunt aprovado por operador" },
    { hora: "12:28:18", tipo: "plan",         detalhe: "hipótese: /rest/user/login pode ser vulnerável a SQLi/IDOR…" },
    { hora: "12:31:28", tipo: "scope_block",  detalhe: "BLOQUEADO fora de escopo: acl.xml" },
    { hora: "12:34:06", tipo: "finding",      detalhe: "[critical] SQLi auth bypass /rest/user/login" },
    { hora: "12:34:29", tipo: "run_end",      detalhe: "finished · 2 confirmados · US$ 1.26" }
  ]
};
