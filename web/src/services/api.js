/**
 * Camada de integração da FOSC/TS. O estado local é demonstrativo.
 * Nenhum endpoint ou contrato definitivo do backend está presumido.
 */
export const API_BASE_URL = '';
// 'live' quando servido pelo viewer do agente (API real em /api/*); cai para
// 'mock' sozinho se os endpoints não existirem (demo standalone da Ana segue ok).
export const DATA_MODE = 'live';

const state = {
  campaign: { id: 'CMP-2026-001', name: 'Avaliação do Portal SeguroLab', target: 'portal.securelab.com.br', status: 'draft', progress: 0, startedAt: null, owner: 'Alex Costa', scopeId: 'SCP-001' },
  policies: {
    allowed: ['Consultar metadados públicos do ativo autorizado', 'Verificar configurações de segurança não destrutivas', 'Registrar evidências sem dados pessoais'],
    conditional: ['Validar comportamento autenticado com conta de teste', 'Executar verificações que possam gerar carga', 'Acessar dados de teste: requer aprovação humana explícita'],
    prohibited: ['Acessar, copiar ou alterar dados reais de terceiros', 'Persistência, exfiltração ou movimentação lateral', 'Negação de serviço ou ações fora do domínio autorizado'],
  },
  plan: [
    { id: 'PLN-01', hypothesis: 'Cabeçalhos de segurança podem estar incompletos.', action: 'Revisar a configuração HTTP do alvo dentro do escopo.', expected: 'Lista de cabeçalhos presentes e ausentes.', stop: 'Interromper se o alvo responder fora do domínio autorizado.', status: 'Aprovada por humano', command: 'curl -sI https://{target}/' },
    { id: 'PLN-02', hypothesis: 'Rotas públicas podem expor informações desnecessárias.', action: 'Solicitar validação de metadados públicos permitidos.', expected: 'Registro de metadados sem conteúdo sensível.', stop: 'Parar diante de dados pessoais ou de terceiros.', status: 'Aguardando aprovação humana', command: 'curl -s https://{target}/robots.txt' },
    { id: 'PLN-03', hypothesis: 'Um fluxo autenticado pode necessitar de conta de teste.', action: 'Validar comportamento autenticado com credencial de demonstração.', expected: 'Resultado de controle de acesso, sem alteração de dados.', stop: 'Não prosseguir sem conta de teste aprovada.', status: 'Aguardando aprovação humana', command: 'fosc-check auth-flow --account conta-demo --read-only' },
  ],
  // Linhas do terminal: registros demonstrativos (ordem cronológica). Nenhum comando é executado.
  commands: [
    { id: 'CMD-001', time: 'Hoje, 10:16:50', command: 'dig +short portal.securelab.com.br', status: 'allowed', planId: null, approvalId: null, actor: 'Agente (simulado)', output: ['203.0.113.10  (endereço redigido)'] },
    { id: 'CMD-002', time: 'Hoje, 10:32:10', command: 'curl -sI https://portal.securelab.com.br/api/status', status: 'allowed', planId: null, approvalId: null, actor: 'Agente (simulado)', output: ['HTTP/2 200', 'server: ████████  (valor redigido)'] },
    { id: 'CMD-003', time: 'Hoje, 10:40:51', command: 'curl -sI https://portal.securelab.com.br/', status: 'approved', planId: 'PLN-01', approvalId: 'APR-029', actor: 'Agente (simulado)', output: ['HTTP/2 200', 'content-type: text/html; charset=utf-8', 'content-security-policy: (ausente)'] },
    { id: 'CMD-004', time: 'Hoje, 10:48:07', command: 'curl -sI https://cdn.terceiro.example/', status: 'blocked', planId: null, approvalId: null, actor: 'Política de escopo', output: ['Bloqueado: host fora do escopo SCP-001. Nenhuma requisição foi enviada.'] },
    { id: 'CMD-005', time: 'Hoje, 10:54:39', command: 'curl -s https://portal.securelab.com.br/robots.txt', status: 'pending', planId: 'PLN-02', approvalId: 'APR-030', actor: 'Agente (simulado)', output: ['Aguardando decisão humana; nada foi executado.'] },
    { id: 'CMD-006', time: 'Hoje, 11:08:14', command: 'fosc-check auth-flow --account conta-demo --read-only', status: 'pending', planId: 'PLN-03', approvalId: 'APR-031', actor: 'Agente (simulado)', output: ['Aguardando decisão humana; nada foi executado.'] },
  ],
  approvals: [
    { id: 'APR-031', planId: 'PLN-03', title: 'Validar fluxo autenticado com conta de teste', scope: 'portal.securelab.com.br · conta de demonstração', reason: 'A ação depende de credencial autenticada fornecida pela equipe.', impact: 'Baixo · sem alteração prevista', requestedAt: 'Hoje, 11:08', status: 'pending' },
    { id: 'APR-030', planId: 'PLN-02', title: 'Revisar metadados adicionais previstos no escopo', scope: 'portal.securelab.com.br · rota autorizada', reason: 'A consulta adicional está dentro do alvo autorizado, mas requer validação do responsável.', impact: 'Médio · requer validação do responsável', requestedAt: 'Hoje, 10:54', status: 'pending' },
    { id: 'APR-029', planId: 'PLN-01', title: 'Verificar cabeçalhos HTTP públicos', scope: 'portal.securelab.com.br', reason: 'Verificação não destrutiva dentro do escopo aprovado.', impact: 'Baixo', requestedAt: 'Hoje, 10:35', status: 'approved' },
  ],
  findings: [
    { id: 'FND-101', title: 'Cabeçalho Content-Security-Policy ausente', asset: 'portal.securelab.com.br', severity: 'medium', confidence: 0.96, impact: 'A ausência de política reduz a proteção do navegador contra execução de conteúdo não esperado.', classification: 'confirmed', evidence: 'Resposta HTTP 200 sem Content-Security-Policy (captura demonstrativa, conteúdo redigido).', observedAt: 'Hoje, 10:41' },
    { id: 'FND-100', title: 'Metadado de versão em resposta pública', asset: 'portal.securelab.com.br', severity: 'low', confidence: 0.74, impact: 'A informação pode auxiliar a identificação de componentes; não demonstra exposição de dados.', classification: 'inconclusive', evidence: 'Cabeçalho Server parcialmente redigido; é necessária validação manual.', observedAt: 'Hoje, 10:32' },
    { id: 'FND-099', title: 'Permissão ampla em rota de perfil (hipótese)', asset: 'portal.securelab.com.br', severity: 'high', confidence: 0.31, impact: 'Se confirmada, poderia permitir acesso além da conta autorizada.', classification: 'discarded', evidence: 'Hipótese descartada: resposta simulada não contém evidência reproduzível.', observedAt: 'Hoje, 10:12' },
  ],
  audit: [
    { id: 'EVT-008', time: 'Hoje, 11:08:14', kind: 'approval', title: 'Aprovação solicitada', detail: 'Fluxo autenticado com conta de teste enviado à fila de aprovação humana.', actor: 'Sistema de demonstração' },
    { id: 'EVT-007', time: 'Hoje, 10:54:39', kind: 'decision', title: 'Ação condicionada à aprovação', detail: 'Consulta adicional dentro do alvo mantida bloqueada até decisão humana.', actor: 'Política de escopo' },
    { id: 'EVT-006', time: 'Hoje, 10:41:02', kind: 'result', title: 'Achado confirmado', detail: 'Ausência de cabeçalho de segurança registrada com evidência redigida.', actor: 'Agente (simulado)' },
    { id: 'EVT-005', time: 'Hoje, 10:40:51', kind: 'command', title: 'Ação registrada', detail: 'Revisão passiva de cabeçalhos HTTP — registro demonstrativo, sem comando executado.', actor: 'Agente (simulado)' },
    { id: 'EVT-004', time: 'Hoje, 10:32:18', kind: 'hypothesis', title: 'Hipótese registrada', detail: 'Metadado de versão pode estar visível em resposta pública; evidência inconclusiva.', actor: 'Agente (simulado)' },
    { id: 'EVT-003', time: 'Hoje, 10:20:04', kind: 'decision', title: 'Escopo validado', detail: 'Alvo corresponde ao domínio autorizado; itens fora do escopo serão bloqueados.', actor: 'Alex Costa' },
    { id: 'EVT-002', time: 'Hoje, 10:16:44', kind: 'hypothesis', title: 'Hipótese inicial', detail: 'Revisar postura de segurança HTTP do portal de demonstração.', actor: 'Agente (simulado)' },
    { id: 'EVT-001', time: 'Hoje, 10:16:02', kind: 'campaign', title: 'Campanha configurada', detail: 'Escopo informado: portal.securelab.com.br. Estado demonstrativo.', actor: 'Alex Costa' },
  ],
};

const cloneState = () => structuredClone(state);
const clock = () => `Hoje, ${new Intl.DateTimeFormat('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(new Date())}`;
const commandText = plan => (plan.command || 'verificação-registrada').replace('{target}', state.campaign.target);
const pushCommand = (command, status, { planId = null, approvalId = null, actor = 'Agente (simulado)', output = [] } = {}) => {
  const entry = { id: `CMD-${String(Date.now()).slice(-6)}`, time: clock(), command, status, planId, approvalId, actor, output };
  state.commands.push(entry);
  return entry;
};
// Passos passivos usados só para animar o terminal enquanto a campanha demonstrativa avança.
const liveSteps = [
  ['dig +short {target}', ['203.0.113.10  (endereço redigido)']],
  ['curl -sI https://{target}/', ['HTTP/2 200', 'content-type: text/html; charset=utf-8']],
  ['curl -sI https://{target}/favicon.ico', ['HTTP/2 200']],
  ['curl -sI https://{target}/status', ['HTTP/2 404']],
];
const pushEvent = (kind, title, detail, actor = 'Alex Costa') => state.audit.unshift({ id: `EVT-${String(Date.now()).slice(-6)}`, time: `Hoje, ${new Intl.DateTimeFormat('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'}).format(new Date())}`, kind, title, detail, actor });
const pause = (ms = 130) => new Promise(resolve => setTimeout(resolve, ms));

const mockApi = {
  async getWorkspace() { await pause(); return cloneState(); },
  async updateTarget(target) {
    await pause();
    if (state.campaign.status === 'running') throw new Error('Interrompa a campanha antes de alterar o alvo.');
    state.campaign.target = target.trim().replace(/^https?:\/\//, '');
    pushEvent('decision', 'Alvo autorizado atualizado', `Escopo configurado para ${state.campaign.target}.`);
    return cloneState();
  },
  async startCampaign({ target, authorized }) {
    await pause(240);
    if (!authorized) throw new Error('Confirme a autorização antes de iniciar.');
    if (state.campaign.status === 'running') throw new Error('Já existe uma campanha em andamento.');
    state.campaign.target = target.trim().replace(/^https?:\/\//, '');
    state.campaign.status = 'running'; state.campaign.progress = 8; state.campaign.startedAt = 'Agora';
    state.campaign.id = `CMP-${String(Date.now()).slice(-6)}`;
    pushEvent('campaign', 'Campanha iniciada', `Demonstração iniciada para ${state.campaign.target}.`);
    return cloneState();
  },
  async advanceCampaign() {
    if (state.campaign.status !== 'running') return cloneState();
    state.campaign.progress = Math.min(100, state.campaign.progress + 8);
    const [step, output] = liveSteps[Math.floor(state.campaign.progress / 8) % liveSteps.length];
    pushCommand(step.replaceAll('{target}', state.campaign.target), 'allowed', { output });
    if (state.campaign.progress === 100) {
      state.campaign.status = 'completed';
      pushEvent('result', 'Campanha concluída', 'Etapas demonstrativas concluídas; nenhum alvo foi consultado.');
    }
    return cloneState();
  },
  async emergencyStop() {
    await pause(120);
    state.campaign.status = 'interrupted';
    const cancelled = state.approvals.filter(item => item.status === 'pending');
    cancelled.forEach(item => {
      item.status = 'cancelled';
      state.commands.filter(row => row.approvalId === item.id && row.status === 'pending').forEach(row => { row.status = 'cancelled'; row.output = ['Cancelado pela parada de emergência; nada foi executado.']; });
      const plan = state.plan.find(entry => entry.id === item.planId || entry.action === item.title);
      if (plan) plan.status = 'Cancelada pela interrupção';
      pushEvent('approval', 'Aprovação cancelada pela interrupção', `${item.title} cancelada pelo controle de emergência.`, 'Sistema de segurança');
    });
    pushEvent('emergency', 'Interrupção de emergência', `Campanha interrompida; ${cancelled.length} ação(ões) pendente(s) cancelada(s).`);
    return cloneState();
  },
  async resolveApproval(id, decision) {
    await pause(160);
    const item = state.approvals.find(row => row.id === id);
    if (!item || item.status !== 'pending') throw new Error('Esta solicitação já foi resolvida.');
    item.status = decision;
    state.commands.filter(row => row.approvalId === id && row.status === 'pending').forEach(row => {
      row.status = decision === 'approved' ? 'approved' : 'rejected';
      row.output = decision === 'approved' ? ['Aprovado por decisão humana. Registro demonstrativo: nada foi executado.'] : ['Recusado e bloqueado por decisão humana. Nada foi executado.'];
    });
    const plan = state.plan.find(entry => entry.id === item.planId || entry.action === item.title);
    if (plan) plan.status = decision === 'approved' ? 'Aprovada por humano' : 'Recusada e bloqueada';
    pushEvent('approval', `Solicitação ${decision === 'approved' ? 'aprovada' : 'recusada'}`, `${item.title} — decisão humana registrada.`, 'Alex Costa');
    return cloneState();
  },
  async requestApproval(planId) {
    await pause(120);
    const plan = state.plan.find(item => item.id === planId);
    if (!plan) throw new Error('Item do plano não encontrado.');
    const item = { id: `APR-${String(Date.now()).slice(-5)}`, planId: plan.id, title: plan.action, scope: state.campaign.target, reason: plan.stop, impact: 'Pendente de revisão humana', requestedAt: 'Agora', status: 'pending' };
    state.approvals.unshift(item);
    pushCommand(commandText(plan), 'pending', { planId: plan.id, approvalId: item.id, output: ['Aguardando decisão humana; nada foi executado.'] });
    plan.status = 'Aguardando aprovação humana';
    pushEvent('approval', 'Aprovação solicitada', `${plan.action} enviada à fila humana.`);
    return cloneState();
  },
};

// REST e SSE genéricos; nenhum endpoint é definido antes do contrato do backend.
export async function request(path, options = {}) {
  if (!API_BASE_URL) throw new Error('URL da API ainda não configurada.');
  const response = await fetch(`${API_BASE_URL}${path}`, { headers: { 'Content-Type': 'application/json', ...options.headers }, ...options });
  if (!response.ok) throw new Error(`Falha ao consultar serviço (${response.status}).`);
  return response.json();
}
export function subscribeToUpdates(url, onUpdate, onError = () => {}) {
  if (!url) throw new Error('URL de eventos ainda não configurada.');
  const stream = new EventSource(url);
  stream.onmessage = event => { try { onUpdate(JSON.parse(event.data)); } catch { onError(new Error('Atualização inválida.')); } };
  stream.onerror = () => onError(new Error('Conexão de atualizações interrompida.'));
  return () => stream.close();
}

/* ============================================================================
 * Modo LIVE — consome a API real do viewer do agente (fosc/webview.py).
 * Mesma interface do mock; cai para o mock se os endpoints não existirem
 * (a demo standalone da Ana continua funcionando). Não altera app.js/CSS.
 * ========================================================================== */
const live = { target: null, confirmedIds: null };

function dashboardUrl(path) {
  return new URL(String(path).replace(/^\/+/, ''), document.baseURI).toString();
}
function requireLogin() {
  window.location.assign(dashboardUrl('auth/login'));
}
async function jget(path) {
  const r = await fetch(dashboardUrl(path), { headers: { Accept: 'application/json' } });
  if (r.status === 401) { requireLogin(); throw new Error('AUTH_REQUIRED'); }
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
async function jpost(path, body) {
  const r = await fetch(dashboardUrl(path), { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-FOSC': '1' }, body: JSON.stringify(body || {}) });
  if (r.status === 401) { requireLogin(); throw new Error('AUTH_REQUIRED'); }
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// Popup quando um achado é CONFIRMADO — usa o #toast-region do front da Ana.
function vulnToast(f) {
  const region = document.getElementById('toast-region');
  if (!region) return;
  const el = document.createElement('div');
  el.className = 'toast toast-finding';
  el.textContent = `🐛 Vuln confirmada · ${String(f.severity || '').toUpperCase()} · ${f.title}`;
  region.append(el);
  setTimeout(() => el.remove(), 6000);
}
function noteFindings(ws) {
  const confirmed = (ws.findings || []).filter(f => f.classification === 'confirmed');
  const ids = new Set(confirmed.map(f => f.id));
  if (live.confirmedIds !== null) {               // não dispara toast retroativo na 1ª carga
    for (const f of confirmed) if (!live.confirmedIds.has(f.id)) vulnToast(f);
  }
  live.confirmedIds = ids;
}

const liveApi = {
  async getWorkspace() {
    try {
      const ws = await jget(`/api/workspace${live.target ? `?target=${encodeURIComponent(live.target)}` : ''}`);
      live.target = ws.campaign?.target || live.target;
      noteFindings(ws);
      return ws;
    } catch (error) {
      if (error.message === 'AUTH_REQUIRED') throw error;
      return mockApi.getWorkspace();
    }
  },
  async advanceCampaign() { return this.getWorkspace(); }, // o motor avança sozinho; aqui só re-busca (+toast)
  async updateTarget(target) {
    live.target = String(target || '').trim().replace(/^https?:\/\//, '');
    live.confirmedIds = null;
    return this.getWorkspace();
  },
  async startCampaign({ target, authorized }) {
    if (!authorized) throw new Error('Confirme a autorização antes de iniciar.');
    try {
      const r = await jpost('/api/hunt', { target: String(target || '').trim() });
      if (r.error) throw new Error(r.error);
      live.target = String(target || '').trim().replace(/^https?:\/\//, ''); live.confirmedIds = null;
      return this.getWorkspace();
    } catch (error) {
      if (error.message === 'AUTH_REQUIRED') throw error;
      if (/^HTTP /.test(error.message)) return mockApi.startCampaign({ target, authorized });
      throw error;
    }
  },
  async emergencyStop() {
    try { await jpost('/api/halt', { target: live.target }); return this.getWorkspace(); }
    catch (error) {
      if (error.message === 'AUTH_REQUIRED') throw error;
      return mockApi.emergencyStop();
    }
  },
  async resolveApproval(id, decision) {
    const r = await jpost('/api/approval', { target: live.target, id, decision });
    if (r.error) throw new Error(r.error);
    return this.getWorkspace();
  },
  async requestApproval() { return this.getWorkspace(); }, // no live, os pedidos nascem do agente
};

export const api = DATA_MODE === 'live' ? liveApi : mockApi;
