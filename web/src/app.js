import { api, DATA_MODE } from './services/api.js';
import { authenticatedFetch, getIdentity, logout } from './services/auth.js';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const icon = (name, cls = '') => `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const content = $('#page-content');
const names = { fleet: 'Campanhas', campaign: 'Console da campanha', scope: 'Escopo e política', plan: 'Plano do agente', approvals: 'Aprovação humana', terminal: 'Terminal da campanha', findings: 'Achados confirmados', reports: 'Relatórios', audit: 'Trilha de auditoria' };
const cmdLabels = { allowed: 'Permitido', approved: 'Aprovado', pending: 'Pendente', blocked: 'Bloqueado', rejected: 'Recusado', cancelled: 'Cancelado' };
const kinds = { hypothesis: 'Hipótese', decision: 'Decisão', approval: 'Aprovação', command: 'Comando', result: 'Resultado', campaign: 'Campanha', emergency: 'Emergência' };
const labels = { draft: 'Pronta para iniciar', running: 'Em andamento', interrupted: 'Interrompida', completed: 'Concluída', pending: 'Pendente', approved: 'Aprovada', rejected: 'Recusada', cancelled: 'Cancelada' };
const severity = { critical: 'Crítica', high: 'Alta', medium: 'Média', low: 'Baixa' };
let workspace;
let findingFilter = 'all';
let auditFilter = 'all';
let reportMode = 'executive';
let terminalFilter = 'all';

const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
const heading = (title, description, action = '') => `<div class="page-heading"><div><div class="eyebrow">FOSC/TS · DADOS REAIS DO MOTOR</div><h1>${title}</h1><p>${description}</p></div>${action ? `<div class="heading-actions">${action}</div>` : ''}</div>`;
const note = (text, type = '') => `<div class="data-note ${type}">${icon('info')}<span>${text}</span></div>`;
const statusPill = (key, text = labels[key] || key) => `<span class="status-pill status-${key}">${esc(text)}</span>`;
const primary = (label, action, symbol = 'arrow') => `<button class="button button-primary" data-action="${action}">${icon(symbol)} ${label}</button>`;

function fleetCard(c) {
  const sev = c.severity || {};
  const alta = (sev.critical || 0) + (sev.high || 0);
  return `<article class="panel finding-card fleet-card" data-action="open-campaign" data-campaign="${esc(c.target)}" role="button" tabindex="0" style="cursor:pointer">
    <div class="finding-card-heading"><span class="severity-mark ${c.live ? 'high' : 'low'}">${icon(c.live ? 'radar' : 'file')}</span>
      <div class="finding-main-title"><div class="eyebrow">${esc(c.scopeId || '')} · início ${esc(c.startedAt || '—')}</div><h2>${esc(c.target)}</h2></div>
      <span class="term-dot ${c.live ? 'on' : ''}" aria-hidden="true"></span>${statusPill(c.status, labels[c.status] || c.status)}</div>
    <div class="finding-metrics"><div><small>Confirmados</small><strong>${c.confirmed || 0}</strong></div>
      <div><small>Alta/Crítica</small><strong>${alta}</strong></div>
      <div><small>Média</small><strong>${sev.medium || 0}</strong></div>
      <div><small>Custo</small><strong>$${(c.cost || 0).toFixed(2)}</strong></div></div></article>`;
}

async function fleetView() {
  const data = await api.getCampaigns();
  const cs = data.campaigns || [];
  const t = data.totals || {};
  return `${heading('Campanhas', 'Todas as campanhas do motor, ao vivo. Clique em uma para abri-la nas demais páginas.', `<a class="button button-primary" href="#campaign">${icon('plus')} Nova campanha</a>`)}
    <div class="report-stats"><div><strong>${t.count ?? cs.length}</strong><span>Campanhas</span></div>
      <div><strong>${t.live ?? 0}</strong><span>Ao vivo</span></div>
      <div><strong>${t.confirmed ?? 0}</strong><span>Confirmados</span></div>
      <div><strong>$${(t.cost ?? 0).toFixed(2)}</strong><span>Custo total</span></div></div>
    <div class="finding-list">${cs.map(fleetCard).join('') || `<section class="panel empty-state">${icon('radar')}<strong>Nenhuma campanha ainda</strong><p>Inicie uma no Console da campanha.</p></section>`}</div>`;
}

function campaignView() {
  const c = workspace.campaign;
  const active = c.status === 'running';
  const editable = !active;
  const queued = !!c.queued;
  const pending = workspace.approvals.filter(a => a.status === 'pending').length;
  const confirmed = workspace.findings.filter(f => f.classification === 'confirmed').length;
  return `${heading('Console da campanha', 'Configure o alvo autorizado, acompanhe a execução e mantenha o controle humano.', primary('Ver trilha de auditoria', 'go-audit', 'audit'))}
    <section class="campaign-banner scope-boundary ${active ? 'is-running' : ''}"><div><div class="campaign-kicker"><span class="pulse ${active ? 'on' : ''}"></span> ${queued ? 'NA FILA' : active ? 'CAMPANHA ATIVA' : 'CONTROLE DA CAMPANHA'}</div><h2>${queued ? 'Campanha na fila' : active ? 'Campanha em execução controlada' : c.status === 'interrupted' ? 'Campanha interrompida' : c.status === 'completed' ? 'Execução concluída' : 'Tudo pronto para iniciar'}</h2><p>${queued ? `Posição ${c.queuePosition} na fila — aguardando vaga no motor. Começa automaticamente.` : active ? 'A campanha avança conforme o motor executa as tarefas dentro do escopo autorizado; ações sensíveis passam por aprovação humana.' : 'Defina um alvo autorizado e confirme o escopo antes de iniciar.'}</p></div><div class="campaign-banner-side">${statusPill(c.status)}<small>${esc(c.id)}</small></div></section>
    <div class="telemetry-divider" aria-hidden="true"><span></span><span></span><span></span><span></span><span></span><span></span><span></span></div>
    <div class="campaign-grid"><section class="panel campaign-control"><div class="panel-heading"><div><h2 class="panel-title">${active ? 'Campanha em andamento' : 'Alvo e autorização'}</h2><p class="panel-subtitle">${active ? 'Escopo bloqueado enquanto a campanha está ativa.' : 'Informe somente ativos próprios ou com autorização expressa.'}</p></div>${icon('shield','panel-title-icon')}</div>
      <form id="campaign-form" class="campaign-form"><div class="field"><label for="campaign-target">Alvo autorizado</label><input id="campaign-target" name="target" value="${esc(c.target)}" ${editable ? '' : 'readonly'} required maxlength="200" pattern="(https?://)?[a-zA-Z0-9.\\-]+(:[0-9]{1,5})?(/[^ ]*)?" title="Informe um domínio ou URL válida"></div>
      ${editable ? `<div class="field"><label for="campaign-workers">Workers paralelos (1–10)</label><input id="campaign-workers" name="workers" type="number" min="1" max="10" value="6" title="Quantos sub-agentes caçam em paralelo"></div><div class="field"><label for="campaign-scope">Escopo / autorização (opcional)</label><textarea id="campaign-scope" name="scope" rows="2" maxlength="500" placeholder="Restringe a caçada. Ex.: somente ${esc(c.target||'app.alvo.com')}, sem subdomínios nem domínio-pai."></textarea></div><label class="authorization-check"><input name="authorized" type="checkbox" required><span><strong>Confirmo que tenho autorização para este alvo e que o escopo foi revisado.</strong><small>Esta confirmação é registrada na trilha de auditoria.</small></span></label><div class="campaign-form-actions"><button class="button" type="button" data-action="save-target">Salvar escopo</button><button class="button button-primary" type="submit">${icon('play')} Iniciar campanha</button></div>` : `<div class="campaign-progress"><div class="progress-label"><strong>${queued ? 'Na fila' : 'Progresso'}</strong><b>${queued ? `posição ${c.queuePosition}` : `${c.progress}%`}</b></div><div class="progress-track"><span style="width:${queued ? 4 : c.progress}%"></span></div><small>${queued ? 'Começa assim que houver vaga; atualiza sozinho.' : 'Atualiza automaticamente a cada 5s.'}</small></div><div class="campaign-form-actions"><a class="button" href="#scope">Revisar política</a><button class="button button-danger" type="button" data-action="emergency">${icon('stop')} Interromper agora</button></div>`}</form>
      <div class="scope-lock">${icon('scope')}<span><strong>Escopo ${esc(c.scopeId)}</strong><small>${active ? 'Alvo bloqueado durante a campanha' : 'A política restringe as ações ao alvo autorizado'}</small></span><a class="row-link" href="#scope">Ver política ${icon('chevron')}</a></div>
    </section><aside class="campaign-side"><section class="panel"><div class="panel-heading"><div><h2 class="panel-title">Guardrails humanos</h2><p class="panel-subtitle">Controles que mantêm a campanha sob revisão</p></div></div><div class="guardrail-list"><div><span class="guardrail-check">${icon('check')}</span><span><strong>Alvo autorizado</strong><small>Escopo definido pela equipe</small></span></div><a href="#approvals"><span class="guardrail-wait">${icon('approve')}</span><span><strong>${pending} ação(ões) aguardam aprovação</strong><small>Nenhuma ação condicionada segue sem decisão humana</small></span>${icon('chevron')}</a><a href="#findings"><span class="guardrail-check">${icon('bug')}</span><span><strong>${confirmed} achado(s) confirmado(s)</strong><small>Separados de itens descartados ou inconclusivos</small></span>${icon('chevron')}</a></div></section><section class="panel emergency-panel"><div class="emergency-panel-icon">${icon('stop')}</div><div><h2>Interrupção de emergência</h2><p>Encerra a campanha e cancela todas as aprovações pendentes.</p></div><button class="button button-danger" data-action="emergency">Interromper campanha</button></section></aside></div>
    <div class="campaign-lower"><section class="panel"><div class="panel-heading"><div><h2 class="panel-title">Atividade recente</h2><p class="panel-subtitle">Decisões e resultados registrados</p></div><a href="#audit" class="row-link">Abrir auditoria ${icon('arrow')}</a></div>${workspace.audit.slice(0,3).map(auditRow).join('')}</section><section class="panel"><div class="panel-heading"><div><h2 class="panel-title">Fila de aprovação</h2><p class="panel-subtitle">Revisão humana obrigatória para ações condicionadas</p></div><a href="#approvals" class="row-link">Revisar ${icon('arrow')}</a></div>${pending ? workspace.approvals.filter(a=>a.status==='pending').slice(0,2).map(a=>`<div class="mini-approval"><span class="approval-mark">${icon('approve')}</span><span><strong>${esc(a.title)}</strong><small>${esc(a.requestedAt)} · ${esc(a.impact)}</small></span>${statusPill('pending','Pendente')}</div>`).join('') : `<div class="empty-state compact"><strong>Nenhuma ação pendente</strong><p>A fila está em dia.</p></div>`}</section></div>
    ${note('Estado, progresso, aprovações e eventos vêm do motor real (RunState). Ações sensíveis passam por aprovação humana antes de qualquer execução.')}`;
}

function scopeView() {
  const c = workspace.campaign;
  const cards = [
    ['allowed','Permitidas','Ações compatíveis com o escopo e sem impacto destrutivo',workspace.policies.allowed,'policy-allowed'],
    ['conditional','Condicionadas','Exigem aprovação humana explícita antes de qualquer execução',workspace.policies.conditional,'policy-conditional'],
    ['prohibited','Proibidas','Bloqueadas pela política em qualquer circunstância',workspace.policies.prohibited,'policy-prohibited'],
  ];
  return `${heading('Escopo e política','Regras visíveis antes e durante toda a campanha.',`<span class="status-pill status-approved">${icon('shield')} Política ativa</span>`)}
    <section class="panel scope-summary scope-boundary"><div class="scope-summary-symbol">${icon('scope')}</div><div><div class="eyebrow">ESCOPO AUTORIZADO · ${esc(c.scopeId)}</div><h2>${esc(c.target)}</h2><p>Qualquer domínio, rota ou ação fora deste escopo deve ser bloqueado e registrado.</p></div><a class="button" href="#campaign">${icon('arrow')} Console da campanha</a></section>
    <div class="policy-grid">${cards.map(([key,title,desc,items,cls])=>`<section class="panel policy-card ${cls}"><div class="policy-heading"><span class="policy-symbol">${icon(key==='allowed'?'check':key==='conditional'?'approve':'stop')}</span><div><h2>${title}</h2><p>${desc}</p></div></div><ul>${items.map(item=>`<li>${icon(key==='allowed'?'check':key==='conditional'?'info':'close')}<span>${esc(item)}</span></li>`).join('')}</ul>${key==='conditional'?`<a href="#approvals" class="row-link">Ver fila de aprovação humana ${icon('arrow')}</a>`:''}</section>`).join('')}</div>
    <section class="panel stop-rule"><span>${icon('stop')}</span><div><strong>Condição de parada global</strong><p>Interrompa imediatamente se o alvo divergir do escopo, houver impacto inesperado, surgirem dados de terceiros ou faltar autorização.</p></div><button class="button button-danger" data-action="emergency">${icon('stop')} Parada de emergência</button></section>
    <div class="data-note">${icon('info')}<span><strong>Política real do motor.</strong> As três listas vêm do Authorization Engine determinístico (fosc/authz.py): ações passivas são auto-aprovadas, sensíveis exigem aprovação humana e proibidas são recusadas automaticamente. O proxy de escopo valida cada requisição antes de enviá-la.</span></div>`;
}

function planView() {
  return `${heading('Plano do agente','Revise hipóteses, ações propostas, resultados esperados e condições de parada.',`<span class="status-pill status-running">${icon('plan')} Plano do motor</span>`)}
    <div class="plan-intro"><div>${icon('info')}<span><strong>Revisão antes da ação.</strong> O plano vem da trilha de auditoria real do agente: cada hipótese, ação e condição de parada é registrada antes da execução. Esta tela só exibe; a execução fica no motor.</span></div><a class="button button-danger button-small" href="#campaign" data-action="emergency">${icon('stop')} Interromper campanha</a></div>
    <div class="plan-list">${workspace.plan.map((item,index)=>`<article class="panel plan-card"><div class="plan-card-top"><span class="plan-index">${String(index+1).padStart(2,'0')}</span><div><div class="eyebrow">${esc(item.id)}</div><h2>${esc(item.hypothesis)}</h2></div><span class="plan-status ${planStatusClass(item)}">${esc(item.status)}</span></div><div class="plan-details"><div><span class="plan-detail-title">Ação proposta</span><p>${esc(item.action)}</p></div><div><span class="plan-detail-title">Resultado esperado</span><p>${esc(item.expected)}</p></div><div class="stop-condition"><span class="plan-detail-title">Condição de parada</span><p>${esc(item.stop)}</p></div></div>${item.status.includes('Aguardando aprovação humana')?`<span class="status-pill status-pending">Enviado para aprovação</span>`:item.status.includes('Aguardando aprovação')||item.status==='Condicionada'?`<button class="button button-small" data-action="request-approval" data-id="${esc(item.id)}">${icon('approve')} Solicitar aprovação humana</button>`:`${planFooter(item)}`}</article>`).join('')}</div>
    ${note('Hipóteses e ações não representam uma execução real. A equipe de backend é responsável pelo plano executável e pelos controles de política.')}`;
}

function planStatusClass(item) {
  if (item.status.includes('Aguardando') || item.status.includes('Condicionada')) return 'waiting';
  if (item.status.includes('Recusada') || item.status.includes('Cancelada')) return 'blocked';
  return '';
}
function planFooter(item) {
  if (item.status === 'Aguardando aprovação humana') return `<span class="status-pill status-pending">${icon('approve')} Enviado para aprovação</span>`;
  if (item.status.includes('Aguardando aprovação') || item.status === 'Condicionada') return `<button class="button button-small" data-action="request-approval" data-id="${esc(item.id)}">${icon('approve')} Solicitar aprovação humana</button>`;
  if (item.status === 'Aprovada por humano') return `<span class="status-pill status-approved">${icon('check')} Decisão aprovada</span>`;
  if (item.status === 'Recusada e bloqueada') return `<span class="status-pill status-rejected">${icon('close')} Recusada e bloqueada</span>`;
  if (item.status === 'Cancelada pela interrupção') return `<span class="status-pill status-cancelled">${icon('stop')} Cancelada pela parada</span>`;
  return `<span class="status-pill status-approved">${icon('check')} Revisado</span>`;
}

function approvalsView() {
  const pending = workspace.approvals.filter(a=>a.status==='pending');
  const resolved = workspace.approvals.filter(a=>a.status!=='pending');
  return `${heading('Fila de aprovação humana','Ações sensíveis permanecem bloqueadas até uma decisão humana.',`<span class="approval-count-large">${pending.length}<small>pendente(s)</small></span>`)}
    <div class="human-gate-banner">${icon('approve')}<span><strong>Portão humano ativo</strong><small>Aprovar ou recusar registra responsável, horário e justificativa na trilha de auditoria.</small></span><a href="#audit" class="row-link">Ver trilha ${icon('arrow')}</a></div>
    ${pending.length?`<div class="approval-list">${pending.map(item=>`<article class="panel approval-card"><div class="approval-card-head"><span class="approval-mark">${icon('approve')}</span><div><div class="eyebrow">${esc(item.id)} · ${esc(item.requestedAt)}</div><h2>${esc(item.title)}</h2></div>${statusPill('pending','Aguardando decisão')}</div><div class="approval-context"><div><strong>Escopo solicitado</strong><span>${esc(item.scope)}</span></div><div><strong>Motivo da aprovação</strong><span>${esc(item.reason)}</span></div><div><strong>Impacto estimado</strong><span>${esc(item.impact)}</span></div></div><div class="approval-guard">${icon('info')} Esta solicitação não pode prosseguir sem autorização explícita.</div><div class="approval-actions"><button class="button button-danger-quiet" data-action="resolve-approval" data-decision="rejected" data-id="${esc(item.id)}">Recusar e bloquear</button><button class="button button-primary" data-action="resolve-approval" data-decision="approved" data-id="${esc(item.id)}">${icon('check')} Aprovar ação</button></div></article>`).join('')}</div>`:`<section class="panel empty-state">${icon('check')}<strong>Nenhuma ação aguardando aprovação</strong><p>A fila foi resolvida. Novas solicitações aparecem aqui antes de qualquer ação sensível.</p></section>`}
    ${resolved.length?`<section class="panel resolved-panel"><div class="panel-heading"><div><h2 class="panel-title">Decisões registradas</h2><p class="panel-subtitle">Aprovações e recusas anteriores</p></div><a href="#audit" class="row-link">Auditoria ${icon('arrow')}</a></div>${resolved.map(item=>`<div class="resolved-row"><span><strong>${esc(item.title)}</strong><small>${esc(item.id)} · ${esc(item.requestedAt)}</small></span>${statusPill(item.status)}</div>`).join('')}</section>`:''}
    ${note('As aprovações são reais: a decisão é gravada no ApprovalStore e destrava (ou bloqueia) o gate que o agente está aguardando, associada ao operador responsável.')}`;
}

function findingsView() {
  const filters = [['all','Todos'],['confirmed','Confirmados'],['discarded','Descartados'],['inconclusive','Inconclusivos']];
  const shown = workspace.findings.filter(f=>findingFilter==='all'||f.classification===findingFilter);
  const counts = Object.fromEntries(filters.map(([key])=>[key,key==='all'?workspace.findings.length:workspace.findings.filter(f=>f.classification===key).length]));
  return `${heading('Achados confirmados','Severidade, confiança, impacto e evidência para cada resultado revisado.',`<button class="button" data-action="export">${icon('download')} Exportar achados</button>`)}
    <div class="finding-tabs">${filters.map(([key,label])=>`<button class="filter-tab ${findingFilter===key?'active':''}" data-finding-filter="${key}">${label}<span>${counts[key]}</span></button>`).join('')}</div>
    <div class="finding-list">${shown.map(item=>`<article class="panel finding-card" data-action="open-finding" data-id="${esc(item.id)}" role="button" tabindex="0" style="cursor:pointer"><div class="finding-card-heading"><span class="severity-mark ${item.severity}">${icon(item.classification==='confirmed'?'check':item.classification==='discarded'?'close':'info')}</span><div class="finding-main-title"><div class="eyebrow">${esc(item.id)} · ${esc(item.asset)}</div><h2>${esc(item.title)}</h2></div><span class="severity-pill ${item.severity}">${severity[item.severity]}</span><span class="finding-class ${item.classification}">${item.classification==='confirmed'?'Confirmado':item.classification==='discarded'?'Descartado':'Inconclusivo'}</span></div><div class="finding-metrics"><div><small>Confiança</small><strong>${Math.round(item.confidence*100)}%</strong><div class="confidence-track"><span style="width:${item.confidence*100}%"></span></div></div><div><small>Impacto</small><strong>${item.severity==='critical'||item.severity==='high'?'Elevado':item.severity==='medium'?'Moderado':'Baixo'}</strong></div><div><small>Observado</small><strong>${esc(item.observedAt)}</strong></div></div><div class="finding-evidence"><strong>Evidência</strong><p>${esc(item.evidence)}</p><small>Impacto: ${esc(item.impact)}</small></div></article>`).join('')||`<section class="panel empty-state"><strong>Nenhum achado nesta categoria</strong><p>Os achados são organizados por estado de validação.</p></section>`}</div>
    ${note('Achados, severidade e evidências vêm da verificação em duas camadas do motor (reexecução mecânica + refutação adversarial por outro modelo) e do parecer do Conselho.')}`;
}

function reportsView() {
  const tab = reportMode==='executive';
  return `${heading('Relatórios','Apresente uma visão executiva ou consulte os detalhes técnicos da campanha.',`<button class="button" data-action="export">${icon('download')} Exportar ${tab?'resumo':'técnico'}</button>`)}
    <div class="report-switch" role="tablist"><button class="${tab?'active':''}" data-report-mode="executive">Resumo executivo</button><button class="${!tab?'active':''}" data-report-mode="technical">Visão técnica</button></div>
    <section class="panel report-document"><div class="report-doc-head"><div><div class="eyebrow">FOSC/TS · ${tab?'RELATÓRIO EXECUTIVO':'RELATÓRIO TÉCNICO'}</div><h2>${tab?'Panorama de segurança':'Registro técnico da campanha'}</h2><p>Campanha ${esc(workspace.campaign.id)} · Alvo autorizado: ${esc(workspace.campaign.target)}</p></div><span class="status-pill status-${workspace.campaign.status}">${labels[workspace.campaign.status]}</span></div>
      ${tab?`<div class="report-stats"><div><strong>${workspace.findings.filter(f=>f.classification==='confirmed').length}</strong><span>Achados confirmados</span></div><div><strong>${workspace.findings.filter(f=>f.severity==='critical'||f.severity==='high').length}</strong><span>Prioridade alta</span></div><div><strong>${workspace.approvals.filter(a=>a.status==='pending').length}</strong><span>Aprovações pendentes</span></div></div><div class="report-section"><h3>Resumo executivo</h3><p>Este relatório consolida os controles da campanha, a revisão humana de ações sensíveis e a classificação dos achados confirmados pelo motor. Os números acima refletem o estado real da campanha.</p></div><div class="report-section"><h3>Recomendações prioritárias</h3><ul><li>Manter o escopo de cada campanha explicitamente autorizado.</li><li>Resolver aprovações humanas antes de permitir qualquer ação condicionada.</li><li>Validar achados confirmados e documentar a correção com evidências.</li><li>Interromper a campanha diante de qualquer condição de parada.</li></ul></div>`:`<div class="report-stats"><div><strong>${workspace.findings.length}</strong><span>Registros de achados</span></div><div><strong>${workspace.audit.length}</strong><span>Eventos de auditoria</span></div><div><strong>${workspace.campaign.progress}%</strong><span>Progresso</span></div></div><div class="report-section"><h3>Achados e evidências</h3>${workspace.findings.map(f=>`<div class="technical-row"><span class="severity-pill ${f.severity}">${severity[f.severity]}</span><span><strong>${esc(f.title)}</strong><small>${esc(f.classification)} · confiança ${Math.round(f.confidence*100)}% · ${esc(f.asset)}</small><small>Evidência: ${esc(f.evidence)}</small></span></div>`).join('')}</div><div class="report-section"><h3>Política aplicada</h3><p>Permitidas: ${workspace.policies.allowed.length} regras · Condicionadas: ${workspace.policies.conditional.length} regras · Proibidas: ${workspace.policies.prohibited.length} regras. Ações condicionadas dependem de decisão humana registrada.</p></div>`}
    </section>${note('Relatório gerado a partir do estado real da campanha. A exportação salva um snapshot JSON do que está em tela.')}`;
}

function termLine(row) {
  const decide = row.status === 'pending' && row.approvalId
    ? `<div class="term-actions"><button class="button button-danger-quiet button-small" data-action="resolve-approval" data-decision="rejected" data-id="${esc(row.approvalId)}">Recusar</button><button class="button button-primary button-small" data-action="resolve-approval" data-decision="approved" data-id="${esc(row.approvalId)}">${icon('check')} Aprovar</button></div>` : '';
  const refs = [row.planId, row.approvalId].filter(Boolean).map(esc).join(' · ');
  return `<div class="term-line term-${esc(row.status)}"><div class="term-meta"><time>${esc(row.time)}</time><span class="term-id">${esc(row.id)}</span></div><div class="term-main"><div class="term-cmd"><span class="term-prompt" aria-hidden="true">$</span><code>${esc(row.command)}</code></div>${row.output?.length ? `<pre class="term-out">${row.output.map(esc).join('\n')}</pre>` : ''}<small>${esc(row.actor)}${refs ? ` · ${refs}` : ''}</small></div><div class="term-side">${statusPill(row.status, cmdLabels[row.status] || row.status)}${decide}</div></div>`;
}

function feedLine(a) {
  return `<div class="term-line term-feed feed-${esc(a.kind)}"><div class="term-meta"><time>${esc(a.time)}</time><span class="term-id">${esc(a.kind)}</span></div><div class="term-main"><div class="term-cmd"><span class="term-prompt" aria-hidden="true">›</span><code>${esc(a.msg)}</code></div></div></div>`;
}

function fmtDur(sec){ sec=Math.max(0,Math.floor(sec||0)); const h=Math.floor(sec/3600),m=Math.floor(sec%3600/60),s=sec%60; if(h)return `${h}h ${m}m`; if(m)return `${m}m ${s}s`; return `${s}s`; }
function money(n){ n=Number(n||0); return '$'+(n>0&&n<1?n.toFixed(4):n.toFixed(2)); }
const _SEVC={critical:'#e5484d',high:'#f76808',medium:'#ffb224',low:'#30a46c'};
function sevBreak(sev){ const order=[['critical','Crít'],['high','Alta'],['medium','Média'],['low','Baixa']]; const tot=order.reduce((a,[k])=>a+(sev[k]||0),0); if(!tot)return{txt:'nenhum ainda',bar:''}; const txt=order.filter(([k])=>sev[k]).map(([k,l])=>`${sev[k]} ${l}`).join(' · '); const bar=order.filter(([k])=>sev[k]).map(([k])=>`<i style="width:${sev[k]/tot*100}%;background:${_SEVC[k]}"></i>`).join(''); return{txt,bar}; }
const kpi=(label,value,extra='',cls='')=>`<div class="kpi ${cls}"><div class="kpi-label">${esc(label)}</div><div class="kpi-value">${value}</div>${extra}</div>`;

function terminalView() {
  const c = workspace.campaign;
  const h = workspace.hunt || {};
  const live = (h.status || c.status) === 'running';
  const now = Date.now()/1000;
  const feed = workspace.activity || [];
  const filters = [['all', 'Todos'], ...Object.entries(cmdLabels)];
  const count = key => key === 'all' ? workspace.commands.length : workspace.commands.filter(r => r.status === key).length;
  const shown = workspace.commands.filter(r => terminalFilter === 'all' || r.status === terminalFilter);
  const total = h.total || 0, done = h.done || 0;
  const pct = h.progress ?? (total ? Math.round(done/total*100) : 0);
  const sb = sevBreak(h.severity || {});
  const activeN = h.activeCount || 0;
  const elapsed = h.startedAt ? ((live ? now : (h.finishedAt || now)) - h.startedAt) : 0;
  const inflight = h.inflight || [];
  return `${heading('Terminal da caça', 'Painel ao vivo da campanha: o que o agente testa agora, progresso, custo e achados.', `<a class="button button-small" href="#findings">${icon('bug')} Achados</a><button class="button button-small" data-action="export">${icon('download')} Exportar</button>`)}
    <section class="campaign-banner scope-boundary ${live ? 'is-running' : ''}"><div><div class="campaign-kicker"><span class="pulse ${live ? 'on' : ''}"></span> ${live ? 'AO VIVO' : 'SEM EXECUÇÃO ATIVA'}</div><h2>${esc(c.target)}</h2><p>${statusPill(c.status, labels[c.status] || c.status)}${h.round ? ` · round ${esc(h.round)}` : ''}${h.workers ? ` · ${esc(h.workers)} workers` : ''} · ${h.continuous ? 'contínua' : 'passe único'}</p></div><div class="campaign-banner-side"><a class="button button-small" href="#findings">${icon('bug')} Ver achados</a></div></section>
    <div class="hunt-kpis">
      ${kpi('Testados', `${done}<small>/ ${total}</small>`, `<div class="kpi-bar"><i style="width:${pct}%"></i></div>`)}
      ${kpi('Confirmados', String(h.confirmed || 0), `<div class="kpi-sub">${sb.txt}</div>${sb.bar ? `<div class="sevbar">${sb.bar}</div>` : ''}`, 'accent')}
      ${kpi('Custo', money(h.cost), `<div class="kpi-sub">${h.costPerEndpoint ? money(h.costPerEndpoint) + ' / endpoint' : '—'}</div>`)}
      ${kpi('Round', `${esc(h.roundDone ?? 0)}<small>/ ${esc(h.roundTotal ?? 0)}</small>`, `<div class="kpi-sub">round ${esc(h.round ?? '—')}</div>`)}
      ${kpi('Em voo', `${activeN}<small>/ ${esc(h.workers ?? '—')}</small>`, `<div class="kpi-sub">${live ? (activeN ? 'caçando' : 'ocioso') : '—'}</div>`)}
      ${kpi('Duração', elapsed ? fmtDur(elapsed) : '—', `<div class="kpi-sub">${h.startedAt ? 'desde ' + (c.startedAt || '') : ''}</div>`)}
    </div>
    <section class="panel term-panel hunt-inflight"><div class="term-bar"><div class="term-bar-title">${icon('radar')}<strong>Em andamento</strong></div><div class="term-bar-state">${activeN ? `${activeN} tarefa(s)` : ''}</div></div>
      <div class="inflight-body">${inflight.length ? inflight.map(t => `<div class="task ${esc(t.phase)}"><div class="task-url" title="${esc(t.url)}">${esc(t.url)}</div><div class="task-meta"><span>${t.phase === 'reviewing' ? 'revisão Opus' : 'caçando'}</span><span>${t.startedAt ? fmtDur(now - t.startedAt) : ''}</span></div><div class="task-shimmer"></div></div>`).join('') : `<div class="idle">nenhuma tarefa em andamento</div>`}</div></section>
    <section class="panel term-panel"><div class="term-bar"><div class="term-bar-title">${icon('terminal')}<strong>Atividade ao vivo</strong></div><div class="term-bar-state"><span class="term-dot ${live ? 'on' : ''}"></span>${live ? 'Ao vivo' : 'Sem execução ativa'}</div></div>
      <div class="term-body" id="feed-body" role="log" aria-live="polite" aria-label="Atividade ao vivo do agente">${feed.map(feedLine).join('') || `<div class="empty-state compact"><strong>Sem atividade registrada</strong><p>O feed do agente (recon, vereditos, achados) aparece aqui durante a campanha.</p></div>`}</div></section>
    <div class="finding-tabs term-filters">${filters.map(([key, label]) => `<button class="filter-tab ${terminalFilter === key ? 'active' : ''}" data-terminal-filter="${key}">${label}<span>${count(key)}</span></button>`).join('')}</div>
    <section class="panel term-panel"><div class="term-bar"><div class="term-bar-title">${icon('terminal')}<strong>Comandos · política</strong></div><div class="term-bar-state"><span class="term-dot ${live ? 'on' : ''}"></span>${live ? 'Ao vivo' : '—'}</div></div>
      <div class="term-body" id="term-body" role="log" aria-live="polite" aria-label="Linhas de comando da campanha">${shown.map(termLine).join('') || `<div class="empty-state compact"><strong>Nenhum comando nesta categoria</strong><p>Os comandos registrados aparecem aqui em ordem cronológica.</p></div>`}</div>
      <div class="term-foot">${icon('info')}<span>Somente leitura. Comandos pendentes só seguem com decisão humana; bloqueados nunca são enviados.</span></div></section>`;
}

function refreshTerminal() {
  const old = $('#term-body');
  const stick = !old || old.scrollHeight - old.scrollTop - old.clientHeight < 40;
  const top = old?.scrollTop ?? 0;
  const fold = $('#feed-body');
  const fstick = !fold || fold.scrollHeight - fold.scrollTop - fold.clientHeight < 40;
  content.innerHTML = terminalView();
  const body = $('#term-body');
  if (body) body.scrollTop = stick ? body.scrollHeight : top;
  const feed = $('#feed-body');
  if (feed && fstick) feed.scrollTop = feed.scrollHeight;
}

function auditRow(item) { return `<div class="audit-row"><span class="audit-icon audit-${item.kind}">${icon(item.kind==='approval'?'approve':item.kind==='command'?'plan':item.kind==='emergency'?'stop':item.kind==='result'?'check':item.kind==='hypothesis'?'info':'scope')}</span><div class="audit-body"><div><strong>${esc(item.title)}</strong><span class="audit-type">${kinds[item.kind]||esc(item.kind)}</span></div><p>${esc(item.detail)}</p><small>${esc(item.actor)}</small></div><time>${esc(item.time)}</time></div>`; }
function auditView() {
  const filters=[['all','Todos'],...Object.entries(kinds)];
  const filtered=workspace.audit.filter(e=>auditFilter==='all'||e.kind===auditFilter);
  return `${heading('Trilha de auditoria','Registro cronológico e rastreável de hipóteses, decisões, aprovações, comandos e resultados.',`<button class="button" data-action="export">${icon('download')} Exportar trilha</button>`)}
    <div class="audit-banner">${icon('audit')}<span><strong>Registro append-only encadeado por hash</strong><small>Cada evento grava autor, horário, decisão, escopo e resultado, encadeando o hash do anterior — cadeia de custódia verificável.</small></span></div>
    <div class="filter-tabs audit-filters">${filters.map(([key,label])=>`<button class="filter-tab ${auditFilter===key?'active':''}" data-audit-filter="${key}">${label}</button>`).join('')}</div>
    <section class="panel audit-log"><div class="audit-date-label">HOJE · ${filtered.length} EVENTOS</div>${filtered.map(auditRow).join('')||`<div class="empty-state"><strong>Nenhum evento nesta categoria</strong><p>Novos eventos aparecerão aqui em ordem cronológica.</p></div>`}</section>
    ${note('A trilha é verificável: cada evento encadeia o hash do anterior; adulterar um quebra a cadeia (fosc --audit confere a integridade).')}`;
}

function renderPage(route) {
  const pages={ campaign:campaignView, scope:scopeView, plan:planView, approvals:approvalsView, terminal:terminalView, findings:findingsView, reports:reportsView, audit:auditView };
  return (pages[route]||campaignView)();
}

async function renderRoute() {
  closeProfileMenu();
  const route=location.hash.replace(/^#\/?/,'')||'campaign';
  if(!names[route]) { location.hash='#campaign'; return; }
  $('#breadcrumb-current').textContent=names[route];
  $$('.nav-item[data-page]').forEach(link=>link.classList.toggle('active',link.dataset.page===route));
  $('#sidebar').classList.remove('open');$('.mobile-menu-backdrop').classList.remove('show');
  content.innerHTML='<section class="panel"><div class="loading-bar"></div></section>';
  try {
    workspace=await api.getWorkspace();
    if(route==='fleet')content.innerHTML=await fleetView();
    else if(route==='terminal')refreshTerminal();
    else content.innerHTML=renderPage(route);
    const pending=workspace.approvals.filter(item=>item.status==='pending').length;
    $('#approval-count').textContent=pending;
    $('#approval-count').hidden=!pending;
    const confirmed=workspace.findings.filter(item=>item.classification==='confirmed').length;
    const fc=$('#findings-count');
    if(fc){fc.textContent=confirmed;fc.hidden=!confirmed;}
  } catch(error) {
    content.innerHTML=`${heading('Dados indisponíveis','Não foi possível carregar os dados do motor.')}<section class="panel empty-state">${icon('info')}<strong>Falha ao carregar os dados</strong><p>${esc(friendlyError(error))}</p><button class="button" data-action="retry">Tentar novamente</button></section>`;
  }
}

function toast(message) { const el=document.createElement('div');el.className='toast';el.innerHTML=`${icon('check')}${esc(message)}`;$('#toast-region').append(el);setTimeout(()=>el.remove(),3800); }
// Traduz mensagens técnicas (ex.: "HTTP 404") para algo compreensível, só na
// apresentação. Não altera o formato do erro na camada de API (api.js/auth.js).
function friendlyError(error) {
  const message = error?.message || '';
  if (typeof error?.status === 'number' || /HTTP \d+/.test(message)) {
    return 'Não foi possível concluir a ação agora. Tente novamente em instantes.';
  }
  return message || 'Ocorreu um erro inesperado.';
}
function downloadSnapshot() {
  const route=location.hash.replace(/^#\/?/,'')||'campaign';
  const collections={findings:workspace.findings,audit:workspace.audit,terminal:workspace.commands,reports:{campaign:workspace.campaign,findings:workspace.findings,approvals:workspace.approvals,policies:workspace.policies}};
  // simulated=false só quando os dados em tela vieram de fato do liveApi (DATA_MODE
  // 'live' e a tela chegou a renderizar, isto é, nenhuma chamada caiu no catch de
  // renderRoute). Sem essa segunda condição, não há garantia de origem real.
  const data={simulated:!(DATA_MODE==='live'&&workspace),exportedAt:new Date().toISOString(),section:route,data:collections[route]??workspace};
  const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});
  const url=URL.createObjectURL(blob);const link=document.createElement('a');
  link.href=url;link.download=`fosc-ts-${route}-demo.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function openEmergencyDialog() {
  const layer=$('#modal-layer');
  layer.innerHTML=`<div class="modal-backdrop" data-action="dismiss-modal"><section class="modal emergency-modal" role="alertdialog" aria-modal="true" aria-labelledby="emergency-title"><div class="modal-head"><div><span class="modal-alert-icon">${icon('stop')}</span><h2 id="emergency-title">Interromper campanha agora?</h2><p>Esta ação marca a campanha como interrompida e cancela todas as aprovações humanas pendentes.</p></div><button class="modal-close" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><div class="emergency-consequences"><strong>O que será registrado</strong><span>• Campanha marcada como interrompida</span><span>• Ações pendentes canceladas</span><span>• Evento de emergência adicionado à trilha de auditoria</span></div><div class="modal-footer"><button class="button" data-action="close-modal">Continuar campanha</button><button class="button button-danger" data-action="confirm-emergency">${icon('stop')} Confirmar interrupção</button></div></section></div>`;
  $('#modal-layer').setAttribute('aria-hidden','false');
  $('#modal-layer [data-action="confirm-emergency"]').focus();
}
function closeModal(){const layer=$('#modal-layer');layer.innerHTML='';layer.setAttribute('aria-hidden','true');lastCurl='';}

// Markdown mínimo e seguro (escapa antes de formatar) para renderizar o report.md
// do achado: títulos, listas, tabelas simples, **negrito**, `código` e blocos ```.
function mdInline(s){ return s.replace(/`([^`]+)`/g,'<code>$1</code>').replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>'); }
function md(src){
  const lines=String(src||'').split('\n'); let html='',inCode=false,inList=false;
  const closeList=()=>{ if(inList){html+='</ul>';inList=false;} };
  for(const raw of lines){
    if(/^\s*```/.test(raw)){ if(inCode){html+='</code></pre>';inCode=false;} else {closeList();html+='<pre class="md-pre"><code>';inCode=true;} continue; }
    if(inCode){ html+=esc(raw)+'\n'; continue; }
    const h=raw.match(/^(#{1,6})\s+(.*)$/);
    if(h){ closeList(); const l=Math.min(h[1].length+1,6); html+=`<h${l} class="md-h">${mdInline(esc(h[2]))}</h${l}>`; continue; }
    if(/^\s*[-*]\s+/.test(raw)){ if(!inList){html+='<ul class="md-ul">';inList=true;} html+=`<li>${mdInline(esc(raw.replace(/^\s*[-*]\s+/,'')))}</li>`; continue; }
    closeList();
    if(/^\s*\|.*\|\s*$/.test(raw)){ if(/^\s*\|[\s:|-]+\|\s*$/.test(raw))continue; html+=`<div class="md-row">${raw.split('|').filter(c=>c.trim()!=='').map(c=>`<span>${mdInline(esc(c.trim()))}</span>`).join('')}</div>`; continue; }
    if(raw.trim()==='')continue;
    html+=`<p>${mdInline(esc(raw))}</p>`;
  }
  if(inCode)html+='</code></pre>'; closeList();
  return html;
}
let lastCurl='';
const cap = s => { s = String(s ?? '').trim(); return s ? s[0].toUpperCase() + s.slice(1) : '—'; };
const _RISCO = { nenhum:'Nenhum', baixo:'Baixo', medio:'Médio', alto:'Alto', critico:'Crítico' };
const fdSection = (title, inner, icn='') => inner ? `<div class="fd-section"><h3 class="fd-h">${icn?icon(icn):''}${esc(title)}</h3>${inner}</div>` : '';

function councilPanel(c){
  if(!c) return '';
  const aprovado = !!c.aprovado;
  const sevFinal = String(c.severidade_final||'').toLowerCase();
  const stats = `<div class="report-stats fd-council-stats">
    <div><strong>${c.cadeiras_ok ?? 0}/5</strong><span>Cadeiras a favor</span></div>
    <div><strong>${esc(severity[sevFinal] || c.severidade_final || '—')}</strong><span>Severidade corp.</span></div>
    <div><strong>${esc(cap(c.confianca_final))}</strong><span>Confiança</span></div>
    <div><strong>${esc(_RISCO[c.risco_corporativo] || c.risco_corporativo || '—')}</strong><span>Risco corp.</span></div></div>`;
  const flags = [
    c.lgpd_dado_pessoal ? `<span class="fd-flag lgpd">LGPD · dado pessoal</span>` : '',
    ...(c.cia_pilares || []).map(p => `<span class="fd-flag cia">${esc(cap(p))}</span>`)
  ].filter(Boolean).join('');
  const vetos = (c.motivos_veto && c.motivos_veto.length)
    ? `<div class="fd-veto"><strong>Motivos de veto</strong><ul class="md-ul">${c.motivos_veto.map(v => `<li>${esc(typeof v==='string'?v:(v.motivo||v.motivo_veto||JSON.stringify(v)))}</li>`).join('')}</ul></div>` : '';
  const seats = (c.pareceres || []).map(p => `<div class="fd-seat ${p.veto?'veto':(p.ok?'ok':'')}">
    <div class="fd-seat-head"><strong>${esc(p.nome || p.cadeira || 'Cadeira')}</strong><span class="fd-seat-mark">${p.veto?'VETO':(p.ok?'OK':'—')}</span></div>
    ${p.parecer?`<p>${esc(p.parecer)}</p>`:''}
    <small>Severidade: ${esc(p.severidade_sugerida||'—')} · Confiança: ${esc(p.confianca||'—')} · Risco: ${esc(_RISCO[p.risco]||p.risco||'—')}${p.motivo_veto?` · Veto: ${esc(p.motivo_veto)}`:''}</small></div>`).join('');
  return `<div class="fd-section fd-council">
    <h3 class="fd-h">${icon('shield')}Parecer do Conselho<span class="fd-verdict ${aprovado?'ok':'veto'}">${aprovado?'APROVADO':'VETADO'}</span></h3>
    ${stats}
    ${flags?`<div class="fd-flags">${flags}</div>`:''}
    ${vetos}
    ${seats?`<div class="fd-seats">${seats}</div>`:''}</div>`;
}

function findingBody(f, report){
  const steps = Array.isArray(f.steps) ? f.steps : (f.steps ? [f.steps] : []);
  const mitre = (f.mitre || []).map(m => `<span class="fd-flag mitre">${esc(m.id||'')}${m.name?` · ${esc(m.name)}`:''}${m.tactic?` <em>(${esc(m.tactic)})</em>`:''}</span>`).join('');
  const poc = f.repro_curl ? `<div class="fd-poc"><div class="fd-poc-bar"><span>${icon('terminal')}PoC · curl</span><button class="button button-small" data-action="copy-curl">${icon('terminal')} Copiar</button></div><pre class="md-pre"><code>${esc(f.repro_curl)}</code></pre>${f.report_path?`<small class="muted">Relatório: ${esc(f.report_path)}</small>`:''}</div>` : '';
  return `
    ${f.url?`<div class="fd-url">${icon('radar')}<code>${esc(f.url)}</code></div>`:''}
    ${fdSection('Resumo', f.summary?`<p>${esc(f.summary)}</p>`:'')}
    ${fdSection('Impacto', f.impact?`<p>${esc(f.impact)}</p>`:'')}
    ${fdSection('Passos de reprodução', steps.length?`<ol class="fd-steps">${steps.map(s=>`<li>${esc(s)}</li>`).join('')}</ol>`:'')}
    ${fdSection('Prova de conceito', poc)}
    ${f.shell_obtained?fdSection('Shell obtido no alvo', `<p>${esc(f.shell_howto||'Execução de comando confirmada no alvo.')}</p>`):''}
    ${fdSection('Verificação adversarial', f.review?`<p>${esc(f.review)}</p>`:'')}
    ${councilPanel(f.council)}
    ${fdSection('MITRE ATT&CK', mitre?`<div class="fd-flags">${mitre}</div>`:'')}
    ${report?`<details class="fd-report"><summary>Relatório completo (report.md)</summary><div class="report-md">${md(report)}</div></details>`:(f.summary||f.evidence_marker)?'':`<p class="muted">Sem detalhes adicionais. Evidência: ${esc(f.evidence_marker||'—')}</p>`}`;
}

async function openFindingDrawer(id){
  const layer=$('#modal-layer');
  layer.innerHTML=`<div class="modal-backdrop" data-action="dismiss-modal"><section class="modal finding-modal" role="dialog" aria-modal="true" aria-label="Detalhe do achado" style="max-width:900px;width:94vw;text-align:left"><div class="modal-head"><div><div class="eyebrow">${esc(id)}</div><h2>Carregando achado…</h2></div><button class="modal-close" data-action="close-modal" aria-label="Fechar">${icon('close')}</button></div><div class="finding-modal-body" style="max-height:72vh;overflow:auto"><div class="loading-bar"></div></div></section></div>`;
  layer.setAttribute('aria-hidden','false');
  const res=await api.getFinding(id);
  const body=$('.finding-modal-body'); const head=$('.finding-modal .modal-head');
  if(!res||!res.ok){
    if(head)head.innerHTML=`<div><div class="eyebrow">${esc(id)}</div><h2>Não foi possível carregar</h2></div><button class="modal-close" data-action="close-modal" aria-label="Fechar">${icon('close')}</button>`;
    if(body)body.innerHTML=`<p>${esc((res&&res.error)||'Não foi possível carregar o achado.')}</p>`;
    return;
  }
  const f=res.finding||{}; lastCurl=f.repro_curl||'';
  const sev=String(f.severity||'info').toLowerCase();
  const council=f.council||{};
  const tag=(t)=>`<span class="status-pill">${esc(t)}</span>`;
  const hasCouncil=council&&Object.keys(council).length;
  const verdict=hasCouncil?`<span class="fd-verdict ${council.aprovado?'ok':'veto'}">Conselho: ${council.aprovado?'APROVADO':'VETADO'} · ${council.cadeiras_ok??0}/5</span>`:'';
  if(head)head.innerHTML=`<div><div class="eyebrow">${esc(f.id||id)}${f.vuln_class?` · ${esc(f.vuln_class)}`:''}</div><h2>${esc(f.title||'Achado')}</h2><div class="finding-modal-tags" style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px"><span class="severity-pill ${sev}">${severity[sev]||sev}</span>${f.cvss?tag('CVSS '+f.cvss):''}${f.confidence?tag('Confiança '+cap(f.confidence)):''}${verdict}</div></div><button class="modal-close" data-action="close-modal" aria-label="Fechar">${icon('close')}</button>`;
  const report=res.report||'';
  body.innerHTML=`<div class="fd-body">${findingBody(f, report)}</div>`;
}

let activeProfileTrigger = null;

function closeProfileMenu({ restoreFocus = false } = {}) {
  const menu = $('#profile-menu');
  if (!menu || menu.hidden) return;
  menu.hidden = true;
  $$('.profile-menu-trigger').forEach(trigger => trigger.setAttribute('aria-expanded', 'false'));
  if (restoreFocus && activeProfileTrigger) activeProfileTrigger.focus();
  activeProfileTrigger = null;
}

function openProfileMenu(trigger, { focusItem = false } = {}) {
  const menu = $('#profile-menu');
  if (!menu || $('#logout-link').hidden) return;
  activeProfileTrigger = trigger;
  $$('.profile-menu-trigger').forEach(item => item.setAttribute('aria-expanded', String(item === trigger)));
  menu.hidden = false;
  const rect = trigger.getBoundingClientRect();
  const menuRect = menu.getBoundingClientRect();
  const left = Math.min(window.innerWidth - menuRect.width - 12, Math.max(12, rect.right - menuRect.width));
  const preferredTop = trigger.id === 'top-profile-trigger' ? rect.bottom + 8 : rect.top - menuRect.height - 8;
  const top = Math.min(window.innerHeight - menuRect.height - 12, Math.max(12, preferredTop));
  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
  if (focusItem) $('#logout-link').focus();
}

function toggleProfileMenu(trigger, options = {}) {
  const menu = $('#profile-menu');
  if (!menu.hidden && activeProfileTrigger === trigger) closeProfileMenu({ restoreFocus: options.focusItem });
  else openProfileMenu(trigger, options);
}

async function renderIdentity() {
  try {
    // authenticatedFetch cobre os dois modos (Bearer no proxy, cookie no
    // viewer embutido) e já reinicia o login sozinha se vier 401.
    const response = await authenticatedFetch(new URL('api/session', document.baseURI), { headers: { Accept: 'application/json' }, cache: 'no-store' });
    if (!response.ok) return;
    const session = await response.json();
    // No modo proxy, o servidor só vê o `sub` (header X-Operator vindo do
    // JWT authorizer). Nome/e-mail vêm do ID token validado no browser
    // durante o login (getIdentity) — nunca do access token enviado à API.
    const user = { ...(session.user || {}), ...(getIdentity() || {}) };
    const email = user.email || '';
    const username = user['cognito:username'] || '';
    const displayName = user.name || (email ? email.split('@')[0] : username) || 'Conta autenticada';
    $('#profile-name').textContent = displayName;
    $('#profile-role').textContent = email || username || 'Usuário autenticado';
    $('#profile-role').title = email || username;
    $('#profile-menu-name').textContent = displayName;
    $('#profile-menu-email').textContent = email || username || 'Usuário autenticado';
    const initials = String(displayName).split(/\s+|@/).filter(Boolean).slice(0, 2).map(part => part[0]).join('').toUpperCase();
    $('#profile-avatar').textContent = initials;
    $('#profile-menu-avatar').textContent = initials;
    $('#top-profile-trigger').textContent = initials;
    $('#logout-link').hidden = !session.enabled;
  } catch { /* Keep the dashboard usable during a transient local connection failure. */ }
}

async function updateAndRender(message, route=location.hash.replace(/^#/, '')||'campaign') {
  closeModal();
  try { workspace=await api.getWorkspace(); location.hash=`#${route}`; if(location.hash===`#${route}`) { await renderRoute(); } if(message)toast(message); }
  catch(error){toast(friendlyError(error));}
}

document.addEventListener('click',async event=>{
  const profileTrigger=event.target.closest('[data-action="toggle-profile-menu"]');
  if(profileTrigger){event.preventDefault();toggleProfileMenu(profileTrigger);return;}
  if(!event.target.closest('#profile-menu'))closeProfileMenu();
  const target=event.target.closest('button,a,[data-action]');
  if(!target)return;
  const action=target.dataset.action;
  if(target.matches('[data-page]')){event.preventDefault();location.hash=`#${target.dataset.page}`;return;}
  if(target.matches('[data-finding-filter]')){findingFilter=target.dataset.findingFilter;content.innerHTML=findingsView();return;}
  if(target.matches('[data-audit-filter]')){auditFilter=target.dataset.auditFilter;content.innerHTML=auditView();return;}
  if(target.matches('[data-terminal-filter]')){terminalFilter=target.dataset.terminalFilter;refreshTerminal();return;}
  if(target.matches('[data-report-mode]')){reportMode=target.dataset.reportMode;content.innerHTML=reportsView();return;}
  if(action==='emergency'){event.preventDefault();openEmergencyDialog();}
  else if(action==='confirm-emergency'){await api.emergencyStop();await updateAndRender('Campanha interrompida; ações pendentes canceladas.','campaign');}
  else if(action==='logout'){event.preventDefault();closeProfileMenu();await logout();}
  else if(action==='close-modal'){closeModal();}
  else if(action==='dismiss-modal'&&event.target.classList.contains('modal-backdrop'))closeModal();
  else if(action==='save-target'){
    const targetField=$('#campaign-target');
    if(!targetField?.reportValidity())return;
    const targetValue=targetField.value.trim();
    if(!targetValue)return;
    try{await api.updateTarget(targetValue);await updateAndRender('Alvo salvo no escopo.','campaign');}catch(error){toast(friendlyError(error));}
  }
  else if(action==='resolve-approval'){
    try{await api.resolveApproval(target.dataset.id,target.dataset.decision);await updateAndRender(target.dataset.decision==='approved'?'Decisão aprovada e registrada.':'Solicitação recusada e bloqueada.',location.hash==='#terminal'?'terminal':'approvals');}catch(error){toast(friendlyError(error));}
  }
  else if(action==='request-approval'){
    try{await api.requestApproval(target.dataset.id);await updateAndRender('Solicitação enviada para aprovação humana.','approvals');}catch(error){toast(friendlyError(error));}
  }
  else if(action==='export'){downloadSnapshot();toast('Snapshot JSON exportado.');}
  else if(action==='go-audit'){location.hash='#audit';}
  else if(action==='open-campaign'){try{await api.selectCampaign(target.dataset.campaign);}catch(error){toast(friendlyError(error));}location.hash='#terminal';}
  else if(action==='open-finding'){event.preventDefault();await openFindingDrawer(target.dataset.id);}
  else if(action==='copy-curl'){try{await navigator.clipboard.writeText(lastCurl||'');toast('Curl copiado.');}catch{toast('Não foi possível copiar.');}}
  else if(action==='retry')await renderRoute();
  else if(action==='mobile-close'){$('#sidebar').classList.remove('open');$('.mobile-menu-backdrop').classList.remove('show');}
  else if(target.id==='mobile-menu'){$('#sidebar').classList.add('open');$('.mobile-menu-backdrop').classList.add('show');}
});

document.addEventListener('submit',async event=>{
  if(event.target.id!=='campaign-form')return;
  event.preventDefault();
  const form=new FormData(event.target);
  try{
    workspace=await api.startCampaign({target:String(form.get('target')).trim(),authorized:!!form.get('authorized'),workers:Number(form.get('workers'))||6,scope:String(form.get('scope')||'').trim()});
    await renderRoute();toast('Campanha iniciada.');
  }catch(error){toast(friendlyError(error));}
});
document.addEventListener('keydown',event=>{
  const trigger=event.target.closest?.('[data-action="toggle-profile-menu"]');
  if(trigger&&event.key==='ArrowDown'){event.preventDefault();openProfileMenu(trigger,{focusItem:true});return;}
  if(event.key==='Escape'){closeProfileMenu({restoreFocus:true});closeModal();}
});
window.addEventListener('resize',()=>closeProfileMenu());
window.addEventListener('hashchange',renderRoute);

setInterval(async()=>{
  const here=location.hash||'#campaign';
  if(here==='#fleet'){content.innerHTML=await fleetView();return;}
  if(!workspace||workspace.campaign.status!=='running')return;
  try {
    workspace=await api.advanceCampaign();
    if(here==='#campaign')content.innerHTML=campaignView();
    else if(here==='#terminal')refreshTerminal();
  } catch(error) {
    if(error.message!=='AUTH_REQUIRED')toast(error.message);
  }
},5000);

renderIdentity();
renderRoute();
