# FOSC/TS — Interface Web (design)

**Ferramenta Ofensiva de Segurança Cibernética para Tecnologia e Serviços**, a
interface visual que será deployada no Hackathon **Hacka/TS (Banco do Brasil / BBTS)**.

Esta pasta é o **mesmo painel do FOSC** (`fosc/web/`), já com a marca FOSC/TS e a
paleta BB, mais um **modo demo** que roda sem backend. É daqui que a equipe de
design evolui o visual.

> O **CLI do agente continua funcionando normalmente** e não depende desta pasta.
> Nada aqui mexe em `fosc/` (a lógica do agente). Podem mexer à vontade.

## Como abrir

```bash
cd web && python3 -m http.server 8080
# abra http://localhost:8080
```

Abre em **modo demo**, com dados de exemplo que se mexem sozinhos: feed ao vivo,
tarefas em execução, achados e chat. A barra superior mostra o selo "Demo".

## Telas

| Tela | Onde | O que mostra |
|------|------|--------------|
| **Caçadas** | `#/` | alvos na lateral, KPIs, atividade ao vivo, tarefas em voo, ritmo, achados confirmados, tabela de resultados; clique num achado para abrir o drawer (resumo, relatório, log) |
| **Conversa** | `#/chat` | chat com o agente de IA, com ou sem alvo em contexto e escolha de modelo; mostra o que o agente está executando enquanto responde |
| **Aprendizado** | `#/knowledge` | lições entre caçadas, taxa de acerto, playbook |
| **Configurações** | `#/settings` | Telegram (alertas e aprovação remota), som |
| **Nova caçada** | botão azul ou tecla `n` | modal com alvo, escopo, workers e opções |

## Paleta e princípios visuais (Banco do Brasil / BBTS)

Os tokens ficam no topo de **`css/app.css`**, no bloco `:root`. Quando eles mudam, o
painel inteiro acompanha.

| Token | Cor | Uso |
|-------|-----|-----|
| `--bb-amarelo` | `#FCE300` | **superfície de marca**: a barra superior |
| `--bb-azul` | `#2E8BDA` | azul claro: progresso, gráfico, foco, abas, links |
| `--bb-azul-acao` | `#1F6FB5` | botões primários (azul claro escurecido para dar contraste com o texto branco) |
| `--bb-azul-suave` | `#EAF3FC` | itens selecionados (menu, filtro, bolha do usuário) |
| `--bb-branco` | `#FFFFFF` | fundo e cartões |
| `--text` | `#0A2A55` | texto azul-escuro |

**Regras (para não virar cara de template genérico):**
- Fundo branco e cartões com borda fina e sombra mínima. Nada de degradê, brilho ou glassmorphism.
- Amarelo é marca (barra superior), não decoração. Nunca usar como cor de texto sobre branco.
- Azul claro indica o que é clicável ou está selecionado.
- Títulos em fonte normal. Monoespaçada só em URL, comando e código.
- Rótulos em português e com só a inicial maiúscula ("Endpoints testados"), sem CAIXA ALTA espaçada.
- Animação só quando informa algo (abrir o painel lateral), nunca em loop.
- Vermelho só com sentido semântico: Parar, severidade crítica, erro.

## Estrutura

```
web/
├── index.html      # todas as telas (caçadas, conversa, aprendizado, config, drawer, modal)
├── css/app.css     # ← tokens da paleta no topo + todos os estilos
├── js/app.js       # lógica do painel (igual à do fosc/web, só recolorida)
├── js/mock.js      # MODO DEMO: dados de exemplo que imitam a API do agente
└── assets/logo.svg # marca FOSC/TS provisória (trocar pelo logo final)
```

## Ideias para evoluir

- [ ] Logo definitivo, tipografia e ícones no tom BB.
- [ ] Tela de **Aprovações** (human-in-the-loop) e de **Trilha de auditoria** (selo íntegra ✓ / violada ✗, `scope_block`).
- [ ] Botão de **halt de emergência** bem visível.
- [ ] Responsivo/mobile, microinterações.

## Integração com o agente

O `js/mock.js` imita **as mesmas rotas e os mesmos campos** da API real
(`fosc/webview.py`: `/api/overview`, `/api/state`, `/api/events` (SSE), `/api/chat`,
`/api/finding`, `/api/log`, `/api/knowledge`, `/api/config`). Abrir com `?live`
desliga o mock e chama a API de verdade. Falta um passo, do lado do agente: hoje o
viewer (`fosc -v`) serve `fosc/web/`, e precisa passar a servir esta pasta. Mantendo
os nomes dos campos, o plugue é direto.
