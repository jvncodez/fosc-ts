# FOSC/TS — Interface Web (design)

**Ferramenta Ofensiva de Segurança Cibernética para Tecnologia e Serviços** — a
interface visual que será deployada. Hackathon **Hacka/TS — Banco do Brasil (BBTS)**.

Este é um **scaffold mínimo** para a equipe de design evoluir. Ele renderiza sozinho
(sem backend, sem build): dá pra **abrir o `index.html` direto no navegador**.

> O **CLI do agente continua funcionando normalmente** e é independente desta pasta.
> Nada aqui mexe no `fosc/` (a lógica do agente). Trabalhem à vontade.

## Paleta (Banco do Brasil / BBTS)

Amarelo · Azul claro · Branco. Tudo definido em **`css/tokens.css`** — é O arquivo
para ajustar a identidade. Mudou lá, a interface inteira acompanha.

| Token | Cor | Uso |
|-------|-----|-----|
| `--bb-amarelo` | `#FAE100` | acento/realce, borda do topo, selos |
| `--bb-azul` | `#2E8BDA` | cor primária (azul claro) |
| `--bb-azul-escuro` | `#0A3D7A` | texto/títulos, contraste |
| `--bb-branco` | `#FFFFFF` | superfícies/cartões |

> Acessibilidade: amarelo e branco têm pouco contraste entre si — use **texto azul
> escuro** sobre amarelo/branco (já é o padrão nos tokens).

## Estrutura

```
web/
├── index.html        # telas (Console, Achados, Aprovações, Trilha)
├── css/
│   ├── tokens.css    # ← PALETA e tokens (mexer aqui primeiro)
│   └── app.css       # estilos base dos componentes
├── js/
│   ├── data.js       # dados de EXEMPLO (trocar/editar à vontade)
│   └── app.js        # render + navegação por abas
└── assets/
    └── logo.svg      # marca placeholder (trocar)
```

## Como pré-visualizar

- **Simples:** dê duplo-clique em `index.html`.
- **Com servidor local** (recomendado, igual ao deploy):
  ```bash
  cd web && python3 -m http.server 8080
  # abra http://localhost:8080
  ```

## O que já tem (e o que melhorar)

As 4 telas espelham os critérios do desafio (Console da campanha, Achados confirmados,
Aprovação humana, Trilha de auditoria). Estão **propositalmente cruas** — pontos para
evoluir:

- [ ] Identidade: logo definitivo, tipografia, ícones, tom BB.
- [ ] Console: controles de campanha (iniciar/pausar/parar/**halt de emergência**).
- [ ] Achados: filtros por severidade, drawer de detalhe + PoC + relatório.
- [ ] Aprovações: fluxo de aprovar/negar (hoje os botões são protótipo).
- [ ] Trilha: destaque visual do selo **íntegra ✓ / VIOLADA ✗** e dos `scope_block`.
- [ ] Responsivo/mobile, dark mode (opcional), microinterações.

## Integração com o agente (depois)

Hoje a tela lê `js/data.js` (mock). Na integração, os mesmos campos virão da API do
agente (o viewer `fosc/webview.py` já serve o estado real: snapshot da campanha,
achados, aprovações e a trilha de auditoria). O formato do mock foi desenhado para
casar com esses dados — manter os mesmos nomes de campo facilita o plugue.
