"""O Conselho — 5 revisores corporativos entre o achado confirmado e o orquestrador.

Depois que a verificação adversarial (Opus) confirma um achado, ele ainda não é
aceito: passa por um conselho de 5 cadeiras, cada uma uma sessão de modelo isolada
(camada fosc/models), rodando em paralelo. Cada cadeira dá um parecer EM PORTUGUÊS,
uma sugestão de severidade e de confiança, e pode VETAR. A decisão é agregada de
forma determinística (decidir()), podendo rebaixar, suprimir ou reclassificar o
achado — julgamento de nível corporativo.

Cadeiras:
  lgpd        — dado pessoal exposto, categorias, titulares, bases legais (LGPD).
  cia         — qual pilar da tríade (Confidencialidade/Integridade/Disponibilidade).
  usuario     — experiência e impacto concreto no usuário/titular afetado.
  corporativo — risco financeiro, reputacional e regulatório para a organização.
  governanca  — escopo autorizado, evidência reproduzível e os 8 requisitos do MVP.

Veto é soberano: se qualquer cadeira veta (fora de escopo, sem evidência, não
reproduzível), o achado NÃO vira confirmado. Sem veto, a severidade final é a
reclassificação corporativa e a confiança é a mais conservadora entre as cadeiras.
"""
import json
from concurrent.futures import ThreadPoolExecutor

from . import config, models

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEV_BY_RANK = {v: k for k, v in _SEV_RANK.items()}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
_CONF_BY_RANK = {v: k for k, v in _CONF_RANK.items()}

SEATS = [
    {"key": "lgpd", "nome": "LGPD / Privacidade",
     "foco": "Avalie exclusivamente a ótica de proteção de dados (LGPD). O achado expõe, "
             "altera ou permite acesso a DADO PESSOAL ou dado pessoal SENSÍVEL? Quais categorias "
             "(identificação, contato, financeiro, credenciais, localização, saúde)? Quantos "
             "titulares potencialmente afetados? Há violação de princípios (finalidade, "
             "necessidade, segurança — art. 6º) que exigiria comunicação à ANPD/titulares (art. 48)? "
             "Preencha lgpd_dado_pessoal e, no parecer, as categorias e o dever de notificação."},
    {"key": "cia", "nome": "Tríade CIA",
     "foco": "Avalie pela tríade da segurança da informação. Quais pilares o achado quebra: "
             "Confidencialidade (vazamento/leitura indevida), Integridade (escrita/adulteração/forja) "
             "e/ou Disponibilidade (negação/parada)? Liste em cia_pilares usando exatamente "
             "'confidencialidade', 'integridade', 'disponibilidade'. Explique a cadeia técnica no parecer."},
    {"key": "usuario", "nome": "Experiência e impacto no usuário",
     "foco": "Avalie o impacto CONCRETO no usuário final / titular. O que acontece com uma pessoa real "
             "se isso for explorado (conta tomada, dados expostos, prejuízo financeiro, perda de confiança)? "
             "A exploração é silenciosa para a vítima? Descreva o pior cenário plausível do ponto de vista "
             "de quem usa o sistema, sem jargão."},
    {"key": "corporativo", "nome": "Risco corporativo",
     "foco": "Julgue em nível CORPORATIVO/executivo. Dimensione risco financeiro (fraude, multa), "
             "reputacional (exposição pública, imprensa) e regulatório (LGPD/ANPD, BACEN, auditoria). "
             "Esta cadeira é a autoridade sobre a SEVERIDADE de negócio: sua 'severidade_sugerida' é a "
             "reclassificação corporativa do achado. Seja rigoroso: nem tudo que é tecnicamente possível "
             "é materialmente relevante."},
    {"key": "governanca", "nome": "Governança e escopo",
     "foco": "Guardião da governança. O achado está DENTRO do escopo autorizado? Há evidência "
             "REPRODUZÍVEL (passos + comando + marcador de evidência)? O relatório atende aos requisitos "
             "do MVP (severidade, confiança, impacto, evidência, passos de reprodução)? VETE se estiver "
             "fora de escopo, sem evidência reproduzível, ou se for apenas comportamento padrão sem impacto."},
]
SEAT_KEYS = [s["key"] for s in SEATS]

COUNCIL_SCHEMA = {
    "type": "object",
    "properties": {
        "parecer": {"type": "string"},                       # em português
        "risco": {"type": "string", "enum": ["nenhum", "baixo", "medio", "alto", "critico"]},
        "severidade_sugerida": {"type": ["string", "null"], "enum": config.SEVERITIES + [None]},
        "confianca": {"type": ["string", "null"], "enum": ["alta", "media", "baixa", None]},
        "veto": {"type": "boolean"},
        "motivo_veto": {"type": ["string", "null"]},
        "lgpd_dado_pessoal": {"type": ["boolean", "null"]},
        "cia_pilares": {"type": ["array", "null"], "items": {"type": "string"}},
    },
    "required": ["parecer", "risco", "veto"],
}

_CONF_PT = {"alta": "high", "media": "medium", "baixa": "low"}


def _system(seat: dict) -> str:
    return (f"Você é a cadeira '{seat['nome']}' do Conselho de Revisão do FOSC/TS, uma ferramenta "
            f"ofensiva de segurança usada pelo Banco do Brasil Tecnologia e Serviços (BBTS). Revisa um "
            f"achado JÁ confirmado tecnicamente, apenas pela sua ótica, com rigor corporativo e sem "
            f"exagerar impacto. Responda SEMPRE em português do Brasil, de forma objetiva.\n\n"
            f"{seat['foco']}\n\n"
            f"Dê um parecer curto (2-5 frases), um nível de risco, uma severidade sugerida (ou null se "
            f"não for sua alçada), uma confiança e, se for o caso, um veto com motivo. Vete apenas por "
            f"fora de escopo, ausência de evidência reproduzível, ou irrelevância material — nunca por "
            f"discordar da severidade (para isso, ajuste 'severidade_sugerida').")


def _prompt(finding: dict, item: dict, scope_note: str) -> str:
    campos = {k: finding.get(k) for k in ("vuln_class", "severity", "cvss", "confidence",
                                          "title", "summary", "impact", "steps", "repro_curl",
                                          "evidence_marker", "review")}
    return (f"Escopo autorizado: {scope_note}\n"
            f"Endpoint: {item.get('url')} (padrão {item.get('pattern')})\n\n"
            f"Achado confirmado (revise só pela sua ótica):\n"
            f"{json.dumps(campos, ensure_ascii=False, indent=2)}\n")


def _run_seat(seat: dict, finding: dict, item: dict, scope_note: str, task_dir, timeout: int) -> dict:
    run = models.run(
        "council",
        _prompt(finding, item, scope_note),
        cwd=task_dir / f"council_{seat['key']}",
        timeout=timeout,
        stream_path=task_dir / f"council_{seat['key']}.stream.jsonl",
        system_prompt=_system(seat),
        schema=COUNCIL_SCHEMA,
        allow_tools=False,            # juízo sobre o achado, não re-exploração
        effort=config.COUNCIL_EFFORT,
    )
    out = run.get("output") or {}
    return {
        "cadeira": seat["key"], "nome": seat["nome"],
        "ok": run["status"] == "ok",
        "parecer": out.get("parecer") or (run.get("error") or "sem parecer"),
        "risco": out.get("risco") or "nenhum",
        "severidade_sugerida": out.get("severidade_sugerida"),
        "confianca": out.get("confianca"),
        "veto": bool(out.get("veto")) if run["status"] == "ok" else False,
        "motivo_veto": out.get("motivo_veto"),
        "lgpd_dado_pessoal": out.get("lgpd_dado_pessoal"),
        "cia_pilares": out.get("cia_pilares"),
        "cost": run.get("cost", 0),
    }


def decidir(pareceres: list[dict], severidade_atual: str, confianca_atual: str) -> dict:
    """Agregação DETERMINÍSTICA dos 5 pareceres. Pura: sem rede, testável.

    - Veto de qualquer cadeira (entre as que responderam) => aprovado=False.
    - Severidade final = reclassificação da cadeira 'corporativo'; na ausência,
      a mais alta sugerida; limitada por quem respondeu.
    - Confiança final = a mais conservadora (menor) entre as sugeridas.
    """
    respondidas = [p for p in pareceres if p.get("ok")]
    vetos = [p for p in respondidas if p.get("veto")]
    aprovado = not vetos

    # severidade: cadeira corporativa decide; senão, a mais severa sugerida
    corp = next((p for p in respondidas if p["cadeira"] == "corporativo"), None)
    sev = None
    if corp and corp.get("severidade_sugerida"):
        sev = corp["severidade_sugerida"]
    else:
        sugeridas = [p["severidade_sugerida"] for p in respondidas if p.get("severidade_sugerida")]
        if sugeridas:
            sev = _SEV_BY_RANK[max(_SEV_RANK[s] for s in sugeridas)]
    severidade_final = sev or severidade_atual

    # confiança: a menor entre as sugeridas (conservador)
    confs = [_CONF_PT.get(p["confianca"]) for p in respondidas if p.get("confianca")]
    confs = [c for c in confs if c in _CONF_RANK]
    if confs:
        confianca_final = _CONF_BY_RANK[min(_CONF_RANK[c] for c in confs)]
    else:
        confianca_final = confianca_atual or "medium"

    lgpd = any(p.get("lgpd_dado_pessoal") for p in respondidas)
    pilares = sorted({x for p in respondidas for x in (p.get("cia_pilares") or [])})
    risco_max = max((p.get("risco") for p in respondidas),
                    key=lambda r: ["nenhum", "baixo", "medio", "alto", "critico"].index(r)
                    if r in ("nenhum", "baixo", "medio", "alto", "critico") else 0, default="nenhum")

    return {
        "aprovado": aprovado,
        "severidade_final": severidade_final,
        "confianca_final": confianca_final,
        "motivos_veto": [{"cadeira": v["cadeira"], "motivo": v.get("motivo_veto") or v.get("parecer")}
                         for v in vetos],
        "lgpd_dado_pessoal": lgpd,
        "cia_pilares": pilares,
        "risco_corporativo": risco_max,
        "pareceres": pareceres,
        "custo": round(sum(p.get("cost", 0) for p in pareceres), 4),
        "cadeiras_ok": len(respondidas),
    }


def revisar(finding: dict, item: dict, scope_note: str, task_dir, *, on_activity=None,
            timeout: int = None) -> dict:
    """Roda as 5 cadeiras em paralelo e devolve a decisão agregada."""
    timeout = timeout or config.COUNCIL_TIMEOUT
    if on_activity:
        on_activity("conselho: 5 cadeiras revisando o achado")
    with ThreadPoolExecutor(max_workers=len(SEATS)) as ex:
        pareceres = list(ex.map(
            lambda s: _run_seat(s, finding, item, scope_note, task_dir, timeout), SEATS))
    decisao = decidir(pareceres, finding.get("severity"), finding.get("confidence"))
    if on_activity:
        if decisao["aprovado"]:
            on_activity(f"conselho: APROVADO · severidade {decisao['severidade_final']} · "
                        f"risco corporativo {decisao['risco_corporativo']}")
        else:
            on_activity(f"conselho: VETADO por {', '.join(v['cadeira'] for v in decisao['motivos_veto'])}")
    return decisao
