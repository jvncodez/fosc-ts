"""Agent plan — what gets registered BEFORE each step (challenge #3).

The challenge requires that, before every step, the agent records: hypothesis,
action, expected result and stop condition. We build this deterministically from
the ranked item and the run's limits (no extra model call, no drift): the plan is
written to the audit ledger immediately before the model is invoked, so the trail
always shows intent-before-action, and the stop condition is explicit and bounded.
"""


def hunt_plan(item: dict, classes: list[str], *, budget: float, timeout: int,
              scope_label: str) -> dict:
    url = item.get("url") or item.get("target") or "?"
    cls = ", ".join(classes[:4]) if classes else "classes web OWASP priorizadas"
    cap = f"orçamento ${budget:g}" if budget else "sem teto de custo"
    return {
        "step": "active-test",
        "target": url,
        "hypothesis": f"{url} pode estar vulnerável a: {cls}.",
        "action": f"Teste ativo autorizado de [{cls}] em {url}, restrito ao escopo {scope_label}.",
        "expected_result": ("Confirmar ou refutar com PoC reproduzível e marcador de "
                            "evidência; só vira 'confirmed' com impacto demonstrado e "
                            "revisão adversarial independente."),
        "stop_condition": (f"PARAR ao: confirmar achado (seguindo a cadeia até o teto de "
                           f"impacto), esgotar as classes, atingir {cap}, estourar timeout "
                           f"({timeout}s), sair do escopo, ou receber HALT/STOP."),
    }


def privesc_plan(finding: dict, *, pass_no: int, budget: float, timeout: int,
                 scope_label: str) -> dict:
    base = finding.get("url") or finding.get("vuln_class") or "acesso obtido"
    return {
        "step": f"privesc-pass-{pass_no}",
        "target": base,
        "hypothesis": (f"O acesso obtido ({finding.get('vuln_class', '?')}) pode ser "
                       f"escalado a privilégio maior no host/serviço."),
        "action": (f"Enumeração + escalonamento autorizado a partir de {base}, dentro do "
                   f"escopo {scope_label} (passe {pass_no})."),
        "expected_result": "Comprovar (ou descartar) root/privilégio elevado com evidência.",
        "stop_condition": (f"PARAR ao: obter root, esgotar vetores do passe, atingir "
                           f"orçamento ${budget:g}, timeout ({timeout}s) ou HALT/STOP."),
    }
