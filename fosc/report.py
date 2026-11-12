"""Per-finding report.md in a bug bounty submission shape."""
import shutil
import time
from pathlib import Path

from . import mitre, pocfmt


def write_report(run_dir: Path, fid: str, target: str, item: dict, finding: dict,
                 review: dict, task_dir: Path) -> str:
    out_dir = run_dir / "pocs" / fid
    out_dir.mkdir(parents=True, exist_ok=True)

    poc = finding.get("poc_path")
    if poc:
        src = (task_dir / poc).resolve()
        if task_dir.resolve() in src.parents:
            try:
                if src.is_file():
                    shutil.copy2(src, out_dir / src.name)
                elif src.is_dir():
                    shutil.copytree(src, out_dir / src.name, dirs_exist_ok=True)
            except OSError:
                pass

    # finding já incorpora o review E a reclassificação do Conselho — prefira-o.
    sev = (finding.get("severity") or review.get("severity") or "unrated").capitalize()
    cvss = finding.get("cvss") if finding.get("cvss") is not None else review.get("cvss")
    cls = finding.get("vuln_class") or review.get("vuln_class") or "Vulnerability"
    title = finding.get("title") or f"{cls} em {item.get('path') or item['url']}"
    steps = finding.get("steps") or []
    md = [
        f"# {title}",
        "",
        f"- **Alvo:** {target}",
        f"- **Endpoint:** `{item['url']}`",
        f"- **Classe:** {cls}",
        f"- **Severidade:** {sev}" + (f" (CVSS {cvss})" if cvss is not None else ""),
        f"- **Confiança:** {(finding.get('confidence') or 'medium').capitalize()}",
        f"- **MITRE ATT&CK:** {_mitre_tags(finding, cls)}",
        f"- **Encontrado em:** {time.strftime('%d/%m/%Y %H:%M', time.localtime())}",
        "",
        "## Resumo",
        finding.get("summary") or "",
        "",
        "## Impacto",
        finding.get("impact") or "_a redigir_",
        "",
        "## Passos para reprodução",
        *(f"{i}. {s}" for i, s in enumerate(steps, 1)),
    ]
    if finding.get("repro_curl"):
        md += ["", *pocfmt.blocks(finding["repro_curl"])]
    if finding.get("evidence_marker"):
        md += ["", f"Evidência esperada na resposta: `{finding['evidence_marker']}`"]
    techs = finding.get("mitre") or mitre.techniques(cls)
    if techs:
        md += ["", "## MITRE ATT&CK",
               *(f"- **{t['id']}** {t['name']} _({t['tactic']})_" for t in techs)]
    md += ["", "## Revisão independente", review.get("reason") or "", ""]
    md += _council_section(finding.get("council"))
    (out_dir / "report.md").write_text("\n".join(md))
    return f"pocs/{fid}/report.md"


_RISCO_PT = {"nenhum": "Nenhum", "baixo": "Baixo", "medio": "Médio", "alto": "Alto", "critico": "Crítico"}


def _council_section(decisao: dict | None) -> list[str]:
    if not decisao:
        return []
    md = ["", "## Parecer do Conselho"]
    veredito = "APROVADO" if decisao.get("aprovado") else "VETADO"
    md.append(f"- **Veredito:** {veredito} ({decisao.get('cadeiras_ok', 0)}/5 cadeiras)")
    md.append(f"- **Severidade corporativa:** {(decisao.get('severidade_final') or '-').capitalize()}")
    md.append(f"- **Confiança:** {(decisao.get('confianca_final') or '-').capitalize()}")
    md.append(f"- **Risco corporativo:** {_RISCO_PT.get(decisao.get('risco_corporativo'), '-')}")
    if decisao.get("lgpd_dado_pessoal"):
        md.append("- **LGPD:** envolve dado pessoal — avaliar dever de comunicação (art. 48).")
    if decisao.get("cia_pilares"):
        md.append(f"- **Tríade CIA:** {', '.join(decisao['cia_pilares'])}")
    if decisao.get("motivos_veto"):
        md.append("- **Vetos:** " + "; ".join(f"{v['cadeira']} — {v['motivo']}"
                                               for v in decisao["motivos_veto"]))
    md.append("")
    for p in decisao.get("pareceres", []):
        if p.get("ok"):
            marca = " ⛔" if p.get("veto") else ""
            md.append(f"**{p['nome']}**{marca} — {p.get('parecer', '')}")
            md.append("")
    return md


def _mitre_tags(finding: dict, cls: str) -> str:
    techs = finding.get("mitre") or mitre.techniques(cls)
    return ", ".join(t["id"] for t in techs) or "—"


def write_executive_summary(run_dir: Path, target: str, scope_label: str, findings: list[dict],
                            cost: float, audit_status: str) -> str:
    """Campaign-level report (#7): executive summary + a technical index of every
    confirmed finding. Deterministic — no model call."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: order.get((f.get("severity") or "info").lower(), 9))
    sev_counts: dict[str, int] = {}
    for f in findings:
        s = (f.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    tally = ", ".join(f"{n} {s}" for s, n in sorted(sev_counts.items(), key=lambda kv: order.get(kv[0], 9))) or "nenhum"
    techs = sorted({t for f in findings for t in (f.get("mitre") and [x["id"] for x in f["mitre"]] or [])})

    md = [
        f"# Relatório da campanha — {target}",
        "",
        f"- **Escopo autorizado:** {scope_label}",
        f"- **Gerado:** {time.strftime('%Y-%m-%d %H:%M', time.localtime())}",
        f"- **Custo da campanha:** US$ {cost:.2f}",
        f"- **Trilha de auditoria:** {audit_status}",
        "",
        "## Resumo executivo",
        "",
        (f"A campanha autônoma confirmou **{len(findings)} vulnerabilidade(s)** "
         f"({tally}) no escopo autorizado ({scope_label}), cada uma validada por "
         f"revisão adversarial independente e com evidência reproduzível. Todo o "
         f"processo — plano, autorização, comandos e evidências — está registrado "
         f"na trilha de auditoria à prova de adulteração." if findings else
         "A campanha autônoma concluiu dentro do escopo autorizado sem confirmar "
         "vulnerabilidades. Todo o processo está registrado na trilha de auditoria."),
        "",
    ]
    if techs:
        md += [f"**Cobertura MITRE ATT&CK:** {', '.join(techs)}", ""]
    md += ["## Visão técnica — achados confirmados", ""]
    if findings:
        for f in findings:
            sev = (f.get("severity") or "info").capitalize()
            conf = (f.get("confidence") or "medium").capitalize()
            tags = ", ".join(x["id"] for x in (f.get("mitre") or [])) or "—"
            md += [f"### [{sev}] {f.get('vuln_class') or 'Vulnerability'} — `{f.get('url', '')}`",
                   f"- **Confiança:** {conf}  ·  **CVSS:** {f.get('cvss', '—')}  ·  **MITRE:** {tags}",
                   f"- {f.get('summary') or ''}",
                   (f"- **Relatório técnico:** `{f.get('report_path')}`" if f.get("report_path") else ""),
                   ""]
    else:
        md += ["_Nenhum achado confirmado._", ""]

    out = run_dir / "executive_summary.md"
    out.write_text("\n".join(x for x in md if x is not None))
    return str(out)
