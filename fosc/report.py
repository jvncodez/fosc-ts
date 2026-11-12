"""Per-finding report.md in a bug bounty submission shape."""
import shutil
import time
from pathlib import Path

from . import mitre


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

    sev = (review.get("severity") or finding.get("severity") or "unrated").capitalize()
    cvss = review.get("cvss") if review.get("cvss") is not None else finding.get("cvss")
    cls = review.get("vuln_class") or finding.get("vuln_class") or "Vulnerability"
    title = finding.get("title") or f"{cls} on {item.get('path') or item['url']}"
    steps = finding.get("steps") or []
    md = [
        f"# {title}",
        "",
        f"- **Target:** {target}",
        f"- **Endpoint:** `{item['url']}`",
        f"- **Class:** {cls}",
        f"- **Severity:** {sev}" + (f" (CVSS {cvss})" if cvss is not None else ""),
        f"- **Confidence:** {(finding.get('confidence') or 'medium').capitalize()}",
        f"- **MITRE ATT&CK:** {_mitre_tags(finding, cls)}",
        f"- **Found:** {time.strftime('%Y-%m-%d %H:%M', time.localtime())}",
        "",
        "## Summary",
        finding.get("summary") or "",
        "",
        "## Impact",
        finding.get("impact") or "_to be written_",
        "",
        "## Steps to reproduce",
        *(f"{i}. {s}" for i, s in enumerate(steps, 1)),
    ]
    if finding.get("repro_curl"):
        md += ["", "```bash", finding["repro_curl"], "```"]
    if finding.get("evidence_marker"):
        md += ["", f"Expected evidence in the response: `{finding['evidence_marker']}`"]
    techs = finding.get("mitre") or mitre.techniques(cls)
    if techs:
        md += ["", "## MITRE ATT&CK",
               *(f"- **{t['id']}** {t['name']} _({t['tactic']})_" for t in techs)]
    md += ["", "## Independent review", review.get("reason") or "", ""]
    (out_dir / "report.md").write_text("\n".join(md))
    return f"pocs/{fid}/report.md"


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
