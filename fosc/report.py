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
