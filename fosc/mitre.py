"""MITRE ATT&CK mapping — tag each finding with adversary technique(s).

Banco do Brasil's workflow frames findings against ATT&CK. ATT&CK describes
adversary TTPs rather than web bug classes, so this is a deterministic best-effort
map from a canonical vuln class to the technique(s) an attacker would use it for.
It runs without the LLM, so every finding is tagged consistently and defensibly.
"""
from .state import canonical_class

# canonical class -> list of (technique_id, technique_name, tactic)
_MAP: dict[str, list[tuple[str, str, str]]] = {
    "rce": [("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ("T1059", "Command and Scripting Interpreter", "Execution")],
    "sqli": [("T1190", "Exploit Public-Facing Application", "Initial Access"),
             ("T1213", "Data from Information Repositories", "Collection")],
    "lfi": [("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ("T1005", "Data from Local System", "Collection")],
    "ssrf": [("T1190", "Exploit Public-Facing Application", "Initial Access"),
             ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "Credential Access")],
    "xxe": [("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ("T1005", "Data from Local System", "Collection")],
    "upload": [("T1190", "Exploit Public-Facing Application", "Initial Access"),
               ("T1505.003", "Server Software Component: Web Shell", "Persistence")],
    "xss": [("T1059.007", "Command and Scripting Interpreter: JavaScript", "Execution"),
            ("T1539", "Steal Web Session Cookie", "Credential Access")],
    "idor": [("T1190", "Exploit Public-Facing Application", "Initial Access"),
             ("T1213", "Data from Information Repositories", "Collection")],
    "ssti": [("T1190", "Exploit Public-Facing Application", "Initial Access"),
             ("T1059", "Command and Scripting Interpreter", "Execution")],
    "auth-bypass": [("T1190", "Exploit Public-Facing Application", "Initial Access"),
                    ("T1078", "Valid Accounts", "Defense Evasion")],
    "csrf": [("T1190", "Exploit Public-Facing Application", "Initial Access")],
    "open-redirect": [("T1566.002", "Phishing: Spearphishing Link", "Initial Access")],
    "info-disclosure": [("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access")],
    "privilege-escalation": [("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")],
}
_DEFAULT = [("T1190", "Exploit Public-Facing Application", "Initial Access")]


def techniques(vuln_class: str | None) -> list[dict]:
    """ATT&CK techniques for a vuln class, as JSON-friendly dicts."""
    rows = _MAP.get(canonical_class(vuln_class), _DEFAULT)
    return [{"id": i, "name": n, "tactic": t} for i, n, t in rows]


def tag(vuln_class: str | None) -> str:
    """Compact 'T1190, T1059' label for the UI."""
    return ", ".join(t["id"] for t in techniques(vuln_class))
