"""Stand-in for the `claude` CLI in tests. Emits stream-json shaped like the
real CLI (system init -> assistant tool_use -> result with structured_output).

Behaviour is picked from argv/env:
  --model opus           -> adversarial review (FAKE_REVIEW=survive|refute)
  --disallowedTools=...  -> playbook consolidation
  otherwise              -> hunt task (FAKE_HUNT=confirmed|rejected|sleep)
"""
import json
import os
import sys
import time

argv = sys.argv[1:]
model = argv[argv.index("--model") + 1] if "--model" in argv else "?"


def emit(ev):
    print(json.dumps(ev), flush=True)


emit({"type": "system", "subtype": "init", "model": model})

if model == "opus":
    survive = os.environ.get("FAKE_REVIEW", "survive") == "survive"
    out = {"survives": survive, "reason": "reproduced twice, real data of another user" if survive else "payload only echoed in an error page",
           "severity": "high", "cvss": 7.5, "vuln_class": "IDOR",
           "lesson": None if survive else "echo of payload in 404 page is not XSS"}
elif any(a.startswith("--disallowedTools") for a in argv):
    out = {"playbook_markdown": "# Playbook\n\n## IDOR\n- numeric ids on /api/* are worth testing first\n"}
else:
    mode = os.environ.get("FAKE_HUNT", "confirmed")
    if mode == "mixed":  # demo: verdict depends on the endpoint in the prompt
        time.sleep(2 + (hash(argv[-1]) % 4))
        prompt = argv[-1]
        mode = ("confirmed" if "/api/users" in prompt or "/rest/basket" in prompt
                else "rejected" if "search" in prompt else "inconclusive")
    if mode == "sleep":
        time.sleep(30)
    elif mode == "slow":
        time.sleep(3)
        mode = "rejected"
    emit({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": "Bash", "input": {"command": "curl -s https://app.test/api/users/2"}}]}})
    os.makedirs("poc", exist_ok=True)
    with open("poc/poc.md", "w") as f:
        f.write("GET /api/users/2 returns another user's email\n")
    out = {"verdict": mode if mode != "sleep" else "rejected", "vuln_class": "IDOR", "severity": "high", "cvss": 7.1,
           "title": "IDOR on /api/users/{id}", "summary": "Any logged-in user can read other users' profiles.",
           "impact": "PII disclosure", "steps": ["log in", "GET /api/users/2"],
           "repro_curl": "curl -s https://app.test/api/users/2", "evidence_marker": "victim@app.test",
           "poc_path": "poc/poc.md", "tech_observed": ["express"],
           "lessons": ["express apps here expose sequential numeric ids under /api/users"],
           "target_notes": ["JWT in Authorization header"]}

emit({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "StructuredOutput", "input": out}]}})
emit({"type": "result", "subtype": "success", "is_error": False, "num_turns": 3,
      "total_cost_usd": 0.0123, "result": "", "structured_output": out})
