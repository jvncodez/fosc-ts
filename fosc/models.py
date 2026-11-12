"""Model router — the one place the application talks to a model.

Why this layer exists (BB requirement): running on Amazon Bedrock, if a model
fails, refuses, or gets slow we must switch to another model WITHOUT rewriting
the application. So the rest of FOSC never names a concrete model or provider —
it asks `models.run(role, ...)` for a ROLE (hunt / verify / consolidate /
privesc). This module:

  - resolves the role to an ordered LADDER of candidate models (config, not code);
  - picks the PROVIDER per attempt (Anthropic API or Amazon Bedrock) by setting
    the environment the `claude` CLI already honours — no SDK change;
  - FAILS OVER down the ladder on a failover-worthy outcome (error / timeout /
    refusal / slowness), transparently to the caller;
  - charges the caller for every attempt and keeps each failed attempt's stream
    for the audit trail.

Everything is configuration (`config.MODEL_*`, overridable via the user config
file / env), so swapping or adding a model is never an application change.
Offline is NOT failover-worthy: when the network is down another model cannot
help, so the router stops and reports it.
"""
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .claude_runner import run_claude

# statuses for which trying the next model in the ladder makes sense
_FAILOVER = {"error", "timeout", "refused"}


@dataclass
class ModelSpec:
    alias: str
    provider: str
    model_id: str
    env: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.provider}:{self.alias}"


def _user_cfg() -> dict:
    try:
        return config.load_user_config() or {}
    except Exception:
        return {}


def _provider() -> str:
    return str(_user_cfg().get("model_provider") or config.MODEL_PROVIDER).lower()


def _bedrock_ids() -> dict:
    ids = dict(config.BEDROCK_MODEL_IDS)
    o = _user_cfg().get("bedrock_model_ids")
    if isinstance(o, dict):
        ids.update(o)
    return ids


def _provider_env(provider: str) -> dict:
    # Flip the `claude` CLI between the Anthropic API and Bedrock per attempt.
    # Force "0" for anthropic so a ladder entry can fall back to the direct API
    # even when the ambient environment globally enabled Bedrock.
    return {"CLAUDE_CODE_USE_BEDROCK": "1" if provider == "bedrock" else "0"}


def resolve(entry: str) -> ModelSpec:
    """One ladder entry -> a concrete (provider, model-id). An entry is a bare
    alias (resolved via the global provider) or an explicit "provider:model-id"
    to pin or cross providers."""
    if ":" in entry and entry.split(":", 1)[0] in ("anthropic", "bedrock"):
        provider, model_id = entry.split(":", 1)
        alias = model_id
    else:
        provider, alias, model_id = _provider(), entry, entry
    if provider == "bedrock":
        model_id = _bedrock_ids().get(model_id, model_id)
    else:
        model_id = config.ANTHROPIC_MODEL_IDS.get(model_id, model_id)
    return ModelSpec(alias=alias, provider=provider, model_id=model_id, env=_provider_env(provider))


def ladder_for(role: str) -> list[str]:
    base = dict(config.MODEL_LADDERS)
    override = _user_cfg().get("model_ladders")
    if isinstance(override, dict):
        base.update(override)
    entries = base.get(role) or [config.HUNT_MODEL]
    return list(entries)[: config.MODEL_MAX_ATTEMPTS]


def specs_for(role: str) -> list[ModelSpec]:
    return [resolve(e) for e in ladder_for(role)]


def _preserve_stream(stream_path: Path, i: int) -> None:
    """Keep a failed attempt's transcript so the next attempt can write fresh and
    the audit trail still has every attempt."""
    try:
        if stream_path.exists():
            stream_path.rename(stream_path.with_name(f"{stream_path.stem}.try{i}{stream_path.suffix}"))
    except OSError:
        pass


def run(role: str, prompt: str, *, cwd: Path, timeout: int, stream_path: Path,
        system_prompt: str, schema: dict | None = None, on_activity=None,
        allow_tools: bool = True, effort: str | None = None,
        budget: float | None = None) -> dict:
    """Run one task for `role`, failing over down the ladder. Returns the same
    dict shape as run_claude plus: "model"/"provider" (the one that answered) and
    "attempts" (every try, for the audit trail). "cost" is the SUM across attempts.
    """
    specs = specs_for(role)
    attempts: list[dict] = []
    total_cost = 0.0
    result: dict | None = None
    n = len(specs)

    for i, spec in enumerate(specs):
        is_last = i == n - 1
        attempt_timeout = timeout if is_last else max(60, int(timeout * config.MODEL_ATTEMPT_FRACTION))
        if i > 0 and on_activity:
            prev = attempts[-1]
            try:
                on_activity(f"failover → {spec.label} (anterior {prev['model']}: {prev['status']})")
            except Exception:
                pass

        run_res = run_claude(
            prompt, cwd=cwd, timeout=attempt_timeout, stream_path=stream_path,
            model=spec.model_id, system_prompt=system_prompt, schema=schema,
            on_activity=on_activity, allow_tools=allow_tools, effort=effort,
            budget=budget, env_extra=spec.env,
        )
        total_cost += float(run_res.get("cost") or 0.0)
        attempts.append({"model": spec.label, "provider": spec.provider,
                         "model_id": spec.model_id, "status": run_res["status"],
                         "error": run_res.get("error")})
        run_res["model"] = spec.label
        run_res["provider"] = spec.provider
        run_res["attempts"] = attempts
        run_res["cost"] = total_cost  # charge for every attempt made
        result = run_res

        if run_res["status"] not in _FAILOVER:
            return run_res            # ok, or offline (another model won't help)
        if not is_last:
            _preserve_stream(stream_path, i)

    if result is None:
        return {"output": None, "cost": 0.0, "status": "error", "turns": 0,
                "error": "no model configured for role", "model": None,
                "provider": None, "attempts": attempts}
    return result


def summary() -> dict:
    """For the status/banner UI: active provider and each role's ladder."""
    return {"provider": _provider(),
            "ladders": {role: [s.label for s in specs_for(role)] for role in config.MODEL_LADDERS}}
