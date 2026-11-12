"""Deterministic scope enforcement — the hard boundary the LLM cannot cross.

The agent may *propose* anything; this module decides, WITHOUT the model, whether
a host/URL is inside the authorized scope. For a bank engagement the default rule
is strict: an authorized URL means that EXACT host — no parent domain, no siblings,
no subdomains — unless the operator explicitly widens it.

This is the Scope Manager of the governance architecture: every outbound action
(recon enumeration, a tool request, an agent-proposed curl) is checked here first,
and every decision is auditable. It never consults the LLM, so a prompt-injection
or a model mistake cannot cause scope leakage.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


def _host_of(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if "://" in s:
        return (urlparse(s).hostname or "").lower()
    # bare host[:port][/path]
    s = s.split("/")[0].split("@")[-1]
    if s.startswith("["):  # IPv6 literal
        return s[1:].split("]")[0].lower()
    return s.split(":")[0].lower()


def _is_ip_or_local(host: str) -> bool:
    if host in ("localhost",):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@dataclass
class Scope:
    """An authorized scope. `allows(url)` is the single source of truth.

    hosts: exact hostnames (and/or IPs) that are in scope.
    allow_subdomains: if True, any subdomain of a listed host is also in scope
        (classic bug-bounty 'domain and its subdomains'); default False (strict).
    """
    hosts: set[str] = field(default_factory=set)
    allow_subdomains: bool = False

    @classmethod
    def from_target(cls, target: str, allow_subdomains: bool | None = None,
                    extra_hosts: list[str] | None = None) -> "Scope":
        """Build a scope from an operator-supplied target.

        A URL target (https://1.migbot.com.br/#/) -> that EXACT host, strict.
        A bare domain (example.com) -> the domain, subdomains allowed by default
        (that is what a bare-domain program usually means). The operator can force
        either policy with allow_subdomains.
        """
        host = _host_of(target)
        is_url = "://" in (target or "")
        if allow_subdomains is None:
            # URL or IP/localhost -> strict; bare domain -> subdomains on
            allow_subdomains = not (is_url or _is_ip_or_local(host))
        hosts = {host} if host else set()
        for h in extra_hosts or []:
            hh = _host_of(h)
            if hh:
                hosts.add(hh)
        return cls(hosts=hosts, allow_subdomains=allow_subdomains)

    # -- the decision -------------------------------------------------------- #
    def allows_host(self, host: str) -> bool:
        host = (host or "").lower()
        if not host or not self.hosts:
            return False
        if host in self.hosts:
            return True
        if self.allow_subdomains:
            return any(host.endswith("." + h) for h in self.hosts)
        return False

    def allows(self, url: str) -> bool:
        return self.allows_host(_host_of(url))

    def reason(self, url: str) -> str:
        """Human/audit-readable reason a URL is blocked (empty if allowed)."""
        host = _host_of(url)
        if not host:
            return "sem host na URL"
        if self.allows_host(host):
            return ""
        allowed = ", ".join(sorted(self.hosts)) or "(vazio)"
        if self.allow_subdomains:
            return f"host '{host}' fora do escopo (permitido: {allowed} e seus subdomínios)"
        return f"host '{host}' fora do escopo ESTRITO (permitido APENAS: {allowed})"

    # -- descriptions for prompts / reports ---------------------------------- #
    def note(self) -> str:
        """The scope sentence handed to the agent. Deliberately forbids drift."""
        allowed = ", ".join(sorted(self.hosts)) or "(nenhum)"
        if self.allow_subdomains:
            return (f"ESCOPO AUTORIZADO: {allowed} e seus subdomínios. "
                    f"NÃO toque em nenhum outro host, domínio-pai ou domínio irmão.")
        return (f"ESCOPO AUTORIZADO ESTRITO: somente {allowed}. "
                f"É PROIBIDO tocar em subdomínios, no domínio-pai, em domínios irmãos "
                f"ou em qualquer outro host. Fora deste(s) host(s) exato(s) = fora de escopo.")

    def label(self) -> str:
        mode = "subdomínios ON" if self.allow_subdomains else "estrito"
        return f"{', '.join(sorted(self.hosts))} [{mode}]"
