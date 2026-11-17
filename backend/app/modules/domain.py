from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from app.core import dns_lookup
from app.modules.base import BaseModule, ModuleContext, ModuleReport, make_finding

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


def normalize_domain(target: str) -> str:
    value = target.strip()
    if "://" not in value:
        value = "//" + value
    hostname = (urlparse(value).hostname or value).lower().rstrip(".")
    return hostname[4:] if hostname.startswith("www.") else hostname


class DomainModule(BaseModule):
    name = "domain"
    label = "Domaine"
    description = "DNS, RDAP, sous-domaines (crt.sh) et réputation"
    hint = "ex: example.com"

    def run(self, ctx: ModuleContext) -> ModuleReport:
        domain = normalize_domain(ctx.target)
        if not DOMAIN_RE.match(domain):
            raise ValueError("Nom de domaine invalide")
        ctx.progress(0, 4)

        timeout = ctx.options.timeout or ctx.settings.request_timeout
        for record_type in RECORD_TYPES:
            answers = dns_lookup.resolve(domain, record_type, timeout)
            make_finding(
                ctx,
                kind="dns",
                label=f"Enregistrements {record_type}",
                value=", ".join(answers[:20]) or "Aucun",
                status="found" if answers else "info",
                data={"type": record_type, "records": answers},
            )
        ctx.progress(1, 4)

        try:
            response = httpx.get(
                f"https://rdap.org/domain/{domain}",
                timeout=ctx.options.timeout or ctx.settings.request_timeout,
                follow_redirects=True,
            )
            response.raise_for_status()
            payload = response.json()
            events = {
                event.get("eventAction"): event.get("eventDate")
                for event in payload.get("events", [])
            }
            registrar = next(
                (
                    entity.get("vcardArray", [None, []])[1]
                    for entity in payload.get("entities", [])
                    if "registrar" in entity.get("roles", [])
                ),
                [],
            )
            registrar_name = next(
                (item[3] for item in registrar if len(item) > 3 and item[0] == "fn"),
                "Inconnu",
            )
            make_finding(
                ctx,
                kind="registration",
                label="Enregistrement RDAP",
                value=registrar_name,
                status="found",
                detail="; ".join(f"{key}: {value}" for key, value in events.items()),
                data=events,
            )
        except (httpx.HTTPError, ValueError, KeyError, IndexError) as exc:
            make_finding(ctx, kind="registration", label="RDAP", status="warning", detail=str(exc))
        ctx.progress(2, 4)

        try:
            response = httpx.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=max(timeout, 20),
                follow_redirects=True,
            )
            response.raise_for_status()
            names: set[str] = set()
            for entry in response.json():
                for name in str(entry.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain):
                        names.add(name)
            subdomains = sorted(names)[:200]
            make_finding(
                ctx,
                kind="subdomain",
                label="Sous-domaines (certificats)",
                value=", ".join(subdomains) or "Aucun",
                status="found" if subdomains else "info",
                data={"subdomains": subdomains},
            )
        except (httpx.HTTPError, ValueError) as exc:
            make_finding(
                ctx, kind="subdomain", label="Sous-domaines", status="warning", detail=str(exc)
            )
        ctx.progress(3, 4)

        api_key = ctx.settings.api_keys.get("virustotal")
        if api_key:
            try:
                response = httpx.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": api_key},
                    timeout=ctx.options.timeout or ctx.settings.request_timeout,
                )
                response.raise_for_status()
                stats = response.json()["data"]["attributes"]["last_analysis_stats"]
                make_finding(
                    ctx,
                    kind="reputation",
                    label="VirusTotal",
                    value=f"{stats.get('malicious', 0)} détection(s) malveillante(s)",
                    status="warning" if stats.get("malicious", 0) else "info",
                    data=stats,
                )
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                make_finding(
                    ctx, kind="reputation", label="VirusTotal", status="warning", detail=str(exc)
                )
        ctx.progress(4, 4)
        return ModuleReport(metadata={"domain": domain})
