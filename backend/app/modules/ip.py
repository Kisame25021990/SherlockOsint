from __future__ import annotations

import ipaddress

import httpx

from app.core import dns_lookup, geoip
from app.modules.base import BaseModule, ModuleContext, ModuleReport, make_finding


class IpModule(BaseModule):
    name = "ip"
    label = "Adresse IP"
    description = "Géolocalisation, ASN, reverse DNS et réputation"
    hint = "ex: 8.8.8.8"

    def run(self, ctx: ModuleContext) -> ModuleReport:
        try:
            address = ipaddress.ip_address(ctx.target.strip())
        except ValueError as exc:
            raise ValueError("Adresse IP invalide") from exc
        ctx.progress(0, 3)

        timeout = ctx.options.timeout or ctx.settings.request_timeout
        try:
            info = geoip.lookup(str(address), timeout)
            make_finding(
                ctx,
                kind="geolocation",
                label="Localisation",
                value=geoip.location_label(info),
                status="found",
                data={
                    "latitude": info["latitude"],
                    "longitude": info["longitude"],
                    "timezone": info["timezone"],
                    "country": info["country"],
                    "country_code": info["country_code"],
                    "ip": str(address),
                },
            )
            make_finding(
                ctx,
                kind="network",
                label="Réseau",
                value=str(info["asn"] or info["org"] or "Inconnu"),
                detail=info["isp"],
                status="info",
                data=info,
            )
        except (httpx.HTTPError, ValueError) as exc:
            make_finding(
                ctx,
                kind="geolocation",
                label="Localisation",
                value="Indisponible",
                status="warning",
                detail=str(exc),
            )
        ctx.progress(1, 3)

        ptr = dns_lookup.reverse(str(address), timeout)
        make_finding(
            ctx,
            kind="dns",
            label="Reverse DNS",
            value=", ".join(ptr) or "Aucun",
            status="found" if ptr else "info",
            data={"ptr": ptr},
        )
        ctx.progress(2, 3)

        api_key = ctx.settings.api_keys.get("shodan")
        if api_key:
            try:
                response = httpx.get(
                    f"https://api.shodan.io/shodan/host/{address}",
                    params={"key": api_key},
                    timeout=timeout,
                )
                response.raise_for_status()
                payload = response.json()
                ports = payload.get("ports", [])
                open_ports = ", ".join(map(str, ports)) or "aucun"
                make_finding(
                    ctx,
                    kind="exposure",
                    label="Shodan",
                    value=f"Ports ouverts : {open_ports}",
                    status="warning" if payload.get("ports") else "info",
                    data={"ports": payload.get("ports", []), "vulns": payload.get("vulns", [])},
                )
            except (httpx.HTTPError, ValueError) as exc:
                make_finding(
                    ctx, kind="exposure", label="Shodan", status="warning", detail=str(exc)
                )
        else:
            make_finding(
                ctx,
                kind="exposure",
                label="Shodan",
                value="Non vérifié",
                status="info",
                detail="Définissez SHODAN_API_KEY pour activer ce contrôle",
            )
        ctx.progress(3, 3)
        return ModuleReport(metadata={"ip": str(address)})
