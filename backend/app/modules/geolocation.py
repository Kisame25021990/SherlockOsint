from __future__ import annotations

import ipaddress

import httpx

from app.core import dns_lookup, geoip
from app.modules.base import BaseModule, ModuleContext, ModuleReport, make_finding
from app.modules.domain import normalize_domain


class GeolocationModule(BaseModule):
    name = "geolocation"
    label = "Géolocalisation"
    description = "Localise une IP ou l'hébergeur d'un domaine sur une carte"
    hint = "ex: 8.8.8.8 ou example.com"

    def run(self, ctx: ModuleContext) -> ModuleReport:
        target = ctx.target.strip()
        timeout = ctx.options.timeout or ctx.settings.request_timeout
        ctx.progress(0, 3)

        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            domain = normalize_domain(target)
            records = dns_lookup.resolve(domain, "A", timeout)
            if not records:
                raise ValueError(f"Aucune adresse IPv4 trouvée pour {target}") from None
            address = ipaddress.ip_address(records[0].split()[-1])

        make_finding(
            ctx,
            kind="network",
            label="Adresse IP",
            value=str(address),
            detail=f"Résolue depuis {target}",
            status="info",
        )
        ctx.progress(1, 3)

        try:
            info = geoip.lookup(str(address), timeout)
        except (httpx.HTTPError, ValueError) as exc:
            make_finding(
                ctx,
                kind="geolocation",
                label="Géolocalisation",
                value="Indisponible",
                status="warning",
                detail=str(exc),
            )
            ctx.progress(3, 3)
            return ModuleReport()

        latitude = info["latitude"]
        longitude = info["longitude"]
        map_url = (
            f"https://www.openstreetmap.org/?mlat={latitude}&mlon={longitude}"
            f"#map=10/{latitude}/{longitude}"
        )
        make_finding(
            ctx,
            kind="geolocation",
            label="Localisation",
            value=geoip.location_label(info),
            url=map_url,
            detail=f"{info['isp'] or 'FAI inconnu'} · {info['timezone'] or 'fuseau inconnu'}",
            status="found",
            data={
                "latitude": latitude,
                "longitude": longitude,
                "city": info["city"],
                "country": info["country"],
                "country_code": info["country_code"],
                "timezone": info["timezone"],
                "ip": str(address),
            },
        )
        ctx.progress(2, 3)

        make_finding(
            ctx,
            kind="network",
            label="Réseau",
            value=str(info["asn"] or info["org"] or "Inconnu"),
            detail=info["isp"],
            status="info",
            data={
                "asn": info["asn"],
                "org": info["org"],
                "isp": info["isp"],
                "currency": info["currency"],
            },
        )
        ctx.progress(3, 3)
        return ModuleReport(
            metadata={"ip": str(address), "latitude": latitude, "longitude": longitude}
        )
