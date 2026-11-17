from __future__ import annotations

from typing import Any

import httpx

GEOIP_URL = "https://ipwho.is"


def lookup(address: str, timeout: int) -> dict[str, Any]:
    response = httpx.get(f"{GEOIP_URL}/{address}", timeout=timeout, follow_redirects=True)
    response.raise_for_status()
    payload = response.json()
    if not payload.get("success"):
        raise ValueError(str(payload.get("message") or "Géolocalisation indisponible"))

    timezone = payload.get("timezone") or {}
    connection = payload.get("connection") or {}
    currency = payload.get("currency") or {}
    return {
        "ip": payload.get("query") or address,
        "city": payload.get("city"),
        "region": payload.get("region"),
        "country": payload.get("country"),
        "country_code": payload.get("country_code"),
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
        "timezone": timezone.get("id"),
        "currency": currency.get("code"),
        "isp": connection.get("isp"),
        "org": connection.get("org"),
        "asn": connection.get("asn"),
    }


def location_label(info: dict[str, Any]) -> str:
    return (
        ", ".join(
            part for part in (info.get("city"), info.get("region"), info.get("country")) if part
        )
        or "Inconnue"
    )
