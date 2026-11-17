from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver
import httpx

DOH_URL = "https://cloudflare-dns.com/dns-query"


def _resolver(timeout: int) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _doh(name: str, rdtype: str, timeout: int) -> list[str]:
    try:
        response = httpx.get(
            DOH_URL,
            params={"name": name, "type": rdtype},
            headers={"accept": "application/dns-json"},
            timeout=timeout,
        )
        response.raise_for_status()
        answers = response.json().get("Answer", [])
        return [str(item["data"]) for item in answers if item.get("data")]
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return []


def resolve(name: str, rdtype: str, timeout: int) -> list[str]:
    try:
        return [record.to_text() for record in _resolver(timeout).resolve(name, rdtype)]
    except dns.exception.DNSException:
        return _doh(name, rdtype, timeout)


def reverse(address: str, timeout: int) -> list[str]:
    try:
        return [str(record.target) for record in _resolver(timeout).resolve_address(address)]
    except (dns.exception.DNSException, OSError, ValueError):
        try:
            name = ipaddress.ip_address(address).reverse_pointer
        except ValueError:
            return []
        return _doh(name, "PTR", timeout)
