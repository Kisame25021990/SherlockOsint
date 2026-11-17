from __future__ import annotations

import hashlib
import re
from urllib.parse import quote

import httpx

from app.core import dns_lookup
from app.modules.base import BaseModule, ModuleContext, ModuleReport, make_finding

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class EmailModule(BaseModule):
    name = "email"
    label = "Email"
    description = "Vérifie le domaine, les MX, Gravatar et les fuites (HIBP)"
    hint = "ex: alice@example.com"

    def run(self, ctx: ModuleContext) -> ModuleReport:
        email = ctx.target
        ctx.progress(0, 3)
        if not EMAIL_RE.match(email):
            raise ValueError("Format d'email invalide")

        domain = email.rsplit("@", 1)[1]
        local_part = email.rsplit("@", 1)[0]
        make_finding(
            ctx,
            kind="identity",
            label="Adresse",
            value=email,
            status="info",
            data={"local_part": local_part, "domain": domain},
        )

        mx_records = dns_lookup.resolve(
            domain, "MX", ctx.options.timeout or ctx.settings.request_timeout
        )
        make_finding(
            ctx,
            kind="dns",
            label="Serveurs MX",
            value=", ".join(mx_records) or "Aucun",
            status="found" if mx_records else "warning",
            data={"mx": mx_records},
        )
        ctx.progress(1, 3)

        digest = hashlib.md5(email.strip().lower().encode(), usedforsecurity=False).hexdigest()
        avatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404&s=80"
        try:
            response = httpx.get(
                avatar_url,
                timeout=ctx.options.timeout or ctx.settings.request_timeout,
                follow_redirects=True,
            )
            if response.status_code == 200:
                make_finding(
                    ctx,
                    kind="gravatar",
                    label="Gravatar",
                    value=avatar_url,
                    url=f"https://www.gravatar.com/avatar/{digest}",
                    status="found",
                    detail="Un avatar Gravatar est associé à cette adresse",
                )
            else:
                make_finding(
                    ctx,
                    kind="gravatar",
                    label="Gravatar",
                    value="Aucun avatar public",
                    status="info",
                )
        except httpx.HTTPError as exc:
            make_finding(ctx, kind="gravatar", label="Gravatar", status="warning", detail=str(exc))
        ctx.progress(2, 3)

        api_key = ctx.settings.api_keys.get("hibp")
        if api_key:
            try:
                response = httpx.get(
                    f"https://api.haveibeenpwned.com/v3/breachedaccount/{quote(email, safe='')}",
                    headers={
                        "hibp-api-key": api_key,
                        "User-Agent": "Sherlock-OSINT",
                    },
                    timeout=ctx.options.timeout or ctx.settings.request_timeout,
                )
                if response.status_code == 200:
                    breaches: list[str] | None = [item.get("Name", "") for item in response.json()]
                elif response.status_code == 404:
                    breaches = []
                else:
                    breaches = None
                    make_finding(
                        ctx,
                        kind="breach",
                        label="Fuites de données",
                        value=f"Erreur API ({response.status_code})",
                        status="warning",
                    )
                if breaches is not None:
                    make_finding(
                        ctx,
                        kind="breach",
                        label="Fuites de données",
                        value=", ".join(breaches) or "Aucune fuite connue",
                        status="found" if breaches else "info",
                        data={"breaches": breaches},
                    )
            except httpx.HTTPError as exc:
                make_finding(
                    ctx, kind="breach", label="Fuites de données", status="warning", detail=str(exc)
                )
        else:
            make_finding(
                ctx,
                kind="breach",
                label="Fuites de données",
                value="Non vérifié",
                status="info",
                detail="Définissez HIBP_API_KEY pour activer ce contrôle",
            )
        ctx.progress(3, 3)
        return ModuleReport()
