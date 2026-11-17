from __future__ import annotations

from pathlib import Path

import sherlock_project
from sherlock_project.notify import QueryNotify
from sherlock_project.result import QueryResult, QueryStatus
from sherlock_project.sherlock import sherlock
from sherlock_project.sites import SitesInformation

from app.core.config import settings
from app.modules.base import BaseModule, ModuleContext, ModuleReport, make_finding


class StreamNotify(QueryNotify):
    def __init__(self, ctx: ModuleContext, total: int) -> None:
        super().__init__()
        self.ctx = ctx
        self.total = total
        self.done = 0

    def start(self, message: str | None = None) -> None:
        self.ctx.progress(0, self.total)

    def update(self, result: QueryResult) -> None:
        self.done += 1
        if result.status is QueryStatus.CLAIMED:
            make_finding(
                self.ctx,
                kind="account",
                label=result.site_name,
                value=result.site_url_user,
                url=result.site_url_user,
                status="found",
                detail="Compte potentiel trouvé",
                data={"query_time_ms": result.query_time},
            )
        elif result.status in (QueryStatus.UNKNOWN, QueryStatus.WAF, QueryStatus.ILLEGAL):
            make_finding(
                self.ctx,
                kind="account",
                label=result.site_name,
                value=result.site_url_user,
                url=result.site_url_user,
                status="warning",
                detail=f"Résultat incertain : {result.status.value}",
            )
        self.ctx.progress(self.done, self.total)

    def finish(self, message: str | None = None) -> None:
        self.ctx.progress(self.total, self.total)


class UsernameModule(BaseModule):
    name = "username"
    label = "Pseudo / Username"
    description = "Recherche le pseudo sur 400+ réseaux sociaux via Sherlock"
    hint = "ex: alice_dev"

    def _load_sites(self, requested: list[str]) -> SitesInformation:
        local = Path(sherlock_project.__file__).parent / "resources" / "data.json"
        if settings.sherlock_use_remote_sites:
            try:
                return SitesInformation(honor_exclusions=True, do_not_exclude=requested)
            except Exception:
                pass
        return SitesInformation(
            data_file_path=str(local),
            honor_exclusions=True,
            do_not_exclude=requested,
        )

    def run(self, ctx: ModuleContext) -> ModuleReport:
        requested = ctx.options.sites
        sites = self._load_sites(requested)
        if not ctx.options.include_nsfw:
            sites.remove_nsfw_sites(do_not_remove=requested)

        site_data = {site.name: site.information for site in sites}
        known = {name.lower() for name in site_data}

        if requested:
            missing = [site for site in requested if site.lower() not in known]
            site_data = {
                name: data
                for name, data in site_data.items()
                if name.lower() in {site.lower() for site in requested}
            }
            if missing:
                make_finding(
                    ctx,
                    kind="info",
                    label="Sites inconnus",
                    value=", ".join(missing),
                    status="warning",
                    detail="Ces sites ne figurent pas dans la liste Sherlock",
                )

        if not site_data:
            raise ValueError("Aucun site valide à interroger pour ce pseudo")

        notify = StreamNotify(ctx, len(site_data))
        results = sherlock(
            ctx.target,
            site_data,
            notify,
            proxy=ctx.options.proxy or ctx.settings.proxy,
            timeout=ctx.options.timeout or ctx.settings.sherlock_timeout,
        )
        claimed = sum(
            1
            for item in results.values()
            if isinstance(item.get("status"), QueryResult)
            and item["status"].status is QueryStatus.CLAIMED
        )
        make_finding(
            ctx,
            kind="summary",
            label="Sites analysés",
            value=str(len(site_data)),
            status="info",
            detail=f"{claimed} profil(s) potentiel(s) détecté(s)",
            data={"sites_checked": len(site_data), "claimed": claimed},
        )
        return ModuleReport(metadata={"sites_checked": len(site_data), "claimed": claimed})
