from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import socket
import time
import uuid
from typing import Any

from app.api.schemas import (
    Finding,
    ModuleInfo,
    ModuleName,
    ModuleResult,
    Scan,
    ScanCreate,
    ScanSummary,
)
from app.core.config import settings
from app.modules.base import BaseModule, ModuleContext
from app.modules.domain import DOMAIN_RE, DomainModule, normalize_domain
from app.modules.email import EmailModule
from app.modules.geolocation import GeolocationModule
from app.modules.ip import IpModule
from app.modules.phone import PhoneModule
from app.modules.username import UsernameModule
from app.storage import db


class ScanLimitError(Exception):
    pass


MODULES: dict[ModuleName, BaseModule] = {
    "username": UsernameModule(),
    "email": EmailModule(),
    "domain": DomainModule(),
    "ip": IpModule(),
    "phone": PhoneModule(),
    "geolocation": GeolocationModule(),
}


def validate_target(target: str, modules: list[ModuleName]) -> None:
    target_is_ip = False
    if "ip" in modules or "geolocation" in modules:
        try:
            address = ipaddress.ip_address(target)
        except ValueError as exc:
            if "ip" in modules:
                raise ValueError("La cible module IP doit être une adresse IP valide") from exc
        else:
            target_is_ip = True
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
            ):
                raise ValueError("Les adresses IP privées ou réservées sont refusées")

    if "domain" in modules or ("geolocation" in modules and not target_is_ip):
        domain = normalize_domain(target)
        if domain in ("localhost",) or domain.endswith((".local", ".internal")):
            raise ValueError("Les domaines locaux sont refusés")
        try:
            ipaddress.ip_address(domain)
        except ValueError:
            pass
        else:
            raise ValueError("Utilisez le module IP pour une adresse IP")
        if not DOMAIN_RE.match(domain):
            raise ValueError("Nom de domaine invalide")
        try:
            resolved = socket.getaddrinfo(domain, None)
        except OSError:
            resolved = []
        for info in resolved:
            address = ipaddress.ip_address(info[4][0])
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
                or address.is_multicast
                or address.is_unspecified
            ):
                raise ValueError("Le domaine résout vers une adresse IP privée ou réservée")


class ScanEngine:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._events: dict[str, list[dict[str, Any]]] = {}

    def modules_info(self) -> list[ModuleInfo]:
        return [
            ModuleInfo(
                name=module.name,
                label=module.label,
                description=module.description,
                hint=module.hint,
            )
            for module in MODULES.values()
        ]

    async def create_scan(self, payload: ScanCreate) -> Scan:
        validate_target(payload.target, payload.modules)
        active = sum(1 for task in self._tasks.values() if not task.done())
        if active >= settings.max_concurrent_scans:
            raise ScanLimitError(
                f"Limite de {settings.max_concurrent_scans} scans simultanés atteinte"
            )
        scan_id = str(uuid.uuid4())
        created_at = db.utc_now()
        db.create_scan(
            scan_id,
            payload.target,
            list(payload.modules),
            payload.options.model_dump(mode="json"),
            "running",
            created_at,
        )
        task = asyncio.create_task(self._run_scan(scan_id), name=f"scan-{scan_id}")
        self._tasks[scan_id] = task
        task.add_done_callback(lambda _task, sid=scan_id: self._tasks.pop(sid, None))
        scan = db.get_scan(scan_id)
        if scan is None:
            raise RuntimeError("Impossible de créer le scan")
        return scan

    async def subscribe(self, scan_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(scan_id, set()).add(queue)
        for event in list(self._events.get(scan_id, [])):
            queue.put_nowait(event)
        return queue

    async def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        subscribers = self._subscribers.get(scan_id)
        if subscribers:
            subscribers.discard(queue)
            if not subscribers:
                self._subscribers.pop(scan_id, None)

    def _publish_sync(self, scan_id: str, event_type: str, data: Any) -> None:
        event = {"type": event_type, "data": data}
        history = self._events.setdefault(scan_id, [])
        if len(history) < 5000:
            history.append(event)
        for queue in list(self._subscribers.get(scan_id, ())):
            queue.put_nowait(event)

    async def _publish(self, scan_id: str, event_type: str, data: Any) -> None:
        self._publish_sync(scan_id, event_type, data)

    async def _run_scan(self, scan_id: str) -> None:
        scan = db.get_scan(scan_id)
        if scan is None:
            return
        await self._publish(scan_id, "scan_start", {"id": scan_id, "target": scan.target})
        had_error = False

        for name in scan.modules:
            module = MODULES[name]
            findings: list[Finding] = []
            loop = asyncio.get_running_loop()
            result = ModuleResult(module=name, target=scan.target, status="running")
            db.save_result(scan_id, result)
            await self._publish(scan_id, "module_start", {"module": name, "label": module.label})

            def emit(
                finding: Finding,
                _findings: list[Finding] = findings,
                _loop: asyncio.AbstractEventLoop = loop,
            ) -> None:
                _findings.append(finding)
                _loop.call_soon_threadsafe(
                    self._publish_sync,
                    scan_id,
                    "finding",
                    finding.model_dump(mode="json"),
                )

            def progress(
                current: int | None,
                total: int | None,
                _name: ModuleName = name,
                _loop: asyncio.AbstractEventLoop = loop,
            ) -> None:
                _loop.call_soon_threadsafe(
                    self._publish_sync,
                    scan_id,
                    "progress",
                    {"module": _name, "current": current, "total": total},
                )

            ctx = ModuleContext(
                module=name,
                target=scan.target,
                options=scan.options,
                settings=settings,
                emit=emit,
                progress=progress,
            )
            started = time.monotonic()
            try:
                await asyncio.to_thread(module.run, ctx)
                result.status = "done"
            except Exception as exc:
                had_error = True
                result.status = "error"
                result.error = str(exc)
                await self._publish(
                    scan_id,
                    "module_error",
                    {"module": name, "message": str(exc)},
                )
            finally:
                result.findings = findings
                result.duration_ms = int((time.monotonic() - started) * 1000)
                db.save_result(scan_id, result)
                await self._publish(scan_id, "module_done", result.model_dump(mode="json"))

        final_status = "error" if had_error else "done"
        db.update_scan_status(scan_id, final_status)
        await self._publish(scan_id, "scan_done", {"id": scan_id, "status": final_status})

    def get_scan(self, scan_id: str) -> Scan | None:
        return db.get_scan(scan_id)

    def list_scans(self) -> list[ScanSummary]:
        return db.list_scans()

    def delete_scan(self, scan_id: str) -> bool:
        task = self._tasks.pop(scan_id, None)
        if task and not task.done():
            task.cancel()
        deleted = db.delete_scan(scan_id)
        if deleted:
            self._events.pop(scan_id, None)
            self._subscribers.pop(scan_id, None)
        return deleted

    def export_scan(self, scan_id: str, export_format: str) -> str:
        scan = db.get_scan(scan_id)
        if scan is None:
            raise ValueError("Scan introuvable")
        if export_format == "json":
            return json.dumps(scan.model_dump(mode="json"), ensure_ascii=False, indent=2)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            ["scan_id", "module", "target", "kind", "label", "value", "detail", "url", "status"]
        )
        for result in scan.results:
            for finding in result.findings:
                writer.writerow(
                    [
                        scan.id,
                        finding.module,
                        result.target,
                        finding.kind,
                        finding.label,
                        finding.value,
                        finding.detail,
                        finding.url,
                        finding.status,
                    ]
                )
        return output.getvalue()


engine = ScanEngine()
