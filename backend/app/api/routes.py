from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response, StreamingResponse

from app.api.schemas import Scan, ScanCreate, ScanSummary
from app.core.engine import ScanLimitError, engine

router = APIRouter(prefix="/api")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sherlock-osint"}


@router.get("/modules")
def modules() -> list[dict[str, Any]]:
    return [item.model_dump() for item in engine.modules_info()]


@router.post("/scans", status_code=201)
async def create_scan(payload: ScanCreate) -> Scan:
    try:
        return await engine.create_scan(payload)
    except ScanLimitError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/scans", response_model=list[ScanSummary])
def list_scans() -> list[ScanSummary]:
    return engine.list_scans()


@router.get("/scans/{scan_id}", response_model=Scan)
def get_scan(scan_id: str) -> Scan:
    scan = engine.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return scan


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str) -> dict[str, bool]:
    return {"deleted": engine.delete_scan(scan_id)}


@router.get("/scans/{scan_id}/export")
def export_scan(
    scan_id: str, format: str = Query(default="json", pattern="^(json|csv)$")
) -> Response:
    try:
        content = engine.export_scan(scan_id, format)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    media_type = "application/json" if format == "json" else "text/csv"
    filename = f"osint-{scan_id[:8]}.{format}"
    return Response(
        content=content,
        media_type=f"{media_type}; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/stream")
async def stream_scan(scan_id: str) -> StreamingResponse:
    if engine.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="Scan introuvable")

    async def events():
        queue = await engine.subscribe(scan_id)
        try:
            yield ": connecte\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                data = json.dumps(event["data"], ensure_ascii=False)
                yield f"event: {event['type']}\ndata: {data}\n\n"
                if event["type"] == "scan_done":
                    break
        finally:
            await engine.unsubscribe(scan_id, queue)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
