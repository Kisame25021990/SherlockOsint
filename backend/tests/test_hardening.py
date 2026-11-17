from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from app.api.schemas import ScanOptions
from app.core.config import settings
from app.core.engine import engine
from app.main import app
from app.modules import email as email_module
from app.modules import username as username_module
from app.modules.base import ModuleContext
from app.modules.email import EmailModule
from app.modules.username import UsernameModule
from app.storage import db
from fastapi.testclient import TestClient


def _email_context(emitted: list[Any]) -> ModuleContext:
    return ModuleContext(
        module="email",
        target="alice@example.com",
        options=ScanOptions(),
        settings=settings,
        emit=emitted.append,
        progress=lambda _current, _total: None,
    )


def test_hibp_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    emitted: list[Any] = []

    def fake_get(url: str, **kwargs: Any) -> SimpleNamespace:
        calls.append((url, kwargs))
        return SimpleNamespace(status_code=404)

    monkeypatch.setitem(settings.api_keys, "hibp", "test-key")
    monkeypatch.setattr(
        email_module.dns_lookup, "resolve", lambda *_args, **_kwargs: ["mx.example.com"]
    )
    monkeypatch.setattr(email_module.httpx, "get", fake_get)

    EmailModule().run(_email_context(emitted))

    hibp_calls = [call for call in calls if "haveibeenpwned" in call[0]]
    assert len(hibp_calls) == 1
    url, kwargs = hibp_calls[0]
    assert url == "https://api.haveibeenpwned.com/v3/breachedaccount/alice%40example.com"
    assert kwargs["headers"]["hibp-api-key"] == "test-key"
    assert any(
        finding.kind == "breach" and finding.value == "Aucune fuite connue" for finding in emitted
    )


def test_sherlock_uses_local_sites(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_sites(**kwargs: Any) -> str:
        captured.update(kwargs)
        return "sites"

    monkeypatch.setattr(settings, "sherlock_use_remote_sites", False)
    monkeypatch.setattr(username_module, "SitesInformation", fake_sites)
    assert UsernameModule()._load_sites([]) == "sites"
    assert str(captured["data_file_path"]).endswith(str(Path("resources") / "data.json"))
    assert "MANIFEST" not in str(captured["data_file_path"])


def test_basic_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "auth_user", "admin")
    monkeypatch.setattr(settings, "auth_password", "secret")
    credentials = base64.b64encode(b"admin:secret").decode()

    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/modules").status_code == 401
        response = client.get("/api/modules", headers={"Authorization": f"Basic {credentials}"})
        assert response.status_code == 200


def test_concurrent_scan_limit(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeTask:
        def done(self) -> bool:
            return False

    monkeypatch.setattr(settings, "max_concurrent_scans", 1)
    monkeypatch.setattr(engine, "_tasks", {"active": FakeTask()})
    response = client.post("/api/scans", json={"target": "+33612345678", "modules": ["phone"]})
    assert response.status_code == 429


def test_recover_interrupted_scans() -> None:
    scan_id = "interrupted-test-scan"
    db.create_scan(scan_id, "example.com", ["domain"], {}, "running", db.utc_now())
    try:
        assert db.recover_interrupted_scans() >= 1
        scan = db.get_scan(scan_id)
        assert scan is not None
        assert scan.status == "error"
    finally:
        db.delete_scan(scan_id)
