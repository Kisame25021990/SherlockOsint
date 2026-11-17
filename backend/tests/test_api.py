from __future__ import annotations

import time

import pytest
from app.core import geoip
from app.core.engine import MODULES, validate_target
from app.main import app
from app.modules.base import ModuleReport, make_finding
from app.modules.domain import normalize_domain
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


def test_health(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_modules(client: TestClient) -> None:
    response = client.get("/api/modules")
    assert response.status_code == 200
    assert {item["name"] for item in response.json()} == {
        "username",
        "email",
        "domain",
        "ip",
        "phone",
        "geolocation",
    }


def test_normalize_domain() -> None:
    assert normalize_domain("https://www.Example.COM/path") == "example.com"
    assert normalize_domain("example.com") == "example.com"


def test_validate_target() -> None:
    validate_target("example.com", ["domain"])
    with pytest.raises(ValueError):
        validate_target("localhost", ["domain"])
    with pytest.raises(ValueError):
        validate_target("192.168.1.10", ["ip"])
    validate_target("8.8.8.8", ["ip"])
    validate_target("example.com", ["geolocation"])
    validate_target("8.8.8.8", ["geolocation"])
    with pytest.raises(ValueError):
        validate_target("10.0.0.1", ["geolocation"])
    with pytest.raises(ValueError):
        validate_target("pas un domaine", ["geolocation"])


def test_invalid_scan_payloads(client: TestClient) -> None:
    assert client.post("/api/scans", json={"target": "", "modules": ["ip"]}).status_code == 422
    response = client.post(
        "/api/scans",
        json={"target": "127.0.0.1", "modules": ["ip"]},
    )
    assert response.status_code == 400
    assert "privées" in response.json()["detail"]


def test_scan_lifecycle(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(ctx) -> ModuleReport:
        make_finding(ctx, kind="dns", label="Exemple", value="192.0.2.1", status="found")
        return ModuleReport()

    monkeypatch.setattr(MODULES["domain"], "run", fake_run)
    response = client.post(
        "/api/scans",
        json={"target": "example.com", "modules": ["domain"], "options": {"timeout": 5}},
    )
    assert response.status_code == 201
    scan_id = response.json()["id"]

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] == "done":
            break
        time.sleep(0.05)
    else:
        pytest.fail("Le scan ne s'est pas terminé")

    result = scan["results"][0]
    assert result["module"] == "domain"
    assert result["status"] == "done"
    assert result["findings"][0]["label"] == "Exemple"

    exported = client.get(f"/api/scans/{scan_id}/export?format=csv")
    assert exported.status_code == 200
    assert "Exemple" in exported.text
    assert client.get(f"/api/scans/{scan_id}/export?format=json").status_code == 200

    assert client.get("/api/scans").json()[0]["id"] == scan_id
    assert client.delete(f"/api/scans/{scan_id}").json()["deleted"] is True
    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_stream(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(ctx) -> ModuleReport:
        make_finding(ctx, kind="info", label="Test stream", status="info")
        return ModuleReport()

    monkeypatch.setattr(MODULES["phone"], "run", fake_run)
    scan = client.post("/api/scans", json={"target": "+33612345678", "modules": ["phone"]}).json()
    response = client.get(f"/api/scans/{scan['id']}/stream")
    assert response.status_code == 200
    assert "event: finding" in response.text
    assert "event: scan_done" in response.text
    assert "Test stream" in response.text


def test_geolocation(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        geoip,
        "lookup",
        lambda address, timeout: {
            "ip": address,
            "city": "Mountain View",
            "region": "California",
            "country": "United States",
            "country_code": "US",
            "latitude": 37.4,
            "longitude": -122.08,
            "timezone": "America/Los_Angeles",
            "currency": "USD",
            "isp": "Google LLC",
            "org": "Google LLC",
            "asn": 15169,
        },
    )
    scan = client.post("/api/scans", json={"target": "8.8.8.8", "modules": ["geolocation"]}).json()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        result = client.get(f"/api/scans/{scan['id']}").json()
        if result["status"] == "done":
            break
        time.sleep(0.05)
    else:
        pytest.fail("Le scan de géolocalisation ne s'est pas terminé")

    findings = result["results"][0]["findings"]
    location = next(finding for finding in findings if finding["kind"] == "geolocation")
    assert location["status"] == "found"
    assert location["data"]["latitude"] == 37.4
    assert location["data"]["longitude"] == -122.08
