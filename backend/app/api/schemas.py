from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

ModuleName = Literal["username", "email", "domain", "ip", "phone", "geolocation"]
FindingStatus = Literal["found", "info", "warning", "error"]


class ScanOptions(BaseModel):
    timeout: int | None = Field(default=None, ge=1, le=180)
    sites: list[str] = Field(default_factory=list, max_length=100)
    include_nsfw: bool = False
    proxy: str | None = None

    @field_validator("sites", mode="before")
    @classmethod
    def clean_sites(cls, value: Any) -> list[str]:
        if not value:
            return []
        return [str(item).strip() for item in value if str(item).strip()]

    @field_validator("proxy", mode="before")
    @classmethod
    def clean_proxy(cls, value: Any) -> str | None:
        if value is None:
            return None
        proxy = str(value).strip()
        return proxy or None


class ScanCreate(BaseModel):
    target: str = Field(min_length=1, max_length=255)
    modules: list[ModuleName] = Field(min_length=1)
    options: ScanOptions = Field(default_factory=ScanOptions)

    @field_validator("target", mode="before")
    @classmethod
    def clean_target(cls, value: Any) -> str:
        target = str(value).strip()
        if not target:
            raise ValueError("La cible ne peut pas être vide")
        return target

    @field_validator("modules")
    @classmethod
    def unique_modules(cls, value: list[ModuleName]) -> list[ModuleName]:
        return list(dict.fromkeys(value))


class Finding(BaseModel):
    module: ModuleName
    kind: str
    label: str
    value: str | None = None
    detail: str | None = None
    url: str | None = None
    status: FindingStatus = "info"
    data: dict[str, Any] = Field(default_factory=dict)


class ModuleResult(BaseModel):
    module: ModuleName
    target: str
    status: Literal["pending", "running", "done", "error"] = "pending"
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    duration_ms: int | None = None


class Scan(BaseModel):
    id: str
    target: str
    modules: list[ModuleName]
    options: ScanOptions
    status: Literal["running", "done", "error"]
    created_at: str
    updated_at: str
    results: list[ModuleResult] = Field(default_factory=list)


class ScanSummary(BaseModel):
    id: str
    target: str
    modules: list[ModuleName]
    status: str
    created_at: str
    results_count: int


class ModuleInfo(BaseModel):
    name: ModuleName
    label: str
    description: str
    hint: str
    configured: bool = True
