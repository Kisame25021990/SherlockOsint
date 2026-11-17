from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.api.schemas import Finding, ModuleName, ScanOptions
from app.core.config import Settings


@dataclass
class ModuleContext:
    module: ModuleName
    target: str
    options: ScanOptions
    settings: Settings
    emit: Callable[[Finding], None]
    progress: Callable[[int | None, int | None], None]


@dataclass
class ModuleReport:
    notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseModule(ABC):
    name: str
    label: str
    description: str
    hint: str
    needs_key: str | None = None

    @abstractmethod
    def run(self, ctx: ModuleContext) -> ModuleReport:
        """Exécute le module et publie ses résultats via ctx.emit()."""


def make_finding(
    ctx: ModuleContext,
    kind: str,
    label: str,
    value: str | None = None,
    detail: str | None = None,
    url: str | None = None,
    status: str = "info",
    data: dict[str, Any] | None = None,
) -> None:
    ctx.emit(
        Finding(
            module=ctx.module,
            kind=kind,
            label=label,
            value=value,
            detail=detail,
            url=url,
            status=status,
            data=data or {},
        )
    )
