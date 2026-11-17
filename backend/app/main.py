from __future__ import annotations

import base64
import binascii
import hmac
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import settings
from app.storage import db


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db.init_db(settings.db_path)
    db.recover_interrupted_scans()
    yield


app = FastAPI(
    title="Sherlock OSINT",
    description="Application web d'OSINT multi-modules (Sherlock, DNS, email, IP, téléphone)",
    version="0.1.0",
    lifespan=lifespan,
)


def _valid_basic_auth(request: Request) -> bool:
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "basic" or not token:
        return False
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    username, separator, password = decoded.partition(":")
    if not separator:
        return False
    return hmac.compare_digest(username.encode(), settings.auth_user.encode()) and (
        hmac.compare_digest(password.encode(), settings.auth_password.encode())
    )


@app.middleware("http")
async def require_auth(request: Request, call_next):
    if (
        settings.auth_enabled
        and request.url.path != "/api/health"
        and not _valid_basic_auth(request)
    ):
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Sherlock OSINT"'},
        )
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="frontend")
