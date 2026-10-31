from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from .api import router
from .auth import auth_router
from .config import settings
from .db import get_db

app = FastAPI(title="APISentinel", version="0.1.0", description="Scoped API security assessment workspace")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token", "Idempotency-Key"],
    expose_headers=["X-Total-Count", "X-Next-Offset"],
)
app.include_router(auth_router, prefix=settings.api_prefix)
app.include_router(router, prefix=settings.api_prefix)


@app.get("/")
def root():
    return {"name": "APISentinel", "docs": "/docs", "api": settings.api_prefix}


@app.get(f"{settings.api_prefix}/health")
def health():
    return {"status": "ok", "product": "APISentinel", "active_tests_available": settings.allow_active_tests}


@app.get(f"{settings.api_prefix}/ready")
def readiness(db=Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - readiness must not disclose connection details.
        raise HTTPException(503, "Database is not ready") from None
    return {"status": "ready"}
