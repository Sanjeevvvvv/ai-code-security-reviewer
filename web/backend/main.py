from __future__ import annotations
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from web.backend.models import ensure_history_file
from web.backend.routes.history import router as history_router
from web.backend.routes.scan import router as scan_router

app = FastAPI(title="AI Code Security Reviewer API", version="1.0.0")

origins = [
    "http://localhost:5173",
    "https://ai-code-security-reviewer.onrender.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def on_startup() -> None:
    ensure_history_file()

@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}

app.include_router(scan_router)
app.include_router(history_router)

# Serve React frontend
static_dir = Path(__file__).parent.parent.parent / "web" / "static"
if static_dir.exists():
    app.mount("/assets", StaticFiles(directory=str(static_dir / "assets")), name="assets")

    @app.get("/")
    async def root():
        return FileResponse(str(static_dir / "index.html"))

    @app.get("/{full_path:path}")
    async def catch_all(full_path: str):
        return FileResponse(str(static_dir / "index.html"))
else:
    @app.get("/")
    async def root():
        return RedirectResponse(url="/docs")