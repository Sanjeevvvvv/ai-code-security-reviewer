from __future__ import annotations
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from web.backend.models import ensure_history_file
from web.backend.routes.history import router as history_router
from web.backend.routes.scan import router as scan_router

app = FastAPI(title="AI Code Security Reviewer API", version="1.0.0")

origins = [
    "http://localhost:5173",
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

@app.get("/")
async def root():
    return RedirectResponse(url="/docs")

@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok"}

app.include_router(scan_router)
app.include_router(history_router)