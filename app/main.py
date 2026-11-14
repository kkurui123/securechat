from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool
from app.core.config import settings
from app.core.database import engine
from app.routes import auth, chat, incidents, realtime, health

@asynccontextmanager
async def lifespan(app):
    yield
    await run_in_threadpool(engine.dispose)

cfg = settings()
app = FastAPI(title="SecureChat API", version="0.2.0", lifespan=lifespan,
              docs_url="/docs" if cfg.enable_docs else None, redoc_url=None,
              openapi_url="/openapi.json" if cfg.enable_docs else None)
app.add_middleware(CORSMiddleware, allow_origins=cfg.cors_origins,
                   allow_credentials=False, allow_methods=["GET", "POST", "PATCH"],
                   allow_headers=["Authorization", "Content-Type"])
for module in (auth, chat, incidents, realtime, health):
    app.include_router(module.router, prefix="/api/v1")
@app.get("/")
def root():
    return {"service": "SecureChat API", "version": "0.2.0"}
