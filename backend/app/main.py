from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.router import router as analyses_router
from app.db import init_db
from app.ingestion.router import router as ingestion_router
from app.reassembly.router import router as reassembly_router
from app.simulator.router import router as simulator_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="SecureMailScope API", version="0.1.0", lifespan=lifespan)
app.include_router(ingestion_router)
app.include_router(reassembly_router)
app.include_router(analyses_router)
app.include_router(simulator_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
