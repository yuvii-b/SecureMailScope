from fastapi import FastAPI

from app.ingestion.router import router as ingestion_router
from app.reassembly.router import router as reassembly_router

app = FastAPI(title="SecureMailScope API", version="0.1.0")
app.include_router(ingestion_router)
app.include_router(reassembly_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
