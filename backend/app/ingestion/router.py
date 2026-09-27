from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from .extractor import extract_flows
from .validator import PcapValidationError, validate_pcap_file

router = APIRouter(prefix="/api/pcap", tags=["ingestion"])

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


@router.post("/upload")
async def upload_pcap(file: UploadFile = File(...)) -> dict:
    suffix = Path(file.filename or "capture.pcap").suffix or ".pcap"

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = Path(tmp.name)
        size = 0

        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="Capture exceeds 200MB limit")
            tmp.write(chunk)

    try:
        validation = validate_pcap_file(tmp_path)
        extraction = extract_flows(tmp_path)
    except PcapValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        tmp_path.unlink(missing_ok=True)

    return {
        "filename": file.filename,
        "format": validation.file_format,
        "size_bytes": validation.size_bytes,
        **extraction.to_dict(),
    }
