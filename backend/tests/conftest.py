import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = PROJECT_ROOT / "securemail_test_pcaps"

# Stage 7: point the app at a throwaway SQLite DB and uploads dir, and force Celery's
# eager mode, so the test suite stays a zero-external-service `pytest` run - no Postgres
# or Redis required. Must happen before `app.db`/`app.worker` are imported by any test
# module, since both read these env vars at import time. Deleted up front (not at exit)
# since the sqlite file is still open by the engine when the process exits on Windows.
_TEST_DB_PATH = Path(__file__).resolve().parent / ".test_securemailscope.db"
_TEST_UPLOAD_DIR = Path(__file__).resolve().parent / ".test_uploads"
_TEST_DB_PATH.unlink(missing_ok=True)
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_PATH}"
os.environ["UPLOAD_DIR"] = str(_TEST_UPLOAD_DIR)
os.environ.setdefault("CELERY_TASK_ALWAYS_EAGER", "true")

from app.db import init_db  # noqa: E402  (must follow the env var setup above)

init_db()


@pytest.fixture(scope="session")
def dataset_dir() -> Path:
    """Ensure genny.py's synthetic dataset exists, generating it if needed."""
    if not DATASET_DIR.exists() or not any(DATASET_DIR.glob("*.pcap")):
        subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "genny.py")],
            check=True,
            cwd=PROJECT_ROOT,
        )
    return DATASET_DIR
