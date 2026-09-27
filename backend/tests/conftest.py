import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = PROJECT_ROOT / "securemail_test_pcaps"


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
