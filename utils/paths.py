"""Fixed project paths (used by the lab, the dashboard and the tests)."""
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LAB_DIR = PROJECT_ROOT / "lab"
CERT_DIR = LAB_DIR / "certificates"
LAB_CA_PATH = CERT_DIR / "root_ca.pem"
