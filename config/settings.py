from pathlib import Path

# ==========================
# Project Directories
# ==========================

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
SCRIPTS_DIR = BASE_DIR / "scripts"

# ==========================
# Files
# ==========================

WINDOWS_LOG = DATA_DIR / "windows_security.csv"

CLASSIFIED_REPORT = REPORTS_DIR / "classified_events.csv"

BRUTE_FORCE_REPORT = REPORTS_DIR / "brute_force_report.csv"

IOC_REPORT = REPORTS_DIR / "ioc_report.csv"
