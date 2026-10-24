"""Configuration and environment management for Ghost Data Still Exists."""

from __future__ import annotations

import csv
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# Base directory paths
REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"
OUTPUT_PATH = REPO_ROOT / "output.csv"
EVAL_DIR = REPO_ROOT / "evaluation"

# Logging configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger with standard formatting."""
    return logging.getLogger(name)


def load_csv(path: Path) -> List[Dict[str, str]]:
    """Safely load a CSV file into a list of dictionaries with UTF-8 sig encoding."""
    if not path.exists():
        raise FileNotFoundError(f"Required CSV not found: {path}")
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_dt(iso_str: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp string into a datetime object."""
    if not iso_str:
        return None
    s = iso_str.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def before_or_equal(timestamp: str, cutoff: str) -> bool:
    """Return True if timestamp is chronologically <= cutoff; True if either unparseable."""
    dt_a = parse_dt(timestamp)
    dt_b = parse_dt(cutoff)
    if dt_a is None or dt_b is None:
        return True
    return dt_a <= dt_b
