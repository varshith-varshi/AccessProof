"""Reuse the repository's hermetic test bootstrap (temp Guard cache, keys)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))
from tests.conftest import *  # noqa: E402,F401,F403
