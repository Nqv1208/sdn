import json
import time
from pathlib import Path


STATE_FILE = Path(__file__).resolve().parent / "controller_state.json"
STATE_FILE.parent.mkdir(parents=True, exist_ok=True)


def _safe_write(data: dict) -> None:
    tmp_file = STATE_FILE.with_suffix(".tmp")
    with tmp_file.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    tmp_file.replace(STATE_FILE)


def persist_controller_state(snapshot: dict) -> None:
    """Persist latest controller snapshot for external consumers."""
    snapshot = snapshot or {}
    snapshot["updated_at"] = time.time()
    _safe_write(snapshot)


def read_latest_state() -> dict:
    """Return latest snapshot; fallback to defaults when empty."""
    if not STATE_FILE.exists():
        return {}

    try:
        with STATE_FILE.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError:
        # Partial write - ignore and return empty to keep API responsive
        return {}

