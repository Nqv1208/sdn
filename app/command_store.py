import json
import time
import uuid
from pathlib import Path
from typing import List, Dict, Any


COMMAND_FILE = Path(__file__).resolve().parent / "controller_commands.json"
COMMAND_FILE.parent.mkdir(parents=True, exist_ok=True)


def _read_commands() -> List[Dict[str, Any]]:
    if not COMMAND_FILE.exists():
        return []

    try:
        with COMMAND_FILE.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError:
        return []


def _write_commands(commands: List[Dict[str, Any]]) -> None:
    tmp_file = COMMAND_FILE.with_suffix(".tmp")
    with tmp_file.open("w", encoding="utf-8") as fh:
        json.dump(commands, fh, indent=2)
    tmp_file.replace(COMMAND_FILE)


def enqueue_command(command_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Append a command for the controller to process."""
    commands = _read_commands()
    command = {
        "id": str(uuid.uuid4()),
        "type": command_type,
        "payload": payload or {},
        "created_at": time.time(),
    }
    commands.append(command)
    _write_commands(commands)
    return command


def pop_all_commands() -> List[Dict[str, Any]]:
    """Return and clear outstanding commands."""
    commands = _read_commands()
    if commands:
        _write_commands([])
    return commands

