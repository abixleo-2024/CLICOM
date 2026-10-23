"""
Configuration and DLL discovery for the CLICOM Python Client.
"""

import os
import sys
from pathlib import Path
from typing import List, Optional

DEFAULT_DISPLAY_NAME: str = "NODE-ALPHA"
DEFAULT_SAMPLE_RATE: int = 48000
DEFAULT_CHANNELS: int = 1
DEFAULT_MAX_QUEUE_FRAMES: int = 64
DEFAULT_MAX_PARTICIPANTS: int = 64


def get_project_root() -> Path:
    """Return the absolute path to the project root directory."""
    # Assuming config.py is located at <project_root>/client/config.py
    return Path(__file__).resolve().parent.parent


def get_candidate_dll_paths(explicit_path: Optional[str] = None) -> List[Path]:
    """Return list of candidate paths where libclicom_engine.dll might reside."""
    candidates: List[Path] = []

    if explicit_path:
        candidates.append(Path(explicit_path).resolve())

    env_path = os.environ.get("CLICOM_DLL_PATH")
    if env_path:
        candidates.append(Path(env_path).resolve())

    root = get_project_root()
    relative_candidates = [
        root / "build" / "windows-ninja-debug" / "engine" / "libclicom_engine.dll",
        root / "build" / "windows-ninja-debug" / "engine" / "clicom_engine.dll",
        root / "engine" / "build" / "libclicom_engine.dll",
        root / "engine" / "build" / "clicom_engine.dll",
        root / "dist" / "clicom-2.0.0-windows-x64" / "libclicom_engine.dll",
        root / "dist" / "clicom-2.0.0-windows-x64" / "clicom_engine.dll",
        root / "build" / "engine" / "libclicom_engine.dll",
        Path.cwd() / "libclicom_engine.dll",
        Path.cwd() / "clicom_engine.dll",
    ]

    for p in relative_candidates:
        if p not in candidates:
            candidates.append(p)

    return candidates


def find_engine_dll(explicit_path: Optional[str] = None) -> Path:
    """
    Search for the compiled native engine DLL in standard workspace locations.

    Raises:
        FileNotFoundError: If no candidate DLL file exists on disk.
    """
    candidates = get_candidate_dll_paths(explicit_path)
    for path in candidates:
        if path.is_file():
            return path

    searched = "\n  - ".join(str(p) for p in candidates)
    raise FileNotFoundError(
        f"CLICOM Native Engine DLL could not be located.\n"
        f"Searched paths:\n  - {searched}\n\n"
        f"Please build the native engine first using:\n"
        f"  scripts\\build_windows.bat\n"
        f"or set the CLICOM_DLL_PATH environment variable."
    )
