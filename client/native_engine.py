"""
ctypes integration wrapper for CLICOM C Native Engine.

Maintains strict C ABI fidelity, maps error codes to Python exceptions,
guards against calls on destroyed handles, and exposes clean Pythonic models.
"""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import List, Optional

from client.config import (
    DEFAULT_CHANNELS,
    DEFAULT_DISPLAY_NAME,
    DEFAULT_MAX_PARTICIPANTS,
    DEFAULT_MAX_QUEUE_FRAMES,
    DEFAULT_SAMPLE_RATE,
    find_engine_dll,
)

# ── Buffer Size Constants from clicom.h ─────────────────────────────────────
CLICOM_MAX_NAME_LEN = 64
CLICOM_MAX_ROOM_ID_LEN = 64
CLICOM_MAX_KEY_LEN = 64
CLICOM_MAX_UUID_LEN = 40
CLICOM_AUDIO_MAX_SAMPLES = 960


# ── Native Enums ───────────────────────────────────────────────────────────
class ClicomError(IntEnum):
    OK = 0
    ERR_GENERIC = -1
    ERR_INVALID_ARG = -2
    ERR_NULL_POINTER = -3
    ERR_NOT_INITIALIZED = -4
    ERR_ALREADY_INITIALIZED = -5
    ERR_BUFFER_TOO_SMALL = -6
    ERR_INVALID_STATE = -7
    ERR_QUEUE_FULL = -8
    ERR_QUEUE_EMPTY = -9
    ERR_NOT_FOUND = -10
    ERR_OUT_OF_MEMORY = -11
    ERR_LIMIT_REACHED = -12
    ERR_SHUTDOWN = -13
    ERR_NETWORK_DISCONNECTED = -14
    ERR_CONNECTION_FAILED = -15
    ERR_UNAUTHORIZED = -16
    ERR_REVOKED = -17
    ERR_RATE_LIMITED = -18
    ERR_PTT_BUSY = -19
    ERR_AUDIO_DEVICE = -20


class ClicomEngineState(IntEnum):
    UNINITIALIZED = 0
    INITIALIZING = 1
    RUNNING = 2
    STOPPING = 3
    SHUTDOWN = 4


class ClicomRoomJoinState(IntEnum):
    DISCONNECTED = 0
    JOINING = 1
    JOINED = 2
    LEAVING = 3


class ClicomConnectionState(IntEnum):
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    RECONNECTING = 3
    FAILED = 4


class ClicomAudioEngineState(IntEnum):
    STOPPED = 0
    STARTING = 1
    RUNNING = 2
    PAUSED = 3
    ERROR = 4


# ── Exception Classes ──────────────────────────────────────────────────────
class NativeEngineError(Exception):
    """Base exception for native engine errors."""
    pass


class DllNotFoundError(NativeEngineError):
    """Raised when the native DLL cannot be located."""
    pass


class EngineClosedError(NativeEngineError):
    """Raised when an operation is performed on a closed/destroyed engine handle."""
    pass


class NativeCallError(NativeEngineError):
    """Raised when a native C API call returns an error code."""

    def __init__(self, error_code: int, message: str):
        super().__init__(f"C Error [{error_code}]: {message}")
        self.error_code = error_code
        self.error_message = message

    @property
    def code(self) -> int:
        return self.error_code


# ── ctypes C-Structures ────────────────────────────────────────────────────
class ClicomConfig(ctypes.Structure):
    _fields_ = [
        ("client_display_name", ctypes.c_char_p),
        ("max_audio_queue_frames", ctypes.c_uint32),
        ("max_participants", ctypes.c_uint32),
        ("audio_sample_rate", ctypes.c_uint32),
        ("audio_channels", ctypes.c_uint8),
    ]


class ClicomEngineStatus(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_int32),
        ("uptime_ms", ctypes.c_uint64),
        ("active_participants", ctypes.c_uint32),
        ("is_audio_running", ctypes.c_bool),
        ("is_mic_muted", ctypes.c_bool),
        ("is_ptt_active", ctypes.c_bool),
    ]


class ClicomMicState(ctypes.Structure):
    _fields_ = [
        ("is_muted", ctypes.c_bool),
        ("is_ptt_active", ctypes.c_bool),
        ("gain", ctypes.c_float),
    ]


class ClicomRoomState(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_int32),
        ("room_id", ctypes.c_char * CLICOM_MAX_ROOM_ID_LEN),
        ("join_key", ctypes.c_char * CLICOM_MAX_KEY_LEN),
        ("active_speaker_id", ctypes.c_char * CLICOM_MAX_UUID_LEN),
        ("participant_count", ctypes.c_uint32),
    ]


class ClicomParticipant(ctypes.Structure):
    _fields_ = [
        ("participant_id", ctypes.c_char * CLICOM_MAX_UUID_LEN),
        ("display_name", ctypes.c_char * CLICOM_MAX_NAME_LEN),
        ("is_speaking", ctypes.c_bool),
        ("is_muted", ctypes.c_bool),
        ("joined_at_ms", ctypes.c_uint64),
    ]


class ClicomTelemetrySnapshot(ctypes.Structure):
    _fields_ = [
        ("conn_state", ctypes.c_int32),
        ("rtt_ms", ctypes.c_uint32),
        ("packet_loss_pct", ctypes.c_float),
        ("bytes_sent", ctypes.c_uint64),
        ("bytes_received", ctypes.c_uint64),
        ("frames_sent", ctypes.c_uint64),
        ("frames_received", ctypes.c_uint64),
        ("frames_dropped", ctypes.c_uint64),
        ("jitter_ms", ctypes.c_float),
        ("timestamp_ms", ctypes.c_uint64),
    ]


class ClicomAudioFrame(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("sample_rate", ctypes.c_uint32),
        ("channels", ctypes.c_uint8),
        ("num_samples", ctypes.c_uint16),
        ("pcm_data", ctypes.c_int16 * CLICOM_AUDIO_MAX_SAMPLES),
    ]


class ClicomAudioStatus(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_int32),
        ("sample_rate", ctypes.c_uint32),
        ("channels", ctypes.c_uint8),
        ("capture_queue_depth", ctypes.c_uint32),
        ("capture_queue_capacity", ctypes.c_uint32),
        ("playback_queue_depth", ctypes.c_uint32),
        ("playback_queue_capacity", ctypes.c_uint32),
        ("total_frames_pushed", ctypes.c_uint64),
        ("total_frames_popped", ctypes.c_uint64),
        ("total_frames_dropped", ctypes.c_uint64),
    ]


# ── Python High-Level Data Classes ─────────────────────────────────────────
@dataclass
class EngineStatus:
    state: ClicomEngineState
    uptime_ms: int
    active_participants: int
    is_audio_running: bool
    is_mic_muted: bool
    is_ptt_active: bool


@dataclass
class MicState:
    is_muted: bool
    is_ptt_active: bool
    gain: float


@dataclass
class RoomState:
    state: ClicomRoomJoinState
    room_id: str
    join_key: str
    active_speaker_id: str
    participant_count: int


@dataclass
class Participant:
    participant_id: str
    display_name: str
    is_speaking: bool
    is_muted: bool
    joined_at_ms: int


@dataclass
class TelemetrySnapshot:
    conn_state: ClicomConnectionState
    rtt_ms: int
    packet_loss_pct: float
    bytes_sent: int
    bytes_received: int
    frames_sent: int
    frames_received: int
    frames_dropped: int
    jitter_ms: float
    timestamp_ms: int


@dataclass
class AudioStatus:
    state: ClicomAudioEngineState
    sample_rate: int
    channels: int
    capture_queue_depth: int
    capture_queue_capacity: int
    playback_queue_depth: int
    playback_queue_capacity: int
    total_frames_pushed: int
    total_frames_popped: int
    total_frames_dropped: int


# ── Native Engine Wrapper ──────────────────────────────────────────────────
class NativeEngine:
    """
    Python ctypes wrapper for the compiled CLICOM native C engine.
    Ensures safe initialization, shutdown, and type validation.
    """

    def __init__(self, dll_path: Optional[str | Path] = None, display_name: str = DEFAULT_DISPLAY_NAME):
        self._dll_path: Path = Path(dll_path) if dll_path else self._resolve_dll()
        self._lib = self._load_and_bind_dll(self._dll_path)
        self._handle: Optional[ctypes.c_void_p] = None
        self._display_name: str = display_name
        self._is_initialized: bool = False

    @staticmethod
    def _resolve_dll() -> Path:
        try:
            return find_engine_dll()
        except FileNotFoundError as e:
            raise DllNotFoundError(str(e)) from e

    def _load_and_bind_dll(self, path: Path) -> ctypes.CDLL:
        if not path.is_file():
            raise DllNotFoundError(f"DLL path does not exist: {path}")

        if hasattr(os, "add_dll_directory"):
            for dll_dir in [str(path.parent), r"C:\msys64\ucrt64\bin", r"C:\msys64\mingw64\bin"]:
                if os.path.isdir(dll_dir):
                    try:
                        os.add_dll_directory(dll_dir)
                    except OSError:
                        pass

        try:
            lib = ctypes.CDLL(str(path))
        except OSError as e:
            raise DllNotFoundError(
                f"Failed to load native library '{path}'.\nError details: {e}"
            ) from e

        # Bind all function signatures
        lib.clicom_get_version.restype = ctypes.c_uint32
        lib.clicom_get_version.argtypes = []

        lib.clicom_get_version_string.restype = ctypes.c_char_p
        lib.clicom_get_version_string.argtypes = []

        lib.clicom_error_string.restype = ctypes.c_char_p
        lib.clicom_error_string.argtypes = [ctypes.c_int32]

        lib.clicom_engine_create.restype = ctypes.c_int32
        lib.clicom_engine_create.argtypes = [ctypes.POINTER(ctypes.c_void_p)]

        lib.clicom_engine_init.restype = ctypes.c_int32
        lib.clicom_engine_init.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomConfig)]

        lib.clicom_engine_shutdown.restype = ctypes.c_int32
        lib.clicom_engine_shutdown.argtypes = [ctypes.c_void_p]

        lib.clicom_engine_destroy.restype = None
        lib.clicom_engine_destroy.argtypes = [ctypes.c_void_p]

        lib.clicom_engine_get_status.restype = ctypes.c_int32
        lib.clicom_engine_get_status.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomEngineStatus)]

        lib.clicom_set_display_name.restype = ctypes.c_int32
        lib.clicom_set_display_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        lib.clicom_get_display_name.restype = ctypes.c_int32
        lib.clicom_get_display_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]

        lib.clicom_set_mic_muted.restype = ctypes.c_int32
        lib.clicom_set_mic_muted.argtypes = [ctypes.c_void_p, ctypes.c_bool]

        lib.clicom_is_mic_muted.restype = ctypes.c_int32
        lib.clicom_is_mic_muted.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_bool)]

        lib.clicom_set_ptt_active.restype = ctypes.c_int32
        lib.clicom_set_ptt_active.argtypes = [ctypes.c_void_p, ctypes.c_bool]

        lib.clicom_is_ptt_active.restype = ctypes.c_int32
        lib.clicom_is_ptt_active.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_bool)]

        lib.clicom_set_mic_gain.restype = ctypes.c_int32
        lib.clicom_set_mic_gain.argtypes = [ctypes.c_void_p, ctypes.c_float]

        lib.clicom_get_mic_gain.restype = ctypes.c_int32
        lib.clicom_get_mic_gain.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_float)]

        lib.clicom_get_mic_state.restype = ctypes.c_int32
        lib.clicom_get_mic_state.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomMicState)]

        lib.clicom_room_join.restype = ctypes.c_int32
        lib.clicom_room_join.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

        lib.clicom_room_leave.restype = ctypes.c_int32
        lib.clicom_room_leave.argtypes = [ctypes.c_void_p]

        lib.clicom_get_room_state.restype = ctypes.c_int32
        lib.clicom_get_room_state.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomRoomState)]

        lib.clicom_participant_add.restype = ctypes.c_int32
        lib.clicom_participant_add.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomParticipant)]

        lib.clicom_participant_remove.restype = ctypes.c_int32
        lib.clicom_participant_remove.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        lib.clicom_get_participant_count.restype = ctypes.c_int32
        lib.clicom_get_participant_count.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]

        lib.clicom_get_participants.restype = ctypes.c_int32
        lib.clicom_get_participants.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ClicomParticipant),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]

        lib.clicom_get_participant_by_id.restype = ctypes.c_int32
        lib.clicom_get_participant_by_id.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(ClicomParticipant),
        ]

        lib.clicom_get_connection_state.restype = ctypes.c_int32
        lib.clicom_get_connection_state.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32)]

        lib.clicom_set_connection_state.restype = ctypes.c_int32
        lib.clicom_set_connection_state.argtypes = [ctypes.c_void_p, ctypes.c_int32]

        lib.clicom_get_telemetry.restype = ctypes.c_int32
        lib.clicom_get_telemetry.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomTelemetrySnapshot)]

        lib.clicom_update_telemetry.restype = ctypes.c_int32
        lib.clicom_update_telemetry.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomTelemetrySnapshot)]

        lib.clicom_audio_start.restype = ctypes.c_int32
        lib.clicom_audio_start.argtypes = [ctypes.c_void_p]

        lib.clicom_audio_stop.restype = ctypes.c_int32
        lib.clicom_audio_stop.argtypes = [ctypes.c_void_p]

        lib.clicom_get_audio_status.restype = ctypes.c_int32
        lib.clicom_get_audio_status.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomAudioStatus)]

        lib.clicom_audio_queue_push_capture.restype = ctypes.c_int32
        lib.clicom_audio_queue_push_capture.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomAudioFrame)]

        lib.clicom_audio_queue_pop_capture.restype = ctypes.c_int32
        lib.clicom_audio_queue_pop_capture.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomAudioFrame)]

        lib.clicom_audio_queue_push_playback.restype = ctypes.c_int32
        lib.clicom_audio_queue_push_playback.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomAudioFrame)]

        lib.clicom_audio_queue_pop_playback.restype = ctypes.c_int32
        lib.clicom_audio_queue_pop_playback.argtypes = [ctypes.c_void_p, ctypes.POINTER(ClicomAudioFrame)]

        lib.clicom_audio_queue_clear.restype = ctypes.c_int32
        lib.clicom_audio_queue_clear.argtypes = [ctypes.c_void_p]

        lib.clicom_audio_set_mock_backend.restype = ctypes.c_int32
        lib.clicom_audio_set_mock_backend.argtypes = [ctypes.c_void_p, ctypes.c_bool]

        lib.clicom_audio_get_backend.restype = ctypes.c_int32
        lib.clicom_audio_get_backend.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_bool)]

        lib.clicom_audio_get_device_counts.restype = ctypes.c_int32
        lib.clicom_audio_get_device_counts.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]

        lib.clicom_get_floor_status.restype = ctypes.c_int32
        lib.clicom_get_floor_status.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_bool),
            ctypes.POINTER(ctypes.c_bool),
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]

        lib.clicom_network_refresh_participants.restype = ctypes.c_int32
        lib.clicom_network_refresh_participants.argtypes = [ctypes.c_void_p]

        lib.clicom_get_active_session_id.restype = ctypes.c_int32
        lib.clicom_get_active_session_id.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]

        # Network API (Phase 2A)
        lib.clicom_network_connect.restype = ctypes.c_int32
        lib.clicom_network_connect.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint16, ctypes.c_char_p]

        lib.clicom_network_disconnect.restype = ctypes.c_int32
        lib.clicom_network_disconnect.argtypes = [ctypes.c_void_p]

        lib.clicom_is_network_connected.restype = ctypes.c_int32
        lib.clicom_is_network_connected.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_bool)]

        lib.clicom_network_poll.restype = ctypes.c_int32
        lib.clicom_network_poll.argtypes = [ctypes.c_void_p, ctypes.c_int32]

        lib.clicom_network_create_room.restype = ctypes.c_int32
        lib.clicom_network_create_room.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]

        lib.clicom_network_join_room.restype = ctypes.c_int32
        lib.clicom_network_join_room.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]

        lib.clicom_network_leave_room.restype = ctypes.c_int32
        lib.clicom_network_leave_room.argtypes = [ctypes.c_void_p]

        lib.clicom_network_revoke_invitation.restype = ctypes.c_int32
        lib.clicom_network_revoke_invitation.argtypes = [ctypes.c_void_p]

        lib.clicom_network_close_room.restype = ctypes.c_int32
        lib.clicom_network_close_room.argtypes = [ctypes.c_void_p]

        return lib

    def _check_call(self, return_code: int) -> None:
        """Evaluate native return code and raise NativeCallError on failure."""
        if return_code != ClicomError.OK:
            msg_bytes = self._lib.clicom_error_string(return_code)
            msg = msg_bytes.decode("utf-8", errors="replace") if msg_bytes else "Unknown error"
            raise NativeCallError(return_code, msg)

    def _ensure_active(self) -> ctypes.c_void_p:
        """Validate that the engine handle is open and not destroyed."""
        if self._handle is None:
            raise EngineClosedError("Native engine handle is NULL or has been destroyed.")
        return self._handle

    # ── Version and Metadata ────────────────────────────────────────────────
    def get_version(self) -> int:
        return self._lib.clicom_get_version()

    def get_version_string(self) -> str:
        res = self._lib.clicom_get_version_string()
        return res.decode("utf-8") if res else ""

    def get_error_string(self, error_code: int) -> str:
        res = self._lib.clicom_error_string(error_code)
        return res.decode("utf-8") if res else "Unknown error"

    # ── Engine Lifecycle ────────────────────────────────────────────────────
    def init(
        self,
        display_name: Optional[str] = None,
        max_queue_frames: int = DEFAULT_MAX_QUEUE_FRAMES,
        max_participants: int = DEFAULT_MAX_PARTICIPANTS,
        sample_rate: int = DEFAULT_SAMPLE_RATE,
        channels: int = DEFAULT_CHANNELS,
    ) -> None:
        """Create and initialize the native engine instance."""
        if self._handle is not None and self._is_initialized:
            return

        handle = ctypes.c_void_p()
        rc = self._lib.clicom_engine_create(ctypes.byref(handle))
        self._check_call(rc)
        self._handle = handle

        name_to_use = display_name or self._display_name
        cfg = ClicomConfig()
        cfg.client_display_name = name_to_use.encode("utf-8")
        cfg.max_audio_queue_frames = max_queue_frames
        cfg.max_participants = max_participants
        cfg.audio_sample_rate = sample_rate
        cfg.audio_channels = channels

        rc = self._lib.clicom_engine_init(self._handle, ctypes.byref(cfg))
        self._check_call(rc)
        self._is_initialized = True
        self._display_name = name_to_use

    def shutdown(self) -> None:
        """Gracefully shut down the engine state."""
        if self._handle is not None and self._is_initialized:
            rc = self._lib.clicom_engine_shutdown(self._handle)
            self._check_call(rc)
            self._is_initialized = False

    def destroy(self) -> None:
        """Destroy the engine handle and free native resources."""
        if self._handle is not None:
            self._lib.clicom_engine_destroy(self._handle)
            self._handle = None
            self._is_initialized = False

    def __enter__(self) -> NativeEngine:
        self.init()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.destroy()

    @property
    def is_alive(self) -> bool:
        return self._handle is not None and self._is_initialized

    # ── Status and Display Name ─────────────────────────────────────────────
    def get_status(self) -> EngineStatus:
        handle = self._ensure_active()
        status = ClicomEngineStatus()
        rc = self._lib.clicom_engine_get_status(handle, ctypes.byref(status))
        self._check_call(rc)
        return EngineStatus(
            state=ClicomEngineState(status.state),
            uptime_ms=status.uptime_ms,
            active_participants=status.active_participants,
            is_audio_running=status.is_audio_running,
            is_mic_muted=status.is_mic_muted,
            is_ptt_active=status.is_ptt_active,
        )

    def get_display_name(self) -> str:
        handle = self._ensure_active()
        buf = ctypes.create_string_buffer(CLICOM_MAX_NAME_LEN)
        rc = self._lib.clicom_get_display_name(handle, buf, len(buf))
        self._check_call(rc)
        self._display_name = buf.value.decode("utf-8")
        return self._display_name

    def set_display_name(self, name: str) -> None:
        handle = self._ensure_active()
        encoded = name.strip().encode("utf-8")
        rc = self._lib.clicom_set_display_name(handle, encoded)
        self._check_call(rc)
        self._display_name = name.strip()

    # ── Local Microphone & PTT ──────────────────────────────────────────────
    def set_mic_muted(self, muted: bool) -> None:
        handle = self._ensure_active()
        rc = self._lib.clicom_set_mic_muted(handle, muted)
        self._check_call(rc)

    def is_mic_muted(self) -> bool:
        handle = self._ensure_active()
        muted = ctypes.c_bool()
        rc = self._lib.clicom_is_mic_muted(handle, ctypes.byref(muted))
        self._check_call(rc)
        return muted.value

    def set_ptt_active(self, active: bool) -> None:
        handle = self._ensure_active()
        rc = self._lib.clicom_set_ptt_active(handle, active)
        self._check_call(rc)

    def is_ptt_active(self) -> bool:
        handle = self._ensure_active()
        active = ctypes.c_bool()
        rc = self._lib.clicom_is_ptt_active(handle, ctypes.byref(active))
        self._check_call(rc)
        return active.value

    def set_mic_gain(self, gain: float) -> None:
        handle = self._ensure_active()
        rc = self._lib.clicom_set_mic_gain(handle, ctypes.c_float(gain))
        self._check_call(rc)

    def get_mic_gain(self) -> float:
        handle = self._ensure_active()
        gain = ctypes.c_float()
        rc = self._lib.clicom_get_mic_gain(handle, ctypes.byref(gain))
        self._check_call(rc)
        return float(gain.value)

    def get_mic_state(self) -> MicState:
        handle = self._ensure_active()
        state = ClicomMicState()
        rc = self._lib.clicom_get_mic_state(handle, ctypes.byref(state))
        self._check_call(rc)
        return MicState(
            is_muted=state.is_muted,
            is_ptt_active=state.is_ptt_active,
            gain=float(state.gain),
        )

    # ── Room and Participant Management ─────────────────────────────────────
    def room_join(self, room_id: str, join_key: str = "") -> None:
        handle = self._ensure_active()
        r_id = room_id.strip().encode("utf-8")
        j_key = join_key.strip().encode("utf-8") if join_key else None
        rc = self._lib.clicom_room_join(handle, r_id, j_key)
        self._check_call(rc)

    def room_leave(self) -> None:
        handle = self._ensure_active()
        rc = self._lib.clicom_room_leave(handle)
        self._check_call(rc)

    def get_room_state(self) -> RoomState:
        handle = self._ensure_active()
        state = ClicomRoomState()
        rc = self._lib.clicom_get_room_state(handle, ctypes.byref(state))
        self._check_call(rc)
        return RoomState(
            state=ClicomRoomJoinState(state.state),
            room_id=state.room_id.decode("utf-8", errors="replace"),
            join_key=state.join_key.decode("utf-8", errors="replace"),
            active_speaker_id=state.active_speaker_id.decode("utf-8", errors="replace"),
            participant_count=state.participant_count,
        )

    def participant_add(
        self,
        participant_id: str,
        display_name: str,
        is_speaking: bool = False,
        is_muted: bool = False,
    ) -> None:
        handle = self._ensure_active()
        p = ClicomParticipant()
        p.participant_id = participant_id.encode("utf-8")
        p.display_name = display_name.encode("utf-8")
        p.is_speaking = is_speaking
        p.is_muted = is_muted
        p.joined_at_ms = 0
        rc = self._lib.clicom_participant_add(handle, ctypes.byref(p))
        self._check_call(rc)

    def participant_remove(self, participant_id: str) -> None:
        handle = self._ensure_active()
        rc = self._lib.clicom_participant_remove(handle, participant_id.encode("utf-8"))
        self._check_call(rc)

    def get_participant_count(self) -> int:
        handle = self._ensure_active()
        count = ctypes.c_uint32()
        rc = self._lib.clicom_get_participant_count(handle, ctypes.byref(count))
        self._check_call(rc)
        return count.value

    def get_participants(self, max_count: int = 64) -> List[Participant]:
        handle = self._ensure_active()
        array_type = ClicomParticipant * max_count
        buf = array_type()
        actual = ctypes.c_uint32()

        rc = self._lib.clicom_get_participants(handle, buf, max_count, ctypes.byref(actual))
        # Handle buffer size check
        if rc != ClicomError.OK and rc != ClicomError.ERR_BUFFER_TOO_SMALL:
            self._check_call(rc)

        items: List[Participant] = []
        for i in range(actual.value):
            raw = buf[i]
            items.append(
                Participant(
                    participant_id=raw.participant_id.decode("utf-8", errors="replace"),
                    display_name=raw.display_name.decode("utf-8", errors="replace"),
                    is_speaking=raw.is_speaking,
                    is_muted=raw.is_muted,
                    joined_at_ms=raw.joined_at_ms,
                )
            )
        return items

    def get_participant_by_id(self, participant_id: str) -> Optional[Participant]:
        handle = self._ensure_active()
        raw = ClicomParticipant()
        rc = self._lib.clicom_get_participant_by_id(handle, participant_id.encode("utf-8"), ctypes.byref(raw))
        if rc == ClicomError.ERR_NOT_FOUND:
            return None
        self._check_call(rc)
        return Participant(
            participant_id=raw.participant_id.decode("utf-8", errors="replace"),
            display_name=raw.display_name.decode("utf-8", errors="replace"),
            is_speaking=raw.is_speaking,
            is_muted=raw.is_muted,
            joined_at_ms=raw.joined_at_ms,
        )

    # ── Connection State & Telemetry ────────────────────────────────────────
    def get_connection_state(self) -> ClicomConnectionState:
        handle = self._ensure_active()
        state = ctypes.c_int32()
        rc = self._lib.clicom_get_connection_state(handle, ctypes.byref(state))
        self._check_call(rc)
        return ClicomConnectionState(state.value)

    def set_connection_state(self, state: ClicomConnectionState) -> None:
        handle = self._ensure_active()
        rc = self._lib.clicom_set_connection_state(handle, int(state))
        self._check_call(rc)

    def get_telemetry(self) -> TelemetrySnapshot:
        handle = self._ensure_active()
        snap = ClicomTelemetrySnapshot()
        rc = self._lib.clicom_get_telemetry(handle, ctypes.byref(snap))
        self._check_call(rc)
        return TelemetrySnapshot(
            conn_state=ClicomConnectionState(snap.conn_state),
            rtt_ms=snap.rtt_ms,
            packet_loss_pct=float(snap.packet_loss_pct),
            bytes_sent=snap.bytes_sent,
            bytes_received=snap.bytes_received,
            frames_sent=snap.frames_sent,
            frames_received=snap.frames_received,
            frames_dropped=snap.frames_dropped,
            jitter_ms=float(snap.jitter_ms),
            timestamp_ms=snap.timestamp_ms,
        )

    def update_telemetry(self, snapshot: TelemetrySnapshot) -> None:
        handle = self._ensure_active()
        raw = ClicomTelemetrySnapshot()
        raw.conn_state = int(snapshot.conn_state)
        raw.rtt_ms = snapshot.rtt_ms
        raw.packet_loss_pct = ctypes.c_float(snapshot.packet_loss_pct)
        raw.bytes_sent = snapshot.bytes_sent
        raw.bytes_received = snapshot.bytes_received
        raw.frames_sent = snapshot.frames_sent
        raw.frames_received = snapshot.frames_received
        raw.frames_dropped = snapshot.frames_dropped
        raw.jitter_ms = ctypes.c_float(snapshot.jitter_ms)
        raw.timestamp_ms = snapshot.timestamp_ms
        rc = self._lib.clicom_update_telemetry(handle, ctypes.byref(raw))
        self._check_call(rc)

    # ── Audio Subsystem ─────────────────────────────────────────────────────
    def audio_start(self) -> None:
        handle = self._ensure_active()
        rc = self._lib.clicom_audio_start(handle)
        self._check_call(rc)

    def audio_stop(self) -> None:
        handle = self._ensure_active()
        rc = self._lib.clicom_audio_stop(handle)
        self._check_call(rc)

    def get_audio_status(self) -> AudioStatus:
        handle = self._ensure_active()
        raw = ClicomAudioStatus()
        rc = self._lib.clicom_get_audio_status(handle, ctypes.byref(raw))
        self._check_call(rc)
        return AudioStatus(
            state=ClicomAudioEngineState(raw.state),
            sample_rate=raw.sample_rate,
            channels=raw.channels,
            capture_queue_depth=raw.capture_queue_depth,
            capture_queue_capacity=raw.capture_queue_capacity,
            playback_queue_depth=raw.playback_queue_depth,
            playback_queue_capacity=raw.playback_queue_capacity,
            total_frames_pushed=raw.total_frames_pushed,
            total_frames_popped=raw.total_frames_popped,
            total_frames_dropped=raw.total_frames_dropped,
        )

    def audio_queue_clear(self) -> None:
        handle = self._ensure_active()
        rc = self._lib.clicom_audio_queue_clear(handle)
        self._check_call(rc)

    def audio_set_mock_backend(self, use_mock: bool = True) -> None:
        """Configure engine to use in-memory mock audio backend rather than hardware."""
        handle = self._ensure_active()
        rc = self._lib.clicom_audio_set_mock_backend(handle, ctypes.c_bool(use_mock))
        self._check_call(rc)

    def get_active_session_id(self) -> str:
        """Retrieve current active room session UUID string."""
        handle = self._ensure_active()
        buf = ctypes.create_string_buffer(CLICOM_MAX_UUID_LEN)
        rc = self._lib.clicom_get_active_session_id(handle, buf, ctypes.c_size_t(CLICOM_MAX_UUID_LEN))
        self._check_call(rc)
        return buf.value.decode("utf-8", errors="replace")

    def audio_get_backend(self) -> tuple[int, bool]:
        """Query active audio backend (backend_type, is_mock)."""
        handle = self._ensure_active()
        backend = ctypes.c_int32(0)
        is_mock = ctypes.c_bool(False)
        rc = self._lib.clicom_audio_get_backend(handle, ctypes.byref(backend), ctypes.byref(is_mock))
        self._check_call(rc)
        return int(backend.value), bool(is_mock.value)

    def audio_get_device_counts(self) -> tuple[int, int]:
        """Query physical input and output audio devices detected on the host."""
        handle = self._ensure_active()
        inputs = ctypes.c_uint32(0)
        outputs = ctypes.c_uint32(0)
        rc = self._lib.clicom_audio_get_device_counts(handle, ctypes.byref(inputs), ctypes.byref(outputs))
        self._check_call(rc)
        return int(inputs.value), int(outputs.value)

    def get_floor_status(self) -> tuple[bool, bool, str]:
        """Query server-authoritative PTT floor status (is_held, is_held_by_me, holder_id_or_name)."""
        handle = self._ensure_active()
        is_held = ctypes.c_bool(False)
        held_by_me = ctypes.c_bool(False)
        holder_buf = ctypes.create_string_buffer(CLICOM_MAX_UUID_LEN)
        rc = self._lib.clicom_get_floor_status(
            handle,
            ctypes.byref(is_held),
            ctypes.byref(held_by_me),
            holder_buf,
            ctypes.c_size_t(CLICOM_MAX_UUID_LEN),
        )
        self._check_call(rc)
        holder_str = holder_buf.value.decode("utf-8", errors="replace")
        return bool(is_held.value), bool(held_by_me.value), holder_str

    def network_refresh_participants(self) -> None:
        """Refresh local room participants table from the server."""
        handle = self._ensure_active()
        rc = self._lib.clicom_network_refresh_participants(handle)
        self._check_call(rc)

    # ── Network Engine Operations (Phase 2A) ────────────────────────────────
    def network_connect(
        self,
        host: str = "127.0.0.1",
        port: int = 8443,
        ca_cert_path: Optional[str] = None,
    ) -> None:
        """Connect to CLICOM server over TLS 1.3."""
        handle = self._ensure_active()
        ca_bytes = ca_cert_path.encode("utf-8") if ca_cert_path else None
        rc = self._lib.clicom_network_connect(
            handle,
            host.encode("utf-8"),
            ctypes.c_uint16(port),
            ca_bytes,
        )
        self._check_call(rc)

    def network_disconnect(self) -> None:
        """Disconnect from CLICOM server."""
        handle = self._ensure_active()
        rc = self._lib.clicom_network_disconnect(handle)
        self._check_call(rc)

    def is_network_connected(self) -> bool:
        """Query if currently connected to a server."""
        handle = self._ensure_active()
        connected = ctypes.c_bool(False)
        rc = self._lib.clicom_is_network_connected(handle, ctypes.byref(connected))
        self._check_call(rc)
        return bool(connected.value)

    def network_poll(self, timeout_ms: int = 0) -> None:
        """Poll incoming frames and heartbeat pings."""
        handle = self._ensure_active()
        rc = self._lib.clicom_network_poll(handle, ctypes.c_int32(timeout_ms))
        self._check_call(rc)

    def network_create_room(
        self,
        room_name: str,
        member_limit: int = 16,
    ) -> tuple[str, str]:
        """Create a server-authoritative room with participant limit. Returns (room_id, join_key)."""
        handle = self._ensure_active()
        room_id_buf = ctypes.create_string_buffer(CLICOM_MAX_ROOM_ID_LEN)
        key_buf = ctypes.create_string_buffer(CLICOM_MAX_KEY_LEN)
        rc = self._lib.clicom_network_create_room(
            handle,
            room_name.encode("utf-8"),
            ctypes.c_uint32(member_limit),
            room_id_buf,
            ctypes.c_size_t(CLICOM_MAX_ROOM_ID_LEN),
            key_buf,
            ctypes.c_size_t(CLICOM_MAX_KEY_LEN),
        )
        self._check_call(rc)
        return (
            room_id_buf.value.decode("utf-8", errors="replace"),
            key_buf.value.decode("utf-8", errors="replace"),
        )

    def network_join_room(self, join_key: str) -> tuple[str, str]:
        """Join a room on the server via invitation key. Returns (room_id, room_name)."""
        handle = self._ensure_active()
        room_id_buf = ctypes.create_string_buffer(CLICOM_MAX_ROOM_ID_LEN)
        name_buf = ctypes.create_string_buffer(CLICOM_MAX_NAME_LEN)
        rc = self._lib.clicom_network_join_room(
            handle,
            join_key.encode("utf-8"),
            room_id_buf,
            ctypes.c_size_t(CLICOM_MAX_ROOM_ID_LEN),
            name_buf,
            ctypes.c_size_t(CLICOM_MAX_NAME_LEN),
        )
        self._check_call(rc)
        return (
            room_id_buf.value.decode("utf-8", errors="replace"),
            name_buf.value.decode("utf-8", errors="replace"),
        )

    def network_leave_room(self) -> None:
        """Leave current server-managed room."""
        handle = self._ensure_active()
        rc = self._lib.clicom_network_leave_room(handle)
        self._check_call(rc)

    def network_revoke_invitation(self) -> None:
        """Revoke current room's invitation key (owner-only)."""
        handle = self._ensure_active()
        rc = self._lib.clicom_network_revoke_invitation(handle)
        self._check_call(rc)

    def network_close_room(self) -> None:
        """Close and destroy current room on server (owner-only)."""
        handle = self._ensure_active()
        rc = self._lib.clicom_network_close_room(handle)
        self._check_call(rc)
