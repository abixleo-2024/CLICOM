"""
Unit tests for ctypes bindings, struct declarations, error mapping, and DLL loading.
"""

import ctypes
import pytest
from pathlib import Path

from client.native_engine import (
    CLICOM_AUDIO_MAX_SAMPLES,
    CLICOM_MAX_KEY_LEN,
    CLICOM_MAX_NAME_LEN,
    CLICOM_MAX_ROOM_ID_LEN,
    CLICOM_MAX_UUID_LEN,
    ClicomAudioFrame,
    ClicomAudioStatus,
    ClicomConfig,
    ClicomEngineStatus,
    ClicomError,
    ClicomMicState,
    ClicomParticipant,
    ClicomRoomState,
    ClicomTelemetrySnapshot,
    DllNotFoundError,
    EngineClosedError,
    NativeCallError,
    NativeEngine,
)


def test_ctypes_struct_definitions():
    """Verify struct field counts and sizes match native definitions."""
    # Config
    assert len(ClicomConfig._fields_) == 5

    # Engine Status
    assert len(ClicomEngineStatus._fields_) == 6

    # Mic State
    assert len(ClicomMicState._fields_) == 3

    # Room State
    assert len(ClicomRoomState._fields_) == 5
    room_fields = dict(ClicomRoomState._fields_)
    assert ctypes.sizeof(room_fields["room_id"]) == CLICOM_MAX_ROOM_ID_LEN
    assert ctypes.sizeof(room_fields["join_key"]) == CLICOM_MAX_KEY_LEN
    assert ctypes.sizeof(room_fields["active_speaker_id"]) == CLICOM_MAX_UUID_LEN

    # Participant
    assert len(ClicomParticipant._fields_) == 5
    part_fields = dict(ClicomParticipant._fields_)
    assert ctypes.sizeof(part_fields["participant_id"]) == CLICOM_MAX_UUID_LEN
    assert ctypes.sizeof(part_fields["display_name"]) == CLICOM_MAX_NAME_LEN

    # Telemetry
    assert len(ClicomTelemetrySnapshot._fields_) == 10

    # Audio Frame
    assert len(ClicomAudioFrame._fields_) == 5
    af_fields = dict(ClicomAudioFrame._fields_)
    assert ctypes.sizeof(af_fields["pcm_data"]) == CLICOM_AUDIO_MAX_SAMPLES * ctypes.sizeof(ctypes.c_int16)

    # Audio Status
    assert len(ClicomAudioStatus._fields_) == 10


def test_missing_dll_error():
    """Verify that a nonexistent DLL path raises DllNotFoundError with an actionable message."""
    invalid_path = Path("nonexistent_path/libclicom_engine_fake.dll")
    with pytest.raises(DllNotFoundError) as exc_info:
        NativeEngine(dll_path=invalid_path)
    assert "DLL path does not exist" in str(exc_info.value) or "could not be located" in str(exc_info.value)


def test_dll_loading_and_signatures():
    """Verify that libclicom_engine.dll loads successfully and all symbols are bound."""
    engine = NativeEngine()
    assert engine._lib is not None
    assert engine.get_version() != 0
    assert engine.get_version_string() == "2.0.0"


def test_invalid_native_return_codes():
    """Verify that non-OK C return codes are translated to NativeCallError."""
    engine = NativeEngine()
    engine.init()

    # Empty display name triggers CLICOM_ERR_INVALID_ARG (-2)
    with pytest.raises(NativeCallError) as exc_info:
        engine.set_display_name("")
    assert exc_info.value.error_code == ClicomError.ERR_INVALID_ARG
    assert "Invalid argument" in str(exc_info.value)

    # Negative mic gain triggers CLICOM_ERR_INVALID_ARG (-2)
    with pytest.raises(NativeCallError) as exc_info:
        engine.set_mic_gain(-1.0)
    assert exc_info.value.error_code == ClicomError.ERR_INVALID_ARG

    # Empty room ID triggers CLICOM_ERR_INVALID_ARG (-2)
    with pytest.raises(NativeCallError) as exc_info:
        engine.room_join("")
    assert exc_info.value.error_code == ClicomError.ERR_INVALID_ARG

    engine.shutdown()
    engine.destroy()


def test_closed_handle_guards():
    """Verify that calling methods on a destroyed engine raises EngineClosedError."""
    engine = NativeEngine()
    engine.init()
    engine.shutdown()
    engine.destroy()

    assert not engine.is_alive
    with pytest.raises(EngineClosedError):
        engine.get_status()

    with pytest.raises(EngineClosedError):
        engine.set_display_name("TEST")

    with pytest.raises(EngineClosedError):
        engine.room_join("room-1")
