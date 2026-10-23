"""
Unit tests for NativeEngine lifecycle, state transitions, room/membership, and audio queues.
"""

import pytest

from client.native_engine import (
    ClicomAudioEngineState,
    ClicomConnectionState,
    ClicomEngineState,
    ClicomRoomJoinState,
    NativeEngine,
)


def test_lifecycle_and_shutdown():
    """Verify initialization, status inspection, repeated shutdown, and destruction."""
    engine = NativeEngine()
    engine.init("NODE-TEST-01")

    assert engine.is_alive
    status = engine.get_status()
    assert status.state == ClicomEngineState.RUNNING
    assert engine.get_display_name() == "NODE-TEST-01"

    # Repeated shutdown should be idempotent and not raise
    engine.shutdown()
    assert not engine.is_alive
    engine.shutdown()

    engine.destroy()
    engine.destroy()  # Repeated destroy is safe


def test_context_manager():
    """Verify NativeEngine context manager initializes and cleanly destroys."""
    with NativeEngine(display_name="CTX-NODE") as engine:
        assert engine.is_alive
        assert engine.get_display_name() == "CTX-NODE"
    assert not engine.is_alive


def test_microphone_and_ptt_controls():
    """Verify thread-safe mic and PTT manipulation."""
    with NativeEngine() as engine:
        # Default state
        mic = engine.get_mic_state()
        assert not mic.is_muted
        assert not mic.is_ptt_active
        assert 0.99 <= mic.gain <= 1.01

        # Mute toggle
        engine.set_mic_muted(True)
        assert engine.is_mic_muted()
        mic = engine.get_mic_state()
        assert mic.is_muted

        engine.set_mic_muted(False)
        assert not engine.is_mic_muted()

        # PTT toggle
        engine.set_ptt_active(True)
        assert engine.is_ptt_active()
        engine.set_ptt_active(False)
        assert not engine.is_ptt_active()

        # Gain adjustment
        engine.set_mic_gain(1.75)
        assert 1.74 <= engine.get_mic_gain() <= 1.76


def test_room_and_participant_operations():
    """Verify room join/leave and participant add/remove/speaking tracking."""
    with NativeEngine() as engine:
        engine.room_join("TACTICAL-GRID-9", "KEY-ABC")
        room = engine.get_room_state()
        assert room.state == ClicomRoomJoinState.JOINED
        assert room.room_id == "TACTICAL-GRID-9"
        assert room.join_key == "KEY-ABC"
        assert room.participant_count == 0

        # Add participant 1
        engine.participant_add("p-01", "Alpha-One", is_speaking=False, is_muted=False)
        assert engine.get_participant_count() == 1

        # Add participant 2 (Speaking)
        engine.participant_add("p-02", "Bravo-Two", is_speaking=True, is_muted=False)
        assert engine.get_participant_count() == 2

        room = engine.get_room_state()
        assert room.active_speaker_id == "p-02"

        # Lookup
        p1 = engine.get_participant_by_id("p-01")
        assert p1 is not None
        assert p1.display_name == "Alpha-One"

        # Enumeration
        plist = engine.get_participants()
        assert len(plist) == 2

        # Update participant 2 to stop speaking
        engine.participant_add("p-02", "Bravo-Two", is_speaking=False, is_muted=False)
        room = engine.get_room_state()
        assert room.active_speaker_id == ""

        # Remove
        engine.participant_remove("p-01")
        assert engine.get_participant_count() == 1

        # Leave room resets state
        engine.room_leave()
        room = engine.get_room_state()
        assert room.state == ClicomRoomJoinState.DISCONNECTED
        assert engine.get_participant_count() == 0


def test_audio_engine_lifecycle():
    """Verify starting and stopping the local audio engine."""
    with NativeEngine() as engine:
        status = engine.get_audio_status()
        assert status.state == ClicomAudioEngineState.STOPPED

        engine.audio_start()
        status = engine.get_audio_status()
        assert status.state == ClicomAudioEngineState.RUNNING

        engine.audio_queue_clear()
        status = engine.get_audio_status()
        assert status.capture_queue_depth == 0

        engine.audio_stop()
        status = engine.get_audio_status()
        assert status.state == ClicomAudioEngineState.STOPPED
