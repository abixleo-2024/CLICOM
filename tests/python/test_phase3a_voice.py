"""
CLICOM Phase 3A Integration Test: Python Native Engine Voice Transport & PTT Arbitration
"""

import os
import subprocess
import sys
import time
from pathlib import Path
import pytest

from client.native_engine import (
    ClicomAudioEngineState,
    ClicomError,
    ClicomRoomJoinState,
    NativeCallError,
    NativeEngine,
)
from client.config import get_project_root


def test_phase3a_constants_and_signatures():
    """Verify Phase 3A audio/PTT error codes and ctypes function signatures."""
    assert ClicomError.ERR_PTT_BUSY == -19
    assert ClicomError.ERR_AUDIO_DEVICE == -20

    engine = NativeEngine()
    engine.init("PHASE3A-CHECK")
    try:
        assert hasattr(engine._lib, "clicom_audio_set_mock_backend")
        assert hasattr(engine._lib, "clicom_get_active_session_id")
        assert hasattr(engine._lib, "clicom_set_ptt_active")
        assert hasattr(engine._lib, "clicom_is_ptt_active")

        # Before joining a room, get_active_session_id raises ERR_NOT_FOUND
        with pytest.raises(NativeCallError) as exc_info:
            engine.get_active_session_id()
        assert exc_info.value.code == ClicomError.ERR_NOT_FOUND
    finally:
        engine.destroy()


def test_phase3a_voice_and_floor_arbitration_e2e():
    """
    Full Phase 3A E2E test with two Python NativeEngine instances:
    1. Spawn server over TLS 1.3
    2. Alice and Bob connect via TLS
    3. Alice creates tactical room; Bob joins via join key
    4. Verify active communication session binding on both
    5. Start audio subsystem on both (mock audio backend for headless VM safety)
    6. Server-enforced floor control: Alice acquires floor; Bob is rejected with ERR_PTT_BUSY
    7. Mute toggle affects microphone state
    8. Floor release & handover: Alice releases floor; Bob acquires floor; Alice is rejected
    9. Clean shutdown of audio, room sessions, and engines
    """
    root = get_project_root()
    server_bin = root / "build" / "windows-ninja-debug" / "server" / "clicom-server.exe"
    if not server_bin.is_file():
        pytest.skip(f"clicom-server executable not found at {server_bin}")

    port = 14999
    db_file = root / "test_phase3a_py.db"
    if db_file.exists():
        try:
            db_file.unlink()
        except OSError:
            pass

    server_cmd = [
        str(server_bin),
        "--port", str(port),
        "--tls",
        "--cert", "certs/server.crt",
        "--key", "certs/server.key",
        "--db", str(db_file),
    ]

    env = os.environ.copy()
    if sys.platform == "win32":
        env["PATH"] = r"C:\msys64\ucrt64\bin;" + env.get("PATH", "")

    srv_proc = subprocess.Popen(
        server_cmd,
        cwd=str(root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1.0)
    if srv_proc.poll() is not None:
        out, err = srv_proc.communicate()
        pytest.fail(f"clicom-server failed to start (rc={srv_proc.returncode}):\n{out.decode()}\n{err.decode()}")

    try:
        engine_alice = NativeEngine()
        engine_bob = NativeEngine()

        engine_alice.init("Alice-Py")
        engine_bob.init("Bob-Py")

        engine_alice.audio_set_mock_backend(True)
        engine_bob.audio_set_mock_backend(True)

        ca_cert = str(root / "certs" / "ca.crt")
        engine_alice.network_connect("127.0.0.1", port, ca_cert)
        engine_bob.network_connect("127.0.0.1", port, ca_cert)

        assert engine_alice.is_network_connected()
        assert engine_bob.is_network_connected()

        # Alice creates room
        room_id, join_key = engine_alice.network_create_room("TACTICAL_OPS", 4)
        assert len(room_id) > 0
        assert len(join_key) > 0

        # Bob joins room
        bob_room_id, bob_name = engine_bob.network_join_room(join_key)
        assert bob_room_id == room_id
        assert bob_name == "TACTICAL_OPS"

        # Verify active room session binding on both
        alice_sess = engine_alice.get_active_session_id()
        bob_sess = engine_bob.get_active_session_id()
        assert len(alice_sess) > 0
        assert alice_sess == bob_sess

        # Start audio subsystem on both
        engine_alice.audio_start()
        engine_bob.audio_start()

        a_stat = engine_alice.get_audio_status()
        b_stat = engine_bob.get_audio_status()
        assert a_stat.state == ClicomAudioEngineState.RUNNING
        assert b_stat.state == ClicomAudioEngineState.RUNNING

        # ── Half-duplex floor arbitration ──
        # Alice requests floor: MUST BE GRANTED
        engine_alice.set_ptt_active(True)
        assert engine_alice.is_ptt_active() is True

        # Bob requests floor while held by Alice: MUST BE STRICTLY REJECTED
        with pytest.raises(NativeCallError) as exc_info:
            engine_bob.set_ptt_active(True)
        assert exc_info.value.code == ClicomError.ERR_PTT_BUSY
        assert engine_bob.is_ptt_active() is False

        # ── Mute toggle ──
        engine_alice.set_mic_muted(True)
        assert engine_alice.is_mic_muted() is True
        engine_alice.set_mic_muted(False)
        assert engine_alice.is_mic_muted() is False

        # ── Floor handover ──
        # Alice releases floor
        engine_alice.set_ptt_active(False)
        assert engine_alice.is_ptt_active() is False

        # Bob now acquires floor: MUST BE GRANTED
        engine_bob.set_ptt_active(True)
        assert engine_bob.is_ptt_active() is True

        # Alice attempts while Bob holds: MUST BE REJECTED
        with pytest.raises(NativeCallError) as exc_info:
            engine_alice.set_ptt_active(True)
        assert exc_info.value.code == ClicomError.ERR_PTT_BUSY
        assert engine_alice.is_ptt_active() is False

        # Bob releases floor
        engine_bob.set_ptt_active(False)
        assert engine_bob.is_ptt_active() is False

        # ── Cleanup ──
        engine_alice.audio_stop()
        engine_bob.audio_stop()

        engine_alice.network_leave_room()
        engine_bob.network_leave_room()

        engine_alice.network_disconnect()
        engine_bob.network_disconnect()

        engine_alice.destroy()
        engine_bob.destroy()

    finally:
        srv_proc.terminate()
        try:
            srv_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            srv_proc.kill()
        if db_file.exists():
            try:
                db_file.unlink()
            except OSError:
                pass
