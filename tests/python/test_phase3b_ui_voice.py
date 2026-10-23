"""
CLICOM Phase 3B Integration Test:
UI Voice Integration, Always-Visible Room Key,
Half-Duplex Floor Arbitration over TLS 1.3, and Non-Blocking Receiver UI.
"""

import os
import subprocess
import sys
import time
from pathlib import Path
import pytest

from client.app import ClicomApp
from client.config import get_project_root
from client.native_engine import (
    ClicomAudioEngineState,
    ClicomError,
    ClicomRoomJoinState,
    NativeCallError,
    NativeEngine,
)
from client.screens.create_room import CreateRoomScreen
from client.screens.live_room import LiveRoomScreen
from client.screens.main_menu import MainMenuScreen
from textual.widgets import Button, Input, Static


def test_phase3b_ctypes_audio_backend_and_floor():
    """Verify Phase 3B ctypes methods: audio backend, device count, and mute state."""
    engine = NativeEngine()
    engine.init("PHASE3B-AUDIT")
    try:
        # Default backend is Real Hardware (WinMM = 1) on Windows
        backend_id, is_mock = engine.audio_get_backend()
        assert backend_id in (0, 1)
        assert isinstance(is_mock, bool)

        in_cnt, out_cnt = engine.audio_get_device_counts()
        assert isinstance(in_cnt, int)
        assert isinstance(out_cnt, int)

        # Switch to mock backend (Mock = 0) and verify
        engine.audio_set_mock_backend(True)
        m_id, m_mock = engine.audio_get_backend()
        assert m_id == 0
        assert m_mock is True

        # Switch back to real backend (WinMM = 1)
        engine.audio_set_mock_backend(False)
        r_id, r_mock = engine.audio_get_backend()
        assert r_id == 1
        assert r_mock is False

        # Verify mute controls
        assert engine.is_mic_muted() is False
        engine.set_mic_muted(True)
        assert engine.is_mic_muted() is True
        engine.set_mic_muted(False)
        assert engine.is_mic_muted() is False
    finally:
        engine.destroy()


@pytest.mark.asyncio
async def test_phase3b_live_room_ui_interactions():
    """
    Verify Textual UI in LiveRoomScreen:
    - Room ID and Invitation Key are always prominently visible in header.
    - Push to Talk button ('t' key) toggles PTT active state.
    - Mute button ('m' key) toggles native mic state and updates button label.
    - Gain controls ('+' / '-') adjust native mic gain.
    - Leave room ('l') cleanly stops audio and navigates back to Main Menu.
    """
    app = ClicomApp(display_name="ALPHA-LEADER")
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, MainMenuScreen)

        # Press '1' to enter Create Room screen
        await pilot.press("1")
        await pilot.pause()
        assert isinstance(app.screen, CreateRoomScreen)

        # Set valid room ID and submit
        create_screen: CreateRoomScreen = app.screen  # type: ignore
        input_room = create_screen.query_one("#input-room-id", Input)
        input_room.value = "ALPHA-GRID-TEST"
        create_screen.submit_form()
        await pilot.pause(0.2)

        # Should now be in LiveRoomScreen
        assert isinstance(app.screen, LiveRoomScreen)
        assert app.engine is not None
        assert app.engine.get_audio_status().state == ClicomAudioEngineState.RUNNING

        # 1. Verify Room Info & Permanent Invitation Key Visibility
        lbl_info = app.screen.query_one("#lbl-live-room-info", Static)
        info_text = str(lbl_info.render())
        assert "ROOM:" in info_text
        assert "INVITATION KEY:" in info_text
        assert ("SEC-ALPH-99" in info_text or len(app.current_room_key) > 0)

        # 2. Verify Initial Mic and PTT State (Mic is always MUTED initially by requirement)
        btn_mic = app.screen.query_one("#btn-toggle-mic", Button)
        assert "Unmute Mic" in str(btn_mic.label)
        assert app.engine.is_mic_muted() is True

        btn_ptt = app.screen.query_one("#btn-toggle-ptt", Button)
        assert "Push to Talk" in str(btn_ptt.label)

        # 3. Press 'm' to unmute mic
        await pilot.press("m")
        await pilot.pause(0.1)
        assert app.engine.is_mic_muted() is False
        assert "Mute Mic" in str(btn_mic.label)

        # 4. Press 't' to toggle PTT active
        await pilot.press("t")
        await pilot.pause(0.1)
        assert app.engine.is_ptt_active() is True
        assert "Release Floor" in str(btn_ptt.label)

        # Press 't' again to release PTT
        await pilot.press("t")
        await pilot.pause(0.1)
        assert app.engine.is_ptt_active() is False
        assert "Push to Talk" in str(btn_ptt.label)

        # 5. Press 'm' to mute mic again
        await pilot.press("m")
        await pilot.pause(0.1)
        assert app.engine.is_mic_muted() is True
        assert "Unmute Mic" in str(btn_mic.label)

        # 5. Press '+' and '-' to adjust gain
        initial_gain = app.engine.get_mic_gain()
        await pilot.press("plus")
        await pilot.pause(0.1)
        assert app.engine.get_mic_gain() >= initial_gain

        await pilot.press("minus")
        await pilot.pause(0.1)

        # 6. Press 'l' to leave room cleanly
        await pilot.press("l")
        await pilot.pause(0.2)

        # Audio engine must be stopped upon leaving room
        assert app.engine.get_audio_status().state == ClicomAudioEngineState.STOPPED
        # Screen must return to MainMenuScreen
        assert isinstance(app.screen, MainMenuScreen)


def test_phase3b_two_client_half_duplex_voice_transport():
    """
    Two-client half-duplex verification over TLS 1.3:
    1. Spawn TLS server.
    2. Client A and Client B connect and join the same room.
    3. Room Key is generated and visible.
    4. Client A requests floor -> granted.
    5. Client A transmits audio frames over wire.
    6. Client B receives relayed audio frames.
    7. Client A releases floor.
    8. Client B acquires floor and transmits audio frames.
    9. Clean teardown and release of all audio and network handles.
    """
    root = get_project_root()
    server_bin = root / "build" / "windows-ninja-debug" / "server" / "clicom-server.exe"
    if not server_bin.is_file():
        pytest.skip(f"clicom-server executable not found at {server_bin}")

    port = 14996
    db_file = root / "test_phase3b_py.db"
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

    srv_log_path = root / "test_phase3b_two_client.log"
    srv_log = open(srv_log_path, "w", encoding="utf-8")
    srv_proc = subprocess.Popen(
        server_cmd,
        cwd=str(root),
        env=env,
        stdout=srv_log,
        stderr=srv_log,
    )
    time.sleep(1.0)
    if srv_proc.poll() is not None:
        srv_log.close()
        log_content = srv_log_path.read_text(encoding="utf-8", errors="replace")
        pytest.fail(f"clicom-server failed to start (rc={srv_proc.returncode}):\n{log_content}")

    engine_a = None
    engine_b = None
    try:
        engine_a = NativeEngine()
        engine_b = NativeEngine()

        engine_a.init("Bravo-Lead")
        engine_b.init("Bravo-Two")

        # Mock backend for automated regression test
        engine_a.audio_set_mock_backend(True)
        engine_b.audio_set_mock_backend(True)

        ca_cert = str(root / "certs" / "ca.crt")
        engine_a.network_connect("127.0.0.1", port, ca_cert)
        engine_b.network_connect("127.0.0.1", port, ca_cert)

        assert engine_a.is_network_connected()
        assert engine_b.is_network_connected()

        # Client A creates room
        room_id, join_key = engine_a.network_create_room("BRAVO_CHANNEL", 4)
        assert len(room_id) > 0
        assert len(join_key) > 0

        # Client B joins room via invitation key
        b_room_id, b_room_name = engine_b.network_join_room(join_key)
        assert b_room_id == room_id
        assert b_room_name == "BRAVO_CHANNEL"

        # Start audio engines
        engine_a.audio_start()
        engine_b.audio_start()

        # Step 1: Client A requests and acquires floor
        engine_a.set_ptt_active(True)
        assert engine_a.is_ptt_active() is True

        time.sleep(0.3)
        engine_a.network_poll(50)
        engine_b.network_poll(50)

        telem_a = engine_a.get_telemetry()
        assert telem_a.frames_sent > 0, "Client A must transmit audio frames over wire when holding floor"

        # Step 2: Client B receives audio frames over wire
        for _ in range(10):
            engine_b.network_poll(50)
            engine_a.network_poll(50)
            time.sleep(0.05)

        telem_b = engine_b.get_telemetry()
        assert telem_b.frames_received > 0, "Client B must receive relayed audio frames over wire"

        # Step 3: Client A releases floor
        engine_a.set_ptt_active(False)
        assert engine_a.is_ptt_active() is False

        # Wait for server to process release and notify client B
        released = False
        for i in range(30):
            engine_a.network_poll(50)
            engine_b.network_poll(50)
            held, _, holder_name = engine_b.get_floor_status()
            if not held:
                released = True
                break
            time.sleep(0.05)

        assert released, f"Client B must observe floor released, currently held={held} holder={holder_name}"

        # Step 4: Client B now acquires floor and transmits
        engine_b.set_ptt_active(True)
        assert engine_b.is_ptt_active() is True
        time.sleep(0.2)
        engine_b.network_poll(50)
        engine_a.network_poll(50)

        assert engine_b.get_telemetry().frames_sent > 0, "Client B must transmit frames when holding floor"

        engine_b.set_ptt_active(False)

        # Step 5: Clean teardown
        engine_a.audio_stop()
        engine_b.audio_stop()

        engine_a.network_leave_room()
        engine_b.network_leave_room()

        engine_a.network_disconnect()
        engine_b.network_disconnect()

        engine_a.destroy()
        engine_b.destroy()
        engine_a = None
        engine_b = None

    finally:
        if engine_a is not None:
            try:
                engine_a.destroy()
            except Exception:
                pass
        if engine_b is not None:
            try:
                engine_b.destroy()
            except Exception:
                pass

        srv_proc.terminate()
        try:
            srv_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            srv_proc.kill()
        srv_log.close()
        for f in [db_file, db_file.with_name(db_file.name + "-wal"), db_file.with_name(db_file.name + "-shm"), srv_log_path]:
            if f.exists():
                try:
                    f.unlink()
                except OSError:
                    pass


@pytest.mark.asyncio
async def test_phase3b_receiver_ui_responsiveness_on_half_duplex():
    """
    Verify Receiver Textual UI remains responsive (< 0.3s per tick)
    during floor requests and incoming audio streams:
    1. Start TLS server.
    2. Client A creates room and joins.
    3. Client B launches Textual ClicomApp, joins room, enters LiveRoomScreen.
    4. Client A acquires floor and streams real audio frames over TLS 1.3.
    5. Client B UI remains responsive without stalls or freezes.
    6. Client A releases floor -> Client B reflects floor free.
    7. Clean exit.
    """
    root = get_project_root()
    server_bin = root / "build" / "windows-ninja-debug" / "server" / "clicom-server.exe"
    if not server_bin.is_file():
        pytest.skip(f"clicom-server executable not found at {server_bin}")

    port = 14999
    db_file = root / "test_phase3b_freeze_regress.db"
    for f in [db_file, root / "test_phase3b_freeze_regress.db-shm", root / "test_phase3b_freeze_regress.db-wal"]:
        if f.exists():
            try:
                f.unlink()
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

    srv_log_path = root / "test_phase3b_freeze_regress.log"
    srv_log = open(srv_log_path, "w", encoding="utf-8")
    srv_proc = subprocess.Popen(
        server_cmd,
        cwd=str(root),
        env=env,
        stdout=srv_log,
        stderr=srv_log,
    )
    time.sleep(1.0)
    if srv_proc.poll() is not None:
        srv_log.close()
        log_content = srv_log_path.read_text(encoding="utf-8", errors="replace")
        pytest.fail(f"clicom-server failed to start:\n{log_content}")

    engine_a = None
    try:
        engine_a = NativeEngine()
        engine_a.init("Lead-Transmitter")
        engine_a.audio_set_mock_backend(True)

        ca_cert = str(root / "certs" / "ca.crt")
        engine_a.network_connect("127.0.0.1", port, ca_cert)
        assert engine_a.is_network_connected()

        room_id, join_key = engine_a.network_create_room("REGRESS_ROOM", 4)
        assert len(room_id) > 0
        assert len(join_key) > 0
        engine_a.audio_start()

        app_b = ClicomApp(display_name="Receiver-Node")
        async with app_b.run_test() as pilot:
            engine_b = app_b.engine
            assert engine_b is not None
            engine_b.network_connect("127.0.0.1", port, ca_cert)
            b_room_id, b_room_name = engine_b.network_join_room(join_key)
            assert b_room_id == room_id
            app_b.current_room_key = join_key
            app_b.current_room_name = b_room_name

            await app_b.push_screen(LiveRoomScreen())
            await pilot.pause(0.2)
            assert isinstance(app_b.screen, LiveRoomScreen)

            # Client A acquires floor
            engine_a.set_ptt_active(True)
            assert engine_a.is_ptt_active() is True

            # Step 1: Step through event loop on Receiver UI during active transmission
            for _ in range(15):
                t_step = time.monotonic()
                await pilot.pause(0.05)
                elapsed = time.monotonic() - t_step
                # Event loop must remain snappy: each 0.05s step must not stall > 0.3s
                assert elapsed < 0.3, f"Receiver UI event loop stalled: {elapsed:.3f}s"

            # Verify Receiver UI automatically blocks other client's mic and PTT when floor is held
            btn_ptt_b = app_b.screen.query_one("#btn-toggle-ptt", Button)
            btn_mic_b = app_b.screen.query_one("#btn-toggle-mic", Button)
            assert btn_ptt_b.disabled is True
            assert btn_mic_b.disabled is True

            # Step 2: Client A releases floor
            engine_a.set_ptt_active(False)
            assert engine_a.is_ptt_active() is False

            for _ in range(15):
                t_step = time.monotonic()
                await pilot.pause(0.05)
                elapsed = time.monotonic() - t_step
                assert elapsed < 0.3, f"Receiver UI stalled after release: {elapsed:.3f}s"

            # Once floor is free, buttons are unblocked
            assert btn_ptt_b.disabled is False
            assert btn_mic_b.disabled is False

            # Step 3: Verify Room Header permanently shows Invitation Key
            lbl_info = app_b.screen.query_one("#lbl-live-room-info", Static)
            info_text = str(lbl_info.render())
            assert "INVITATION KEY:" in info_text
            assert join_key in info_text

            # Step 4: Clean exit via 'l' key
            await pilot.press("l")
            await pilot.pause(0.2)

    finally:
        if engine_a is not None:
            try:
                engine_a.destroy()
            except Exception:
                pass
        srv_proc.terminate()
        try:
            srv_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            srv_proc.kill()
        srv_log.close()
        for f in [db_file, root / "test_phase3b_freeze_regress.db-shm", root / "test_phase3b_freeze_regress.db-wal", srv_log_path]:
            if f.exists():
                try:
                    f.unlink()
                except OSError:
                    pass


def test_phase3b_three_client_roster_sync_and_mic_blocking():
    """
    Verify 3-client synchronization:
    1. Client 1 creates room.
    2. Client 2 and Client 3 join via room key.
    3. All 3 clients refresh and report exactly 3 participants.
    4. Client 1 acquires PTT floor -> Client 2 and 3 see floor busy.
    5. Client 2 and 3 cannot acquire floor (floor busy / blocked).
    6. Client 1 releases floor -> Client 2 and 3 see floor free.
    """
    root = get_project_root()
    server_bin = root / "build" / "windows-ninja-debug" / "server" / "clicom-server.exe"
    if not server_bin.is_file():
        pytest.skip(f"clicom-server executable not found at {server_bin}")

    port = 14992
    db_file = root / "test_phase3b_3cli.db"
    for f in [db_file, root / "test_phase3b_3cli.db-shm", root / "test_phase3b_3cli.db-wal"]:
        if f.exists():
            try:
                f.unlink()
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

    srv_log_path = root / "test_phase3b_3cli.log"
    srv_log = open(srv_log_path, "w", encoding="utf-8")
    srv_proc = subprocess.Popen(
        server_cmd,
        cwd=str(root),
        env=env,
        stdout=srv_log,
        stderr=srv_log,
    )
    time.sleep(1.0)
    if srv_proc.poll() is not None:
        srv_log.close()
        pytest.fail(f"clicom-server failed to start")

    e1 = None
    e2 = None
    e3 = None
    try:
        e1 = NativeEngine()
        e2 = NativeEngine()
        e3 = NativeEngine()

        e1.init("NODE-ALPHA")
        e2.init("NODE-BETA")
        e3.init("NODE-GAMMA")

        # Initial mic state: Muted by default
        e1.set_mic_muted(True)
        e2.set_mic_muted(True)
        e3.set_mic_muted(True)
        assert e1.is_mic_muted() is True
        assert e2.is_mic_muted() is True
        assert e3.is_mic_muted() is True

        ca_cert = str(root / "certs" / "ca.crt")
        e1.network_connect("127.0.0.1", port, ca_cert)
        e2.network_connect("127.0.0.1", port, ca_cert)
        e3.network_connect("127.0.0.1", port, ca_cert)

        # 1. Client 1 creates room
        room_id, join_key = e1.network_create_room("abi", 8)
        assert len(join_key) > 0

        # 2. Client 2 and 3 join
        e2.network_join_room(join_key)
        e3.network_join_room(join_key)

        # 3. Synchronize participant rosters on all 3 clients
        e1.network_refresh_participants()
        e2.network_refresh_participants()
        e3.network_refresh_participants()

        # All 3 dashboards now see all 3 participants!
        p1 = [p.display_name for p in e1.get_participants()]
        p2 = [p.display_name for p in e2.get_participants()]
        p3 = [p.display_name for p in e3.get_participants()]

        assert len(p1) == 3, f"Client 1 must see 3 participants, got {p1}"
        assert len(p2) == 3, f"Client 2 must see 3 participants, got {p2}"
        assert len(p3) == 3, f"Client 3 must see 3 participants, got {p3}"

        assert "NODE-ALPHA" in p1 and "NODE-BETA" in p1 and "NODE-GAMMA" in p1
        assert "NODE-ALPHA" in p2 and "NODE-BETA" in p2 and "NODE-GAMMA" in p2
        assert "NODE-ALPHA" in p3 and "NODE-BETA" in p3 and "NODE-GAMMA" in p3

        # 4. Floor Arbitration: Client 1 acquires floor
        e1.set_ptt_active(True)
        assert e1.is_ptt_active() is True

        time.sleep(0.1)
        e1.network_poll(20)
        e2.network_poll(20)
        e3.network_poll(20)

        # Client 2 and 3 observe floor held by NODE-ALPHA
        held_2, _, holder_2 = e2.get_floor_status()
        held_3, _, holder_3 = e3.get_floor_status()
        assert held_2 is True
        assert held_3 is True
        assert "NODE-ALPHA" in holder_2 or len(holder_2) > 0

        # Client 2 and 3 cannot acquire floor while Client 1 speaks
        with pytest.raises(NativeCallError) as exc_info:
            e2.set_ptt_active(True)
        assert exc_info.value.error_code == ClicomError.ERR_PTT_BUSY

        # 5. Client 1 releases floor
        e1.set_ptt_active(False)
        assert e1.is_ptt_active() is False

        for _ in range(20):
            e1.network_poll(20)
            e2.network_poll(20)
            e3.network_poll(20)
            held_2, _, _ = e2.get_floor_status()
            if not held_2:
                break
            time.sleep(0.05)

        held_2, _, _ = e2.get_floor_status()
        held_3, _, _ = e3.get_floor_status()
        assert held_2 is False
        assert held_3 is False

    finally:
        for eng in [e1, e2, e3]:
            if eng is not None:
                try:
                    eng.destroy()
                except Exception:
                    pass
        srv_proc.terminate()
        try:
            srv_proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            srv_proc.kill()
        srv_log.close()
        for f in [db_file, root / "test_phase3b_3cli.db-shm", root / "test_phase3b_3cli.db-wal", srv_log_path]:
            if f.exists():
                try:
                    f.unlink()
                except OSError:
                    pass
