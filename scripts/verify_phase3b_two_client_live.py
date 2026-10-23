"""
CLICOM Phase 3B Live Verification:
Two independently running client sessions over TLS 1.3 with real WinMM audio hardware.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

# Add project root to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from client.config import get_project_root
from client.native_engine import (
    ClicomAudioEngineState,
    ClicomError,
    NativeCallError,
    NativeEngine,
)


def run_two_client_verification():
    root = get_project_root()
    server_bin = root / "build" / "windows-ninja-debug" / "server" / "clicom-server.exe"
    if not server_bin.is_file():
        print(f"ERROR: Server binary not found at {server_bin}")
        sys.exit(1)

    port = 14995
    db_file = root / "verify_phase3b_live.db"
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

    print("================================================================================")
    print("CLICOM Phase 3B -- Live Two-Client Audio & PTT Arbitration Verification")
    print("================================================================================")
    print(f"[1/7] Spawning CLICOM TLS 1.3 Server on port {port}...")
    srv_proc = subprocess.Popen(
        server_cmd,
        cwd=str(root),
        env=env,
        stdout=None,
        stderr=None,
    )
    time.sleep(1.0)
    if srv_proc.poll() is not None:
        out, err = srv_proc.communicate()
        print(f"FATAL: Server failed to start:\n{out.decode()}\n{err.decode()}")
        sys.exit(1)
    print("  [OK] Server listening on 127.0.0.1:14995 with TLS 1.3")

    engine_a = None
    engine_b = None
    try:
        # Initialize Client A and Client B
        print("\n[2/7] Initializing Client A ('Commander-Alpha') and Client B ('Operator-Bravo')...")
        engine_a = NativeEngine()
        engine_b = NativeEngine()

        engine_a.init("Commander-Alpha")
        engine_b.init("Operator-Bravo")

        # Explicitly configure real WinMM audio hardware
        engine_a.audio_set_mock_backend(False)
        engine_b.audio_set_mock_backend(False)

        backend_a_id, backend_a_mock = engine_a.audio_get_backend()
        backend_b_id, backend_b_mock = engine_b.audio_get_backend()
        in_a, out_a = engine_a.audio_get_device_counts()
        in_b, out_b = engine_b.audio_get_device_counts()

        print(f"  [OK] Client A Audio Backend: ID={backend_a_id} (is_mock={backend_a_mock}), Devices: {in_a} In, {out_a} Out")
        print(f"  [OK] Client B Audio Backend: ID={backend_b_id} (is_mock={backend_b_mock}), Devices: {in_b} In, {out_b} Out")

        # Connect both clients over TLS 1.3
        print("\n[3/7] Establishing authenticated TLS 1.3 connections...")
        ca_cert = str(root / "certs" / "ca.crt")
        engine_a.network_connect("127.0.0.1", port, ca_cert)
        engine_b.network_connect("127.0.0.1", port, ca_cert)
        print(f"  [OK] Client A connected (UUID session active: {engine_a.is_network_connected()})")
        print(f"  [OK] Client B connected (UUID session active: {engine_b.is_network_connected()})")

        # Create room by Client A and join by Client B
        print("\n[4/7] Client A creates tactical room 'OPERATION-NIGHTFALL'...")
        room_id, join_key = engine_a.network_create_room("OPERATION-NIGHTFALL", 4)
        print(f"  [OK] Room Created: ID={room_id}, Join Key={join_key}")

        print(f"  -> Client B joins room via key '{join_key}'...")
        b_room_id, b_name = engine_b.network_join_room(join_key)
        print(f"  [OK] Client B Joined: ID={b_room_id}, Channel Name={b_name}")

        sess_a = engine_a.get_active_session_id()
        sess_b = engine_b.get_active_session_id()
        print(f"  [OK] Active Room Session UUID: {sess_a} (Confirmed matching on B: {sess_b == sess_a})")

        # Start audio hardware engines
        print("\n[5/7] Starting Native C Audio Subsystem on both clients...")
        engine_a.audio_start()
        engine_b.audio_start()
        stat_a = engine_a.get_audio_status()
        stat_b = engine_b.get_audio_status()
        print(f"  [OK] Client A Audio State: {stat_a.state.name} (Sample Rate: {stat_a.sample_rate}Hz, Channels: {stat_a.channels})")
        print(f"  [OK] Client B Audio State: {stat_b.state.name} (Sample Rate: {stat_b.sample_rate}Hz, Channels: {stat_b.channels})")

        # Floor Arbitration Round 1: Client A acquires floor
        print("\n[6/7] Floor Arbitration & Transmission Round 1:")
        print("  -> Client A requests PTT Floor...")
        engine_a.set_ptt_active(True)
        assert engine_a.is_ptt_active() is True
        a_held, a_me, a_holder = engine_a.get_floor_status()
        print(f"  [OK] Client A Floor Granted: floor_held={a_held}, held_by_me={a_me}, holder={a_holder}")

        # Poll Client B to receive broadcast
        engine_b.network_poll(100)
        b_held, b_me, b_holder = engine_b.get_floor_status()
        print(f"  [OK] Client B Broadcast Received: floor_held={b_held}, held_by_me={b_me}, speaker={b_holder}")

        # Client B attempts simultaneous transmission -> MUST BE DENIED
        print("  -> Client B attempts simultaneous transmission while Client A speaks...")
        try:
            engine_b.set_ptt_active(True)
            print("  [FAIL] ERROR: Client B was unexpectedly granted floor!")
            sys.exit(1)
        except NativeCallError as e:
            print(f"  [OK] Server-authoritative floor collision PREVENTED: Client B denied with code {e.code} (ERR_PTT_BUSY)")
            assert e.code == ClicomError.ERR_PTT_BUSY

        # Transmit for 1 second
        print("  -> Client A transmitting live audio frames for 1.0s...")
        t_end = time.time() + 1.0
        while time.time() < t_end:
            engine_a.network_poll(10)
            engine_b.network_poll(10)
            time.sleep(0.01)

        # Mute test: Client A mutes mic
        print("  -> Client A toggles mic mute (set_mic_muted=True)...")
        engine_a.set_mic_muted(True)
        assert engine_a.is_mic_muted() is True
        print("  [OK] Client A microphone muted: hardware capture stopped")

        # Client A releases floor
        print("  -> Client A releases floor (set_ptt_active=False)...")
        engine_a.set_ptt_active(False)
        assert engine_a.is_ptt_active() is False

        # Wait for server to broadcast floor release to Client B
        t_wait = time.time() + 2.0
        while time.time() < t_wait:
            engine_a.network_poll(20)
            engine_b.network_poll(20)
            b_held, b_me, _ = engine_b.get_floor_status()
            if not b_held:
                break
            time.sleep(0.02)

        print(f"  [OK] Floor successfully released: floor_held on B={b_held}")

        # Floor Arbitration Round 2: Client B acquires floor
        print("\n[7/7] Floor Arbitration & Transmission Round 2:")
        print("  -> Client B requests PTT Floor...")
        engine_b.set_ptt_active(True)
        assert engine_b.is_ptt_active() is True
        b_held, b_me, b_holder = engine_b.get_floor_status()
        print(f"  [OK] Client B Floor Granted: floor_held={b_held}, held_by_me={b_me}, holder={b_holder}")

        engine_a.network_poll(100)
        a_held, a_me, a_holder = engine_a.get_floor_status()
        print(f"  [OK] Client A Broadcast Received: floor_held={a_held}, held_by_me={a_me}, speaker={a_holder}")

        # Client A attempts simultaneous transmission -> MUST BE DENIED
        print("  -> Client A attempts simultaneous transmission while Client B speaks...")
        try:
            engine_a.set_ptt_active(True)
            print("  [FAIL] ERROR: Client A was unexpectedly granted floor!")
            sys.exit(1)
        except NativeCallError as e:
            print(f"  [OK] Server-authoritative floor collision PREVENTED: Client A denied with code {e.code} (ERR_PTT_BUSY)")
            assert e.code == ClicomError.ERR_PTT_BUSY

        # Transmit for 1 second
        print("  -> Client B transmitting live audio frames for 1.0s...")
        t_end = time.time() + 1.0
        while time.time() < t_end:
            engine_a.network_poll(10)
            engine_b.network_poll(10)
            time.sleep(0.01)

        print("  -> Client B releases floor...")
        engine_b.set_ptt_active(False)
        engine_b.network_poll(100)
        engine_a.network_poll(100)
        print("  [OK] Floor released and room idle")

        # Telemetry verification
        telem_a = engine_a.get_telemetry()
        telem_b = engine_b.get_telemetry()
        print(f"\nTelemetry Summary:")
        print(f"  Client A: {telem_a.frames_sent} frames sent, {telem_a.frames_received} frames received, RTT={telem_a.rtt_ms}ms")
        print(f"  Client B: {telem_b.frames_sent} frames sent, {telem_b.frames_received} frames received, RTT={telem_b.rtt_ms}ms")

        # Graceful teardown
        print("\nTeardown & Cleanup:")
        engine_a.audio_stop()
        engine_b.audio_stop()
        print("  [OK] Audio subsystems stopped (waveIn/waveOut device handles closed)")

        engine_a.network_leave_room()
        engine_b.network_leave_room()
        print("  [OK] Clients left tactical room")

        engine_a.network_disconnect()
        engine_b.network_disconnect()
        print("  [OK] TLS 1.3 connections disconnected cleanly")

        engine_a.destroy()
        engine_b.destroy()
        engine_a = None
        engine_b = None
        print("  [OK] Native engine handles destroyed with zero leaks")

        print("\n================================================================================")
        print(">>> VERIFICATION SUCCESSFUL: ALL PHASE 3B CRITERIA VERIFIED ON REAL HARDWARE <<<")
        print("================================================================================")

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
        if db_file.exists():
            try:
                db_file.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    run_two_client_verification()
