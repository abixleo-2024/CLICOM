"""
CLICOM Phase 2A Integration Test: Python Native Engine Network Client & Server
"""

import os
import subprocess
import sys
import time
from pathlib import Path
import pytest

from client.native_engine import (
    ClicomError,
    ClicomRoomJoinState,
    NativeCallError,
    NativeEngine,
)
from client.config import find_engine_dll, get_project_root


def test_native_network_signatures_and_constants():
    """Verify Phase 2A network error codes and ctypes function signatures."""
    assert ClicomError.ERR_NETWORK_DISCONNECTED == -14
    assert ClicomError.ERR_CONNECTION_FAILED == -15
    assert ClicomError.ERR_UNAUTHORIZED == -16
    assert ClicomError.ERR_REVOKED == -17
    assert ClicomError.ERR_RATE_LIMITED == -18

    engine = NativeEngine()
    engine.init("TEST-NODE")
    try:
        assert hasattr(engine._lib, "clicom_network_connect")
        assert hasattr(engine._lib, "clicom_network_disconnect")
        assert hasattr(engine._lib, "clicom_is_network_connected")
        assert hasattr(engine._lib, "clicom_network_poll")
        assert hasattr(engine._lib, "clicom_network_create_room")
        assert hasattr(engine._lib, "clicom_network_join_room")
        assert hasattr(engine._lib, "clicom_network_leave_room")
        assert hasattr(engine._lib, "clicom_network_revoke_invitation")
        assert hasattr(engine._lib, "clicom_network_close_room")

        # Initially disconnected
        assert not engine.is_network_connected()
    finally:
        engine.destroy()


def test_network_disconnected_guards():
    """Ensure room operations without network connection raise appropriate errors."""
    engine = NativeEngine()
    engine.init("DISCONNECTED-NODE")
    try:
        assert not engine.is_network_connected()

        # Polling while disconnected
        with pytest.raises(NativeCallError) as exc_info:
            engine.network_poll(10)
        assert exc_info.value.code == ClicomError.ERR_NETWORK_DISCONNECTED

        # Creating room while disconnected
        with pytest.raises(NativeCallError) as exc_info:
            engine.network_create_room("OFFLINE-ROOM", 4)
        assert exc_info.value.code == ClicomError.ERR_NETWORK_DISCONNECTED

        # Joining room while disconnected
        with pytest.raises(NativeCallError) as exc_info:
            engine.network_join_room("GC-1234")
        assert exc_info.value.code == ClicomError.ERR_NETWORK_DISCONNECTED

        # Revoking when not joined
        with pytest.raises(NativeCallError) as exc_info:
            engine.network_revoke_invitation()
        assert exc_info.value.code in (ClicomError.ERR_INVALID_STATE, ClicomError.ERR_NETWORK_DISCONNECTED)
    finally:
        engine.destroy()


def test_phase2a_server_multi_client_workflow():
    """
    Full Phase 2A E2E test:
    1. Spawn clicom-server.exe over TLS 1.3
    2. Client 1 and Client 2 connect independently
    3. Client 1 creates room with limit=2 and receives secure join key
    4. Client 2 joins with valid join key
    5. Client 3 attempts to join and is rejected (Capacity limit reached)
    6. Client 2 (non-owner) attempts to revoke key and is rejected (Unauthorized)
    7. Client 2 leaves room
    8. Client 1 (owner) revokes invitation key
    9. Client 3 attempts to join with revoked key and is rejected (Revoked)
    10. Client 3 attempts to join with invalid key and is rejected (Not found)
    11. Clean shutdown and disconnect
    """
    root = get_project_root()
    server_bin = root / "build" / "windows-ninja-debug" / "server" / "clicom-server.exe"
    if not server_bin.is_file():
        pytest.skip(f"clicom-server executable not found at {server_bin}")

    port = 14998
    db_file = root / "test_phase2a_py.db"
    if db_file.exists():
        try:
            db_file.unlink()
        except OSError:
            pass

    # Start server subprocess
    cmd = [
        str(server_bin),
        "--port", str(port),
        "--tls",
        "--cert", "certs/server.crt",
        "--key", "certs/server.key",
        "--db", str(db_file),
    ]

    # Start server subprocess with runtime DLL path and unbuffered file logging
    env = os.environ.copy()
    if sys.platform == "win32":
        env["PATH"] = r"C:\msys64\ucrt64\bin;" + env.get("PATH", "")

    server_log_path = root / "server_test.log"
    server_log_file = open(server_log_path, "w", encoding="utf-8")

    server_proc = subprocess.Popen(
        cmd,
        cwd=str(root),
        env=env,
        stdout=server_log_file,
        stderr=server_log_file,
    )
    time.sleep(1.0)
    if server_proc.poll() is not None:
        server_log_file.close()
        log_content = server_log_path.read_text(encoding="utf-8", errors="replace")
        pytest.fail(f"clicom-server failed to start (rc={server_proc.returncode}):\n{log_content}")

    try:
        # Client 1
        client1 = NativeEngine()
        client1.init("OPERATOR-ALPHA")

        # Client 2
        client2 = NativeEngine()
        client2.init("OPERATOR-BRAVO")

        # Client 3
        client3 = NativeEngine()
        client3.init("OPERATOR-CHARLIE")

        ca_path = str(root / "certs" / "ca.crt")

        # 1. Clients connect over TLS 1.3
        client1.network_connect("127.0.0.1", port, ca_path)
        assert client1.is_network_connected()

        client2.network_connect("127.0.0.1", port, ca_path)
        assert client2.is_network_connected()

        # 2. Client 1 creates room with limit=2
        room_id, join_key = client1.network_create_room("GRID-SECTOR-7", member_limit=2)
        assert len(room_id) > 0
        assert join_key.startswith("GC-")
        assert len(join_key) == 7

        state1 = client1.get_room_state()
        assert state1.state == ClicomRoomJoinState.JOINED
        assert state1.participant_count == 1

        # 3. Client 2 joins with valid key
        j_id, j_name = client2.network_join_room(join_key)
        assert j_name == "GRID-SECTOR-7"

        state2 = client2.get_room_state()
        assert state2.state == ClicomRoomJoinState.JOINED
        assert state2.participant_count == 2

        # 4. Client 3 connects and tries to join (should fail: capacity reached)
        client3.network_connect("127.0.0.1", port, ca_path)
        assert client3.is_network_connected()

        with pytest.raises(NativeCallError) as exc_info:
            client3.network_join_room(join_key)
        assert exc_info.value.code == ClicomError.ERR_LIMIT_REACHED

        # 5. Non-owner Client 2 tries to revoke invitation (should fail: unauthorized)
        with pytest.raises(NativeCallError) as exc_info:
            client2.network_revoke_invitation()
        assert exc_info.value.code == ClicomError.ERR_UNAUTHORIZED

        # 6. Client 2 leaves room
        client2.network_leave_room()
        assert client2.get_room_state().state == ClicomRoomJoinState.DISCONNECTED

        # 7. Owner Client 1 revokes invitation key
        client1.network_revoke_invitation()

        # 8. Client 3 tries to join with revoked key (should fail: revoked)
        with pytest.raises(NativeCallError) as exc_info:
            client3.network_join_room(join_key)
        assert exc_info.value.code == ClicomError.ERR_REVOKED

        # 9. Client 3 tries to join with invalid/bogus key (should fail: not found)
        with pytest.raises(NativeCallError) as exc_info:
            client3.network_join_room("GC-9999")
        assert exc_info.value.code == ClicomError.ERR_NOT_FOUND

        # Clean disconnect
        client1.network_disconnect()
        client2.network_disconnect()
        client3.network_disconnect()

        assert not client1.is_network_connected()
        assert not client2.is_network_connected()
        assert not client3.is_network_connected()

    finally:
        try:
            server_proc.terminate()
            server_proc.wait(timeout=2.0)
        except Exception:
            server_proc.kill()
        try:
            server_log_file.close()
        except Exception:
            pass
        if db_file.exists():
            try:
                db_file.unlink()
            except OSError:
                pass
