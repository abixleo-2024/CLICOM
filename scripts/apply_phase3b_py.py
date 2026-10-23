"""
apply_phase3b_py.py — Update native_engine.py and live_room.py for Phase 3B.
"""

from pathlib import Path

root = Path(__file__).resolve().parent.parent

# 1. Update client/native_engine.py
ne_path = root / "client" / "native_engine.py"
ne_code = ne_path.read_text(encoding="utf-8")

old_prototypes = """        lib.clicom_audio_set_mock_backend.restype = ctypes.c_int32
        lib.clicom_audio_set_mock_backend.argtypes = [ctypes.c_void_p, ctypes.c_bool]

        lib.clicom_get_active_session_id.restype = ctypes.c_int32
        lib.clicom_get_active_session_id.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]"""

new_prototypes = """        lib.clicom_audio_set_mock_backend.restype = ctypes.c_int32
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
        lib.clicom_get_active_session_id.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]"""

if old_prototypes not in ne_code:
    old_prototypes = old_prototypes.replace("\n", "\r\n")
    new_prototypes = new_prototypes.replace("\n", "\r\n")

if old_prototypes in ne_code:
    ne_code = ne_code.replace(old_prototypes, new_prototypes, 1)

old_methods = """    def get_active_session_id(self) -> str:
        \"\"\"Retrieve current active room session UUID string.\"\"\"
        handle = self._ensure_active()
        buf = ctypes.create_string_buffer(CLICOM_MAX_UUID_LEN)
        rc = self._lib.clicom_get_active_session_id(handle, buf, ctypes.c_size_t(CLICOM_MAX_UUID_LEN))
        self._check_call(rc)
        return buf.value.decode("utf-8", errors="replace")"""

new_methods = """    def get_active_session_id(self) -> str:
        \"\"\"Retrieve current active room session UUID string.\"\"\"
        handle = self._ensure_active()
        buf = ctypes.create_string_buffer(CLICOM_MAX_UUID_LEN)
        rc = self._lib.clicom_get_active_session_id(handle, buf, ctypes.c_size_t(CLICOM_MAX_UUID_LEN))
        self._check_call(rc)
        return buf.value.decode("utf-8", errors="replace")

    def audio_get_backend(self) -> tuple[int, bool]:
        \"\"\"Query active audio backend (backend_type, is_mock).\"\"\"
        handle = self._ensure_active()
        backend = ctypes.c_int32(0)
        is_mock = ctypes.c_bool(False)
        rc = self._lib.clicom_audio_get_backend(handle, ctypes.byref(backend), ctypes.byref(is_mock))
        self._check_call(rc)
        return int(backend.value), bool(is_mock.value)

    def audio_get_device_counts(self) -> tuple[int, int]:
        \"\"\"Query physical input and output audio devices detected on the host.\"\"\"
        handle = self._ensure_active()
        inputs = ctypes.c_uint32(0)
        outputs = ctypes.c_uint32(0)
        rc = self._lib.clicom_audio_get_device_counts(handle, ctypes.byref(inputs), ctypes.byref(outputs))
        self._check_call(rc)
        return int(inputs.value), int(outputs.value)

    def get_floor_status(self) -> tuple[bool, bool, str]:
        \"\"\"Query server-authoritative PTT floor status (is_held, is_held_by_me, holder_id_or_name).\"\"\"
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
        \"\"\"Refresh local room participants table from the server.\"\"\"
        handle = self._ensure_active()
        rc = self._lib.clicom_network_refresh_participants(handle)
        self._check_call(rc)"""

if old_methods not in ne_code:
    old_methods = old_methods.replace("\n", "\r\n")
    new_methods = new_methods.replace("\n", "\r\n")

if old_methods in ne_code:
    ne_code = ne_code.replace(old_methods, new_methods, 1)

ne_path.write_text(ne_code, encoding="utf-8")
print("Updated client/native_engine.py")

# 2. Update client/screens/live_room.py
live_room_path = root / "client" / "screens" / "live_room.py"
live_room_content = '''"""
Live Tactical Room Screen for CLICOM (Phase 3B).
Integrates real-time member sidebar, server-authoritative PTT floor arbitration,
Opus voice metrics, real microphone vs mock backend detection, and connection telemetry.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Label, Static

from client.native_engine import (
    ClicomAudioEngineState,
    ClicomConnectionState,
    ClicomError,
    NativeCallError,
)

if TYPE_CHECKING:
    from client.app import ClicomApp


class LiveRoomScreen(Screen):
    """Live tactical voice room dashboard."""

    BINDINGS = [
        Binding("m", "toggle_mic", "Toggle Mic", priority=True),
        Binding("p", "toggle_ptt", "Toggle PTT", priority=True),
        Binding("t", "transmit", "Transmit PTT", priority=True),
        Binding("r", "release_floor", "Release PTT", priority=True),
        Binding("plus", "gain_up", "Gain +", priority=True),
        Binding("minus", "gain_down", "Gain -", priority=True),
        Binding("l", "leave_room", "Leave Room", priority=True),
        Binding("escape", "leave_room", "Back", priority=True),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._last_refresh_parts_time = 0.0
        self._last_frames_sent = 0
        self._last_frames_recv = 0
        self._disconn_notified = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="live-container"):
            # Header Bar: Room Info & Connection State
            with Horizontal(id="live-header", classes="panel"):
                yield Static("", id="lbl-live-room-info")
                yield Static("", id="lbl-live-conn-state")

            # Main split: Member Sidebar (left) + Audio / Telemetry (right)
            with Horizontal(id="live-body"):
                # Left Sidebar: Members
                with Vertical(id="sidebar-members", classes="panel"):
                    yield Label("ROOM MEMBERSHIP", classes="panel-header")
                    yield DataTable(id="members-table", cursor_type="row")
                    yield Static("", id="lbl-active-speaker", classes="speaker-card")

                # Right Panel: Audio and Hardware
                with Vertical(id="panel-controls", classes="panel"):
                    yield Label("MICROPHONE & FLOOR CONTROLS", classes="panel-header")

                    with Horizontal(classes="control-row"):
                        yield Button("Mute Mic (M)", id="btn-toggle-mic", classes="btn-ctrl")
                        yield Button("Request Floor (P/T)", id="btn-toggle-ptt", variant="primary", classes="btn-ctrl")
                        yield Button("Leave Room (L)", id="btn-leave-room", variant="error", classes="btn-ctrl")

                    with Vertical(id="mic-detail-box"):
                        yield Static("", id="lbl-mic-detail")
                        yield Static("", id="lbl-ptt-detail")
                        yield Static("", id="lbl-tx-status")
                        yield Static("", id="lbl-gain-detail")

                    yield Label("VOICE ENGINE & AUDIO HARDWARE (C11 NATIVE)", classes="panel-header")
                    with Vertical(id="audio-detail-box"):
                        yield Static("", id="lbl-audio-backend")
                        yield Static("", id="lbl-audio-engine-state")
                        yield Static("", id="lbl-audio-queue-status")
                        yield Static("", id="lbl-audio-metrics")

                    yield Label("TLS 1.3 TELEMETRY & WIRE TRANSPORT", classes="panel-header")
                    with Vertical(id="telemetry-detail-box"):
                        yield Static("", id="lbl-telemetry-status")
                        yield Static("", id="lbl-telemetry-packets")

            # Bottom Status Banner
            yield Static(
                "STATUS: Real-time half-duplex voice active. Server-authoritative PTT floor arbitration over TLS 1.3.",
                id="lbl-live-bottom-banner",
                classes="notice-box-bottom",
            )

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#members-table", DataTable)
        table.add_columns("ID", "Operator", "Role", "Status")

        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            try:
                status = app.engine.get_audio_status()
                if status.state != ClicomAudioEngineState.RUNNING:
                    app.engine.audio_start()
            except NativeCallError as e:
                self.notify(f"Audio Device Error: {e.error_message}", title="Audio Initialization", severity="warning")
            except Exception as e:
                self.notify(f"Audio start failed: {e}", title="Audio Initialization", severity="warning")

        self.refresh_room_data()
        self.set_interval(0.25, self.refresh_room_data)

    def on_unmount(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            try:
                if app.engine.get_audio_status().state == ClicomAudioEngineState.RUNNING:
                    app.engine.audio_stop()
            except Exception:
                pass

    def refresh_room_data(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        engine = app.engine

        if not engine or not engine.is_alive:
            return

        try:
            # 1. Non-blocking network event pump
            if engine.is_network_connected():
                try:
                    engine.network_poll(0)
                except Exception:
                    pass

                # Periodically refresh participants table from server
                now = time.monotonic()
                if now - self._last_refresh_parts_time >= 1.5:
                    self._last_refresh_parts_time = now
                    try:
                        engine.network_refresh_participants()
                    except Exception:
                        pass

            # 2. Query native snapshots
            room = engine.get_room_state()
            mic = engine.get_mic_state()
            audio = engine.get_audio_status()
            telem = engine.get_telemetry()
            conn = engine.get_connection_state()
            participants = engine.get_participants()
            floor_held, held_by_me, floor_holder = engine.get_floor_status()

            # Query audio backend & hardware devices
            try:
                backend_code, is_mock = engine.audio_get_backend()
                in_devs, out_devs = engine.audio_get_device_counts()
            except Exception:
                backend_code, is_mock = 0, True
                in_devs, out_devs = 1, 1

            # 3. Handle Disconnect Safety
            if engine.is_network_connected() is False and conn in (ClicomConnectionState.DISCONNECTED, ClicomConnectionState.FAILED):
                if not self._disconn_notified:
                    self._disconn_notified = True
                    self.notify("Server connection lost. Voice session terminated.", title="Network Alert", severity="error")

            # 4. Room Header Info
            key_display = f" | KEY: [yellow]{room.join_key}[/]" if room.join_key else ""
            self.query_one("#lbl-live-room-info", Static).update(
                f"[bold cyan]ROOM:[/] [bold white]{room.room_id}[/]{key_display} "
                f"[dim]({len(participants)} Participants)[/]"
            )

            conn_names = {0: "DISCONNECTED", 1: "CONNECTING", 2: "CONNECTED", 3: "RECONNECTING", 4: "FAILED"}
            c_str = conn_names.get(int(conn), "UNKNOWN")
            c_color = "green" if conn == ClicomConnectionState.CONNECTED else "red"
            mode_tag = "SERVER TLS 1.3" if engine.is_network_connected() else "LOCAL STANDALONE"
            self.query_one("#lbl-live-conn-state", Static).update(
                f"[dim]NET:[/] [bold {c_color}]{c_str} ({mode_tag})[/]"
            )

            # 5. Members Table
            table = self.query_one("#members-table", DataTable)
            table.clear()
            for p in participants:
                is_host = "Host" if ("Host" in p.display_name or p.participant_id == room.room_id) else "Member"
                if floor_held and (p.participant_id == floor_holder or p.display_name == floor_holder):
                    status_badge = "[bold green]🎙️ TRANSMITTING[/]"
                elif p.is_speaking:
                    status_badge = "[bold green]🎙️ TALKING[/]"
                elif p.is_muted:
                    status_badge = "[dim red]🔇 MUTED[/]"
                else:
                    status_badge = "[dim]IDLE[/]"
                table.add_row(p.participant_id[:12] if len(p.participant_id) > 12 else p.participant_id, p.display_name, is_host, status_badge)

            # 6. Floor Ownership & Active Transmitter Card
            spk_lbl = self.query_one("#lbl-active-speaker", Static)
            if held_by_me:
                if mic.is_muted:
                    spk_lbl.update("[bold yellow]▲ FLOOR HELD — TRANSMISSION SUPPRESSED (MIC MUTED)[/]")
                else:
                    spk_lbl.update("[bold green]● TRANSMITTING LIVE AUDIO TO ROOM[/] [dim](Floor Held by You)[/]")
            elif floor_held:
                display_holder = floor_holder if floor_holder else "REMOTE NODE"
                spk_lbl.update(f"[bold red]■ FLOOR BUSY — ACTIVE TRANSMITTER:[/] [bold white]{display_holder}[/]")
            else:
                spk_lbl.update("[dim]○ FLOOR FREE — Ready to Transmit (Press P or T)[/]")

            # 7. Mic & Floor Details
            mic_btn = self.query_one("#btn-toggle-mic", Button)
            ptt_btn = self.query_one("#btn-toggle-ptt", Button)

            if mic.is_muted:
                mic_btn.label = "Unmute Mic (M)"
                mic_btn.variant = "warning"
                mic_status_str = "[bold red]MUTED[/] [dim](Audio Capture Suspended)[/]"
            else:
                mic_btn.label = "Mute Mic (M)"
                mic_btn.variant = "default"
                mic_status_str = "[bold green]LIVE / ACTIVE[/]"

            if held_by_me:
                ptt_btn.label = "Release Floor (P/R)"
                ptt_btn.variant = "warning"
                ptt_status_str = "[bold green]HELD BY YOU (Authoritative Lease Active)[/]"
            elif floor_held:
                ptt_btn.label = "Floor Busy (P)"
                ptt_btn.variant = "error"
                ptt_status_str = f"[bold red]OCCUPIED BY {floor_holder}[/]"
            else:
                ptt_btn.label = "Request Floor (P/T)"
                ptt_btn.variant = "primary"
                ptt_status_str = "[dim]FREE / IDLE[/]"

            # Transmission Status
            if held_by_me and not mic.is_muted:
                tx_status_str = f"[bold green]TRANSMITTING[/] ({telem.frames_sent} frames sent over wire)"
            elif held_by_me and mic.is_muted:
                tx_status_str = "[bold yellow]SUPPRESSED[/] (Local mute halts wire transmission)"
            elif telem.frames_received > self._last_frames_recv:
                tx_status_str = f"[bold cyan]RECEIVING AUDIO[/] ({telem.frames_received} frames received)"
            else:
                tx_status_str = "[dim]STANDBY / LISTENING[/]"

            self._last_frames_sent = telem.frames_sent
            self._last_frames_recv = telem.frames_received

            self.query_one("#lbl-mic-detail", Static).update(f"Microphone State: {mic_status_str}")
            self.query_one("#lbl-ptt-detail", Static).update(f"Floor Authority: {ptt_status_str}")
            self.query_one("#lbl-tx-status", Static).update(f"Transmission Status: {tx_status_str}")
            self.query_one("#lbl-gain-detail", Static).update(f"Software Input Gain: [cyan]{mic.gain:.2f}x[/] (+{mic.gain*6.0 - 6.0:.1f} dB)")

            # 8. Audio Backend & Engine Metrics
            if is_mock:
                backend_str = "[bold yellow]Synthetic Mock Virtual Device[/] [dim](In-Memory Testing Backend)[/]"
            else:
                backend_str = f"[bold green]Windows Multimedia (WinMM)[/] [dim]({in_devs} Mic Inputs, {out_devs} Outputs detected)[/]"

            engine_state_str = f"[bold green]{audio.state.name}[/] [dim](Opus 16000 Hz Mono, 20ms Frames)[/]"

            q_str = f"Capture: {audio.capture_queue_depth}/{audio.capture_queue_capacity} frames | Playback: {audio.playback_queue_depth}/{audio.playback_queue_capacity} frames"
            self.query_one("#lbl-audio-backend", Static).update(f"Audio Hardware: {backend_str}")
            self.query_one("#lbl-audio-engine-state", Static).update(f"Engine State: {engine_state_str}")
            self.query_one("#lbl-audio-queue-status", Static).update(f"Bounded FIFO Queues: [bold white]{q_str}[/]")
            self.query_one("#lbl-audio-metrics", Static).update(
                f"Frames Pushed: {audio.total_frames_pushed} | Popped: {audio.total_frames_popped} | Dropped: {audio.total_frames_dropped}"
            )

            # 9. Telemetry Details
            self.query_one("#lbl-telemetry-status", Static).update(
                f"RTT: {telem.rtt_ms} ms | Loss: {telem.packet_loss_pct:.1f}% | Jitter: {telem.jitter_ms:.1f} ms"
            )
            self.query_one("#lbl-telemetry-packets", Static).update(
                f"Frames Sent: [bold green]{telem.frames_sent}[/] ({telem.bytes_sent} B) | "
                f"Frames Received: [bold cyan]{telem.frames_received}[/] ({telem.bytes_received} B)"
            )
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-toggle-mic":
            self.action_toggle_mic()
        elif btn_id == "btn-toggle-ptt":
            self.action_toggle_ptt()
        elif btn_id == "btn-leave-room":
            self.action_leave_room()

    def action_toggle_mic(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            current = app.engine.is_mic_muted()
            new_state = not current
            app.engine.set_mic_muted(new_state)
            state_text = "MUTED" if new_state else "UNMUTED (Live)"
            self.notify(f"Microphone is now {state_text}", title="Microphone State")
            self.refresh_room_data()

    def action_transmit(self) -> None:
        """Explicitly request floor from server (Transmit)."""
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            if app.engine.is_ptt_active():
                return
            try:
                app.engine.set_ptt_active(True)
                self.notify("Floor granted by server! Transmitting voice...", title="Floor Granted")
            except NativeCallError as e:
                if e.error_code == ClicomError.ERR_PTT_BUSY:
                    self.notify("PTT Floor is currently held by another member!", title="Floor Busy", severity="warning")
                else:
                    self.notify(f"PTT Error: {e.error_message}", title="PTT Error", severity="error")
            self.refresh_room_data()

    def action_release_floor(self) -> None:
        """Explicitly release held floor."""
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            if not app.engine.is_ptt_active():
                return
            try:
                app.engine.set_ptt_active(False)
                self.notify("Floor released. Microphone capture stopped.", title="Floor Released")
            except Exception as e:
                self.notify(f"Floor release error: {e}", title="Floor Release", severity="error")
            self.refresh_room_data()

    def action_toggle_ptt(self) -> None:
        """Toggle PTT floor state."""
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            if app.engine.is_ptt_active():
                self.action_release_floor()
            else:
                self.action_transmit()

    def action_gain_up(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            curr = app.engine.get_mic_gain()
            new_gain = min(2.0, curr + 0.1)
            app.engine.set_mic_gain(new_gain)
            self.refresh_room_data()

    def action_gain_down(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            curr = app.engine.get_mic_gain()
            new_gain = max(0.0, curr - 0.1)
            app.engine.set_mic_gain(new_gain)
            self.refresh_room_data()

    def action_leave_room(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            try:
                if app.engine.is_ptt_active():
                    try:
                        app.engine.set_ptt_active(False)
                    except Exception:
                        pass
                if app.engine.get_audio_status().state == ClicomAudioEngineState.RUNNING:
                    app.engine.audio_stop()
            except Exception:
                pass
            if app.engine.is_network_connected():
                try:
                    app.engine.network_leave_room()
                except Exception:
                    pass
            else:
                try:
                    app.engine.room_leave()
                except Exception:
                    pass
        self.notify("Left tactical room. Audio hardware and network released.", title="Room State")
        self.app.pop_screen()
'''

live_room_path.write_text(live_room_content, encoding="utf-8")
print("Updated client/screens/live_room.py")
