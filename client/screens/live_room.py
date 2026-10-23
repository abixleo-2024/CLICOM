"""
Live Room screen for CLICOM Textual Interface (Half-Duplex Tactical Voice).
"""

from __future__ import annotations

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
    """Live tactical voice room dashboard with half-duplex floor control."""

    BINDINGS = [
        Binding("t", "toggle_ptt", "Push to Talk (T)", priority=True),
        Binding("p", "toggle_ptt", "Push to Talk (P)", priority=True),
        Binding("m", "toggle_mic", "Toggle Mic", priority=True),
        Binding("plus", "gain_up", "Gain +", priority=True),
        Binding("minus", "gain_down", "Gain -", priority=True),
        Binding("l", "leave_room", "Leave Room", priority=True),
        Binding("escape", "leave_room", "Back", priority=True),
    ]

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._disconn_notified = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="live-container"):
            # Header Bar: Room Info & Join Key Always Prominently Visible
            with Horizontal(id="live-header", classes="panel"):
                yield Static("", id="lbl-live-room-info")
                yield Static("", id="lbl-live-conn-state")

            # Main split: Member Sidebar (left) + Audio Controls (right)
            with Horizontal(id="live-body"):
                # Left Sidebar: Members
                with Vertical(id="sidebar-members", classes="panel"):
                    yield Label("ROOM MEMBERSHIP", classes="panel-header")
                    yield DataTable(id="members-table", cursor_type="row")
                    yield Static("", id="lbl-active-speaker", classes="speaker-card")

                # Right Panel: Half-Duplex Floor & Microphone Controls
                with Vertical(id="panel-controls", classes="panel"):
                    yield Label("HALF-DUPLEX FLOOR & VOICE CONTROLS", classes="panel-header")

                    with Horizontal(classes="control-row"):
                        yield Button("Push to Talk (T)", id="btn-toggle-ptt", variant="primary", classes="btn-ctrl")
                        yield Button("Mute Mic (M)", id="btn-toggle-mic", classes="btn-ctrl")
                        yield Button("Leave Room (L)", id="btn-leave-room", variant="error", classes="btn-ctrl")

                    with Vertical(id="mic-detail-box"):
                        yield Static("", id="lbl-floor-detail")
                        yield Static("", id="lbl-mic-detail")
                        yield Static("", id="lbl-gain-detail")
                        yield Static("", id="lbl-voice-instructions")

            # Bottom Status Banner
            yield Static(
                "STATUS: Half-duplex tactical voice active. Server-authoritative floor arbitration over TLS 1.3.",
                id="lbl-live-bottom-banner",
                classes="notice-box-bottom",
            )

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#members-table", DataTable)
        table.add_columns("ID", "Operator", "Role", "Voice Status")

        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            try:
                # Requirement: Always set mic muted initially
                app.engine.set_mic_muted(True)

                status = app.engine.get_audio_status()
                if status.state != ClicomAudioEngineState.RUNNING:
                    app.engine.audio_start()
            except NativeCallError as e:
                self.notify(f"Audio Device Error: {e.error_message}", title="Audio Initialization", severity="warning")
            except Exception as e:
                self.notify(f"Audio start failed: {e}", title="Audio Initialization", severity="warning")

        # Initial refresh of participant roster from server
        self._refresh_participants()
        self.refresh_room_data()
        self.set_interval(0.25, self.refresh_room_data)
        self.set_interval(0.010, self._fast_network_pump)
        # Periodic server participant sync so all clients show updated participant counts
        self.set_interval(1.0, self._refresh_participants)

    def _refresh_participants(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        engine = app.engine
        if engine and engine.is_alive and engine.is_network_connected():
            try:
                engine.network_refresh_participants()
            except Exception:
                pass

    def _fast_network_pump(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        engine = app.engine
        if engine and engine.is_alive and engine.is_network_connected():
            try:
                engine.network_poll(0)
            except Exception:
                pass

    def on_unmount(self) -> None:
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

            # 2. Query native snapshots
            room = engine.get_room_state()
            mic = engine.get_mic_state()
            conn = engine.get_connection_state()
            participants = engine.get_participants()
            floor_held, held_by_me, floor_holder = engine.get_floor_status()

            # 3. Handle Disconnect Safety
            if engine.is_network_connected() is False and conn in (ClicomConnectionState.DISCONNECTED, ClicomConnectionState.FAILED):
                if not self._disconn_notified:
                    self._disconn_notified = True
                    self.notify("Server connection lost. Voice session terminated.", title="Network Alert", severity="error")

            # 4. Room Header Info: JOIN KEY IS ALWAYS PROMINENTLY VISIBLE
            display_room_id = app.current_room_name or room.room_id or "TACTICAL-ROOM"
            display_key = room.join_key or app.current_room_key or "N/A"

            self.query_one("#lbl-live-room-info", Static).update(
                f"[bold cyan]ROOM:[/] [bold white]{display_room_id}[/]  |  "
                f"[bold green]INVITATION KEY:[/] [bold yellow on #1f2a38]  {display_key}  [/]  "
                f"[dim]({len(participants)} Participants connected)[/]"
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
                elif p.is_muted:
                    status_badge = "[dim red]🔇 MUTED[/]"
                else:
                    status_badge = "[dim]LISTENING[/]"
                table.add_row(
                    p.participant_id[:12] if len(p.participant_id) > 12 else p.participant_id,
                    p.display_name,
                    is_host,
                    status_badge,
                )

            # 6. Active Voice Status Card & Half-Duplex Floor Arbitration
            spk_lbl = self.query_one("#lbl-active-speaker", Static)
            ptt_btn = self.query_one("#btn-toggle-ptt", Button)
            mic_btn = self.query_one("#btn-toggle-mic", Button)

            if held_by_me:
                spk_lbl.update("[bold green]🎙️ YOU HOLD THE FLOOR — TRANSMITTING AUDIO[/]")
                ptt_btn.label = "Release Floor (T)"
                ptt_btn.variant = "warning"
                ptt_btn.disabled = False
                mic_btn.disabled = False
                floor_status_str = "[bold green]HELD BY YOU (Active Transmitter)[/]"
            elif floor_held:
                display_holder = floor_holder if floor_holder else "REMOTE NODE"
                spk_lbl.update(f"[bold red]■ FLOOR BUSY — HELD BY {display_holder}[/]")
                ptt_btn.label = f"Floor Busy: {display_holder}"
                ptt_btn.variant = "error"
                ptt_btn.disabled = True
                mic_btn.disabled = True
                floor_status_str = f"[bold red]BUSY ({display_holder})[/]"
            else:
                spk_lbl.update("[dim]○ FLOOR FREE — Press [T] or click 'Push to Talk' to speak[/]")
                ptt_btn.label = "Push to Talk (T)"
                ptt_btn.variant = "primary"
                ptt_btn.disabled = False
                mic_btn.disabled = False
                floor_status_str = "[bold cyan]FREE / READY[/]"

            # 7. Mic Controls & Details (Default Muted / Blocked when floor is busy)
            if floor_held and not held_by_me:
                mic_btn.label = "Mic Blocked (Floor Busy)"
                mic_btn.variant = "error"
                mic_status_str = f"[bold red]BLOCKED[/] [dim](Remote floor held by {floor_holder or 'peer'})[/]"
            elif mic.is_muted:
                mic_btn.label = "Unmute Mic (M)"
                mic_btn.variant = "warning"
                mic_status_str = "[bold red]MUTED[/] [dim](Microphone capture suspended)[/]"
            else:
                mic_btn.label = "Mute Mic (M)"
                mic_btn.variant = "default"
                mic_status_str = "[bold green]READY (Unmuted)[/]"

            self.query_one("#lbl-floor-detail", Static).update(f"Floor Authority: {floor_status_str}")
            self.query_one("#lbl-mic-detail", Static).update(f"Microphone State: {mic_status_str}")
            self.query_one("#lbl-gain-detail", Static).update(
                f"Software Input Gain: [cyan]{mic.gain:.2f}x[/] (+{mic.gain*6.0 - 6.0:.1f} dB) [dim](Press + / -)[/]"
            )
            self.query_one("#lbl-voice-instructions", Static).update(
                "[dim cyan]Half-duplex voice active. Press [bold white]T[/] or [bold white]P[/] to acquire floor and speak.\n"
                "Press [bold white]T[/] again to release floor. Press [bold white]M[/] to toggle mute.[/]"
            )
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-toggle-ptt":
            self.action_toggle_ptt()
        elif btn_id == "btn-toggle-mic":
            self.action_toggle_mic()
        elif btn_id == "btn-leave-room":
            self.action_leave_room()

    def action_toggle_ptt(self) -> None:
        """Toggle half-duplex PTT floor state."""
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            floor_held, held_by_me, floor_holder = app.engine.get_floor_status()
            if floor_held and not held_by_me:
                self.notify(f"Floor is held by {floor_holder or 'another operator'}. Your microphone is blocked.", title="Floor Busy", severity="warning")
                return

            if app.engine.is_ptt_active():
                try:
                    app.engine.set_ptt_active(False)
                    self.notify("Floor released. Floor is now free.", title="Floor Released")
                except Exception as e:
                    self.notify(f"Floor release error: {e}", title="Floor Error", severity="error")
            else:
                try:
                    app.engine.set_ptt_active(True)
                    self.notify("Floor granted by server! You are transmitting voice.", title="Floor Granted")
                except NativeCallError as e:
                    if e.error_code == ClicomError.ERR_PTT_BUSY:
                        self.notify("Floor is currently held by another member!", title="Floor Busy", severity="warning")
                    else:
                        self.notify(f"PTT Error: {e.error_message}", title="PTT Error", severity="error")
            self.refresh_room_data()

    def action_toggle_mic(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            floor_held, held_by_me, floor_holder = app.engine.get_floor_status()
            if floor_held and not held_by_me:
                self.notify(f"Microphone is blocked while {floor_holder or 'another operator'} is transmitting.", title="Mic Blocked", severity="warning")
                return

            current = app.engine.is_mic_muted()
            new_state = not current
            app.engine.set_mic_muted(new_state)
            state_text = "MUTED" if new_state else "UNMUTED"
            self.notify(f"Microphone is now {state_text}", title="Microphone State")
            self.refresh_room_data()

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
