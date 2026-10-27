"""
Main Menu screen for the CLICOM Textual Terminal Interface.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static

if TYPE_CHECKING:
    from client.app import ClicomApp


class DisplayNameModal(ModalScreen[str]):
    """Modal dialog to configure local client display name."""

    BINDINGS = [
        Binding("escape", "dismiss_modal", "Cancel", priority=True),
    ]

    DEFAULT_CSS = """
    DisplayNameModal {
        align: center middle;
    }
    #name-dialog {
        width: 60;
        height: auto;
        border: heavy $accent;
        background: #111822;
        padding: 1 2;
    }
    #name-title {
        color: #00ff88;
        text-style: bold;
        margin-bottom: 1;
    }
    #name-input {
        margin: 1 0;
        border: tall #00d4ff;
    }
    #name-buttons {
        margin-top: 1;
        align: right middle;
    }
    .modal-btn {
        margin-left: 1;
    }
    """

    def __init__(self, current_name: str):
        super().__init__()
        self._current_name = current_name

    def compose(self) -> ComposeResult:
        with Vertical(id="name-dialog"):
            yield Label("CONFIGURE LOCAL DISPLAY NAME", id="name-title")
            yield Static("Enter a user label (1-63 chars). This is updated in the native C engine.", classes="dim-text")
            yield Input(value=self._current_name, id="name-input", max_length=63)
            with Horizontal(id="name-buttons"):
                yield Button("Cancel [Esc]", id="btn-cancel", classes="modal-btn")
                yield Button("Save [Enter]", variant="primary", id="btn-save", classes="modal-btn")

    def action_dismiss_modal(self) -> None:
        self.dismiss(self._current_name)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            val = self.query_one("#name-input", Input).value.strip()
            self.dismiss(val if val else self._current_name)
        else:
            self.dismiss(self._current_name)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        val = event.value.strip()
        self.dismiss(val if val else self._current_name)


class MainMenuScreen(Screen):
    """Main dashboard menu for CLICOM."""

    BINDINGS = [
        Binding("1", "nav_create", "Create Room", priority=True),
        Binding("2", "nav_join", "Join Room", priority=True),
        Binding("3", "config_name", "Display Name", priority=True),
        Binding("m", "toggle_mic", "Toggle Mic", priority=True),
        Binding("q", "app.quit", "Exit", priority=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="main-container"):
            # Tactical Header
            yield Static(
                "┌──────────────────────────────────────────────────────────────────────────────┐\n"
                "│             CLICOM TACTICAL TERMINAL COMMUNICATIONS — v2.0.0                 │\n"
                "└──────────────────────────────────────────────────────────────────────────────┘",
                id="tactical-banner",
            )

            # System Status Card
            with Vertical(id="status-box", classes="panel"):
                yield Label("SYSTEM TELEMETRY & HARDWARE STATUS", classes="panel-header")
                with Horizontal(classes="status-row"):
                    yield Static("", id="lbl-node-name")
                    yield Static("", id="lbl-engine-status")
                with Horizontal(classes="status-row"):
                    yield Static("", id="lbl-net-status")
                    yield Static("", id="lbl-mic-status")
                    yield Static("", id="lbl-audio-status")

            # Main Options
            with Vertical(id="menu-options", classes="panel"):
                yield Label("PRIMARY DIRECTIVES", classes="panel-header")
                yield Button("1. Create New Tactical Room", id="btn-create", classes="menu-button")
                yield Button("2. Join Room via Invitation Key", id="btn-join", classes="menu-button")
                yield Button("3. Configure Local Display Name", id="btn-config-name", classes="menu-button")
                yield Button("Q. Exit CLICOM", id="btn-exit", variant="error", classes="menu-button")

            # Footer notification / security banner
            yield Static(
                "SECURITY ADVISORY: Local C native state is active. Protocol CLIPv1.0. All buffers bounded.",
                id="sec-advisory",
            )

        yield Footer()

    def on_mount(self) -> None:
        self.update_status()
        self.set_interval(1.0, self.update_status)

    def update_status(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        engine = app.engine

        if engine and engine.is_alive:
            try:
                name = engine.get_display_name()
                status = engine.get_status()
                audio_status = engine.get_audio_status()
                is_net = engine.is_network_connected()

                mic_str = "[bold red]MUTED[/]" if status.is_mic_muted else "[bold green]LIVE[/]"
                ptt_str = "[bold yellow]FLOOR HELD[/]" if status.is_ptt_active else "IDLE"
                audio_str = "[bold green]RUNNING[/]" if audio_status.state == 2 else "[dim]STOPPED[/]"
                net_str = "[bold green]CONNECTED (TLS 1.3)[/]" if is_net else "[dim]OFFLINE (Local Mode)[/]"

                self.query_one("#lbl-node-name", Static).update(
                    f"[dim]OPERATOR NODE:[/] [bold cyan]{name}[/]"
                )
                self.query_one("#lbl-engine-status", Static).update(
                    f"[dim]C CORE STATUS:[/] [bold green]ONLINE (C11 v{engine.get_version_string()})[/]"
                )
                self.query_one("#lbl-net-status", Static).update(
                    f"[dim]NETWORK:[/] {net_str}"
                )
                self.query_one("#lbl-mic-status", Static).update(
                    f"[dim]MIC:[/] {mic_str}  [dim]PTT:[/] {ptt_str}"
                )
                self.query_one("#lbl-audio-status", Static).update(
                    f"[dim]AUDIO:[/] {audio_str}"
                )
            except Exception as e:
                self.query_one("#lbl-engine-status", Static).update(f"[bold red]C CORE ERROR:[/] {e}")
        else:
            self.query_one("#lbl-node-name", Static).update("[dim]OPERATOR NODE:[/] [bold red]OFFLINE[/]")
            self.query_one("#lbl-engine-status", Static).update("[bold red]C CORE:[/] DISCONNECTED")
            self.query_one("#lbl-net-status", Static).update("[dim]NETWORK:[/] N/A")
            self.query_one("#lbl-mic-status", Static).update("[dim]MIC:[/] N/A")
            self.query_one("#lbl-audio-status", Static).update("[dim]AUDIO:[/] N/A")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-create":
            self.action_nav_create()
        elif btn_id == "btn-join":
            self.action_nav_join()
        elif btn_id == "btn-config-name":
            self.action_config_name()
        elif btn_id == "btn-exit":
            self.app.exit()

    def action_nav_create(self) -> None:
        self.app.push_screen("create_room")

    def action_nav_join(self) -> None:
        self.app.push_screen("join_room")

    def action_config_name(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        current_name = app.engine.get_display_name() if app.engine and app.engine.is_alive else "OPERATOR"

        def _on_modal_close(new_name: str) -> None:
            if new_name and app.engine and app.engine.is_alive:
                try:
                    app.engine.set_display_name(new_name)
                    self.update_status()
                    self.notify(f"Display name updated to: {new_name}", title="Native Engine")
                except Exception as e:
                    self.notify(f"Failed to set display name: {e}", severity="error")

        self.app.push_screen(DisplayNameModal(current_name), _on_modal_close)

    def action_toggle_mic(self) -> None:
        app: ClicomApp = self.app  # type: ignore
        if app.engine and app.engine.is_alive:
            try:
                current = app.engine.is_mic_muted()
                app.engine.set_mic_muted(not current)
                self.update_status()
                state = "MUTED" if not current else "UNMUTED"
                self.notify(f"Microphone {state}", title="Hardware Control")
            except Exception as e:
                self.notify(f"Mic toggle failed: {e}", severity="error")
