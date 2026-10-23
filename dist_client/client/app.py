"""
Main Application class for the CLICOM Textual Terminal Interface.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Label, Static

from client.config import DEFAULT_DISPLAY_NAME
from client.native_engine import DllNotFoundError, NativeEngine
from client.screens.create_room import CreateRoomScreen
from client.screens.instant_connection import InstantConnectionScreen
from client.screens.join_room import JoinRoomScreen
from client.screens.live_room import LiveRoomScreen
from client.screens.main_menu import MainMenuScreen


class DllErrorModal(ModalScreen[None]):
    """Modal displayed when libclicom_engine.dll is missing or cannot be loaded."""

    DEFAULT_CSS = """
    DllErrorModal {
        align: center middle;
    }
    #error-dialog {
        width: 72;
        height: auto;
        border: heavy #ff5555;
        background: #140c0f;
        padding: 1 2;
    }
    #error-title {
        color: #ff5555;
        text-style: bold;
        margin-bottom: 1;
    }
    #error-body {
        margin: 1 0;
        color: #f8f8f2;
    }
    #error-btn {
        margin-top: 1;
        align: center middle;
    }
    """

    def __init__(self, message: str):
        super().__init__()
        self._message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="error-dialog"):
            yield Label("FATAL: NATIVE ENGINE DLL NOT FOUND", id="error-title")
            yield Static(self._message, id="error-body")
            yield Button("Exit [Enter]", variant="error", id="error-btn")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.app.exit(1)


class ClicomApp(App):
    """CLICOM Tactical Communications Terminal Application."""

    TITLE = "CLICOM Tactical Comms"
    SUB_TITLE = "v2.0.0 — Native C Foundation"

    CSS = """
    Screen {
        background: #090c10;
        color: #c9d1d9;
    }

    #main-container, #form-container, #instant-container, #live-container {
        padding: 1 2;
    }

    #tactical-banner {
        color: #00ff88;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }

    .screen-title {
        color: #00d4ff;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }

    .panel {
        background: #10151c;
        border: tall #1f2a38;
        padding: 1 2;
        margin-bottom: 1;
    }

    .panel:focus-within {
        border: tall #00ff88;
    }

    .panel-header {
        color: #00d4ff;
        text-style: bold;
        margin-bottom: 1;
        border-bottom: solid #1f2a38;
    }

    .menu-button {
        width: 100%;
        margin-bottom: 1;
        background: #161f2c;
        color: #00ff88;
        border: tall #223247;
    }

    .menu-button:hover {
        background: #00ff88;
        color: #090c10;
        text-style: bold;
    }

    .menu-button:focus {
        border: tall #00d4ff;
    }

    .btn-primary {
        background: #005f4b;
        color: #00ff88;
        border: tall #00ff88;
    }

    .btn-primary:hover {
        background: #00ff88;
        color: #090c10;
    }

    .btn-secondary {
        background: #1f2833;
        color: #c9d1d9;
        border: tall #334455;
    }

    .btn-ctrl {
        margin-right: 1;
        background: #182230;
        color: #00d4ff;
        border: tall #25374d;
    }

    .btn-ctrl:hover {
        background: #00d4ff;
        color: #090c10;
    }

    .button-row {
        margin-top: 1;
        align: right middle;
    }

    .field-label {
        color: #79c0ff;
        margin-top: 1;
    }

    .error-text {
        margin-top: 1;
    }

    .notice-box {
        background: #161b22;
        border: solid #d29922;
        padding: 1;
        margin-top: 1;
        margin-bottom: 1;
    }

    .notice-tag {
        color: #d29922;
        text-style: bold;
    }

    .notice-tag-warn {
        color: #ff7b72;
        text-style: bold;
    }

    .notice-body {
        color: #8b949e;
    }

    .notice-box-bottom {
        color: #8b949e;
        border-top: solid #1f2a38;
        padding-top: 1;
        margin-top: 1;
    }

    #sec-advisory {
        color: #58a6ff;
        text-align: center;
        margin-top: 1;
    }

    /* Live Room layout */
    #live-header {
        height: auto;
        min-height: 4;
        margin-bottom: 1;
        padding: 1 2;
        background: #10151c;
        border: tall #00d4ff;
    }

    #live-body {
        height: auto;
    }

    #sidebar-members {
        width: 42%;
        margin-right: 1;
    }

    #panel-controls {
        width: 58%;
    }

    .speaker-card {
        margin-top: 1;
        padding: 1;
        background: #121922;
        border: solid #1f2a38;
    }

    .control-row {
        margin-bottom: 1;
    }

    #mic-detail-box, #audio-detail-box, #telemetry-detail-box {
        margin-bottom: 1;
        padding-left: 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Exit", show=False),
    ]

    def __init__(
        self,
        dll_path: Optional[str | Path] = None,
        display_name: str = DEFAULT_DISPLAY_NAME,
        server: Optional[str] = None,
        port: int = 8443,
        ca_cert: Optional[str | Path] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._custom_dll_path = dll_path
        self._initial_display_name = display_name
        self._server = server
        self._port = port
        self._ca_cert = ca_cert
        self.engine: Optional[NativeEngine] = None
        self.current_room_key: str = ""
        self.current_room_name: str = ""

    def on_mount(self) -> None:
        try:
            # Initialize native C engine
            self.engine = NativeEngine(
                dll_path=self._custom_dll_path,
                display_name=self._initial_display_name,
            )
            self.engine.init()
            try:
                self.engine.set_mic_muted(True)
            except Exception:
                pass
        except DllNotFoundError as e:
            self.push_screen(DllErrorModal(str(e)))
            return
        except Exception as e:
            self.push_screen(DllErrorModal(f"Failed to initialize native engine:\n{e}"))
            return

        # Attempt server connection if configured
        if self._server:
            try:
                ca_path = str(self._ca_cert) if self._ca_cert else None
                self.engine.network_connect(self._server, self._port, ca_path)
                self.notify(
                    f"Connected to {self._server}:{self._port} via TLS 1.3",
                    title="CLICOM Network",
                )
            except Exception as e:
                self.notify(
                    f"Network connection failed: {e}\nContinuing in local mode.",
                    title="CLICOM Network",
                    severity="warning",
                )

        # Register screens
        self.install_screen(MainMenuScreen(), name="main_menu")
        self.install_screen(CreateRoomScreen(), name="create_room")
        self.install_screen(JoinRoomScreen(), name="join_room")
        self.install_screen(InstantConnectionScreen(), name="instant_connection")
        self.install_screen(LiveRoomScreen(), name="live_room")

        self.push_screen("main_menu")
        self.set_interval(1.0, self._poll_network_heartbeat)

    def _poll_network_heartbeat(self) -> None:
        if self.engine and self.engine.is_alive and self.engine.is_network_connected():
            try:
                self.engine.network_poll(0)
            except Exception:
                pass

    def action_quit(self) -> None:
        if self.engine is not None:
            try:
                if self.engine.is_network_connected():
                    self.engine.network_disconnect()
                self.engine.shutdown()
                self.engine.destroy()
            except Exception:
                pass
            self.engine = None
        self.exit()
