"""
Join Room screen for CLICOM Textual Interface.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static

if TYPE_CHECKING:
    from client.app import ClicomApp


class JoinRoomScreen(Screen):
    """Screen for joining an existing tactical room via invitation key."""

    BINDINGS = [
        Binding("escape", "cancel", "Back to Menu", priority=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="form-container"):
            yield Label("JOIN TACTICAL ROOM", classes="screen-title")

            with Vertical(classes="panel"):
                yield Label("CREDENTIAL VERIFICATION", classes="panel-header")

                yield Label("Invitation / Security Key (e.g. SEC-4891 or GC-XXXX):", classes="field-label")
                yield Input(placeholder="Enter Invitation / Join Key", id="input-join-room-key", max_length=63)

                yield Label("Room Identifier (Optional if key provided):", classes="field-label")
                yield Input(placeholder="e.g. ALPHA-GRID-01", id="input-join-room-id", max_length=63)

                yield Static("", id="join-error", classes="error-text")

            with Vertical(classes="notice-box"):
                yield Label("[FAST NODE CONNECTION]", classes="notice-tag")
                yield Static(
                    "Paste or type the Room Invitation Key shared by the room creator.\n"
                    "Upon connection, live bidirectional audio is immediately established.",
                    classes="notice-body",
                )

            with Horizontal(classes="button-row"):
                yield Button("Cancel [Esc]", id="btn-cancel", classes="btn-secondary")
                yield Button("Connect to Room [Enter]", variant="primary", id="btn-submit", classes="btn-primary")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-submit":
            self.submit_form()
        elif event.button.id == "btn-cancel":
            self.action_cancel()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.submit_form()

    def action_cancel(self) -> None:
        self.app.pop_screen()

    def submit_form(self) -> None:
        join_key = self.query_one("#input-join-room-key", Input).value.strip()
        room_id = self.query_one("#input-join-room-id", Input).value.strip()
        err_label = self.query_one("#join-error", Static)

        if not join_key and not room_id:
            err_label.update("[bold red]Error: Room ID and Invitation Key cannot be empty.[/]")
            return

        target_key = join_key if join_key else room_id
        effective_room = room_id if room_id else target_key

        app: ClicomApp = self.app  # type: ignore
        engine = app.engine

        if engine and engine.is_alive:
            try:
                if app._server is not None and not engine.is_network_connected():
                    err_label.update(
                        f"[bold red]Cannot Join Room: Disconnected from Server ({app._server}).\n"
                        f"Please ensure clicom-server is running on {app._server}:{app._port}.[/]"
                    )
                    return

                if engine.is_network_connected():
                    # Server-authoritative room join via invitation key
                    r_id, r_name = engine.network_join_room(target_key)
                    app.current_room_key = target_key
                    app.current_room_name = r_name or effective_room
                    self.notify(f"Joined server room: {r_name} ({r_id})", title="CLICOM Network")
                else:
                    # Local demonstration state (only when running offline without -s)
                    engine.room_join(effective_room, target_key)
                    app.current_room_key = target_key
                    app.current_room_name = effective_room
                    local_name = engine.get_display_name()
                    engine.participant_add(
                        participant_id="local-node-01",
                        display_name=f"{local_name}",
                        is_speaking=False,
                        is_muted=engine.is_mic_muted(),
                    )
                    self.notify(f"[DEMO] Connected to local room: {effective_room}", title="Native Engine")

                engine.audio_start()
                self.app.pop_screen()
                self.app.push_screen("live_room")
            except Exception as e:
                err_label.update(f"[bold red]Server/Native Error: {e}[/]")
        else:
            err_label.update("[bold red]Error: Native engine is not initialized.[/]")
