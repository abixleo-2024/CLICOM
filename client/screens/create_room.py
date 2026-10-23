"""
Create Room screen for CLICOM Textual Interface.
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


class CreateRoomScreen(Screen):
    """Screen for creating a new tactical communication room."""

    BINDINGS = [
        Binding("escape", "cancel", "Back to Menu", priority=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="form-container"):
            yield Label("CREATE NEW TACTICAL ROOM", classes="screen-title")

            with Vertical(classes="panel"):
                yield Label("ROOM PARAMETERS", classes="panel-header")

                yield Label("Room Identifier (Alphanumeric / Hyphens, 1-63 chars):", classes="field-label")
                yield Input(placeholder="e.g. ALPHA-GRID-01", id="input-room-id", max_length=63)

                yield Label("Participant Limit (2 - 64):", classes="field-label")
                yield Input(value="16", id="input-max-members", max_length=2)

                yield Static("", id="form-error", classes="error-text")

            with Vertical(classes="notice-box"):
                yield Label("[AUTOMATIC KEY GENERATION]", classes="notice-tag")
                yield Static(
                    "A secure invitation key will be automatically generated upon room creation.\n"
                    "This key will remain permanently visible on your dashboard to share with other nodes.",
                    classes="notice-body",
                )

            with Horizontal(classes="button-row"):
                yield Button("Cancel [Esc]", id="btn-cancel", classes="btn-secondary")
                yield Button("Create & Enter Room [Enter]", variant="primary", id="btn-submit", classes="btn-primary")

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
        room_id = self.query_one("#input-room-id", Input).value.strip()
        members_str = self.query_one("#input-max-members", Input).value.strip()
        err_label = self.query_one("#form-error", Static)

        # Validation
        if not room_id:
            err_label.update("[bold red]Error: Room Identifier cannot be empty.[/]")
            return

        if not re.match(r"^[A-Za-z0-9_\-]+$", room_id):
            err_label.update("[bold red]Error: Room ID contains invalid characters. Use letters, numbers, hyphens.[/]")
            return

        try:
            members = int(members_str)
            if members < 2 or members > 64:
                err_label.update("[bold red]Error: Participant limit must be between 2 and 64.[/]")
                return
        except ValueError:
            err_label.update("[bold red]Error: Participant limit must be a valid number.[/]")
            return

        app: ClicomApp = self.app  # type: ignore
        engine = app.engine

        if engine and engine.is_alive:
            try:
                if engine.is_network_connected():
                    # Server-authoritative room creation
                    room_id_out, key_out = engine.network_create_room(room_id, members)
                    app.current_room_key = key_out
                    app.current_room_name = room_id
                    self.notify(f"Created server room: {room_id} (Key: {key_out})", title="CLICOM Network")
                else:
                    # Local demonstration state
                    generated_key = f"SEC-{room_id[:4].upper()}-99"
                    engine.room_join(room_id, generated_key)
                    app.current_room_key = generated_key
                    app.current_room_name = room_id
                    local_name = engine.get_display_name()
                    engine.participant_add(
                        participant_id="local-node-01",
                        display_name=f"{local_name} (Host)",
                        is_speaking=False,
                        is_muted=engine.is_mic_muted(),
                    )
                    self.notify(f"Created tactical room: {room_id} (Key: {generated_key})", title="Tactical Room")

                # Start audio engine if not already running
                engine.audio_start()

                # Transition to live room
                self.app.pop_screen()
                self.app.push_screen("live_room")
            except Exception as e:
                err_label.update(f"[bold red]Server/Native Error: {e}[/]")
        else:
            err_label.update("[bold red]Error: Native engine is not initialized.[/]")
