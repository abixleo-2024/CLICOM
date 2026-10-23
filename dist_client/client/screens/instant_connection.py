"""
Instant Connection (Online Node Discovery) screen for CLICOM.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Label, Static

if TYPE_CHECKING:
    from client.app import ClicomApp


class InstantConnectionScreen(Screen):
    """Screen for discovering online nodes and requesting instant point-to-point connections."""

    BINDINGS = [
        Binding("escape", "cancel", "Back to Menu", priority=True),
        Binding("r", "refresh_nodes", "Refresh List", priority=True),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="instant-container"):
            yield Label("INSTANT NODE-TO-NODE CONNECTION", classes="screen-title")

            with Vertical(classes="panel"):
                yield Label("DISCOVERED NODES ON MESH [DEMO PLACEHOLDER]", classes="panel-header")
                yield DataTable(id="nodes-table", cursor_type="row")

            with Vertical(classes="notice-box"):
                yield Label("[STATUS: TRANSPORT UNAVAILABLE IN PHASE 1B]", classes="notice-tag-warn")
                yield Static(
                    "P2P Node discovery and direct connection request/accept workflow\n"
                    "requires the Phase 2 network daemon. The table above displays\n"
                    "simulated endpoints (DEMO) to verify table selection and navigation.",
                    classes="notice-body",
                )

            yield Static("", id="connection-status-msg", classes="status-msg")

            with Horizontal(classes="button-row"):
                yield Button("Back to Main Menu [Esc]", id="btn-back", classes="btn-secondary")
                yield Button("Request Connection [Enter]", variant="primary", id="btn-connect", classes="btn-primary")

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#nodes-table", DataTable)
        table.add_columns("Node UUID", "Display Name", "Network Latency", "Status", "Capability")

        # Explicitly labelled DEMO data
        table.add_row(
            "demo-uuid-001",
            "ALPHA-LEAD [DEMO]",
            "14 ms",
            "STANDBY",
            "Opus/PCM",
        )
        table.add_row(
            "demo-uuid-002",
            "BRAVO-TWO [DEMO]",
            "28 ms",
            "ONLINE",
            "Opus Only",
        )
        table.add_row(
            "demo-uuid-003",
            "DELTA-DISPATCH [DEMO]",
            "45 ms",
            "BUSY",
            "Captions/Audio",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.action_cancel()
        elif event.button.id == "btn-connect":
            self.request_connection()

    def action_cancel(self) -> None:
        self.app.pop_screen()

    def action_refresh_nodes(self) -> None:
        self.notify("Refreshing mesh node list... [Local Simulation]", title="Discovery")

    def request_connection(self) -> None:
        status_lbl = self.query_one("#connection-status-msg", Static)
        status_lbl.update(
            "[bold yellow]CAPABILITY PENDING:[/] Direct TCP/TLS connection requests will be "
            "enabled in Phase 2 with CLIP transport."
        )
        self.notify(
            "Direct node communication requires Phase 2 TCP/TLS daemon.",
            title="Capability Notice",
            severity="warning",
        )
