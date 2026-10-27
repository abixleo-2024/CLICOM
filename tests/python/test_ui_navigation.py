"""
Textual UI navigation and form validation tests using headless pilot.
"""

import pytest

from client.app import ClicomApp
from client.screens.create_room import CreateRoomScreen
from client.screens.instant_connection import InstantConnectionScreen
from client.screens.join_room import JoinRoomScreen
from client.screens.live_room import LiveRoomScreen
from client.screens.main_menu import MainMenuScreen
from textual.widgets import Button, Input, Static


@pytest.mark.asyncio
async def test_app_startup_and_main_menu():
    """Verify application boots, initializes native engine, and displays MainMenuScreen."""
    app = ClicomApp(display_name="TEST-PILOT")
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, MainMenuScreen)
        assert app.engine is not None
        assert app.engine.is_alive
        assert app.engine.get_display_name() == "TEST-PILOT"


@pytest.mark.asyncio
async def test_main_menu_navigation_create_room():
    """Verify navigating to Create Room and back via Escape."""
    app = ClicomApp()
    async with app.run_test() as pilot:
        await pilot.pause()

        # Press '1' to navigate to Create Room
        await pilot.press("1")
        await pilot.pause()
        assert isinstance(app.screen, CreateRoomScreen)

        # Press Escape to return to Main Menu
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, MainMenuScreen)


@pytest.mark.asyncio
async def test_main_menu_navigation_join_room():
    """Verify navigating to Join Room and back via Escape."""
    app = ClicomApp()
    async with app.run_test() as pilot:
        await pilot.pause()

        # Press '2' to navigate to Join Room
        await pilot.press("2")
        await pilot.pause()
        assert isinstance(app.screen, JoinRoomScreen)

        # Press Escape to return to Main Menu
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, MainMenuScreen)


@pytest.mark.asyncio
async def test_main_menu_navigation_display_name_modal():
    """Verify opening display name modal via '3' key binding and closing via Escape."""
    from client.screens.main_menu import DisplayNameModal
    app = ClicomApp()
    async with app.run_test() as pilot:
        await pilot.pause()

        # Press '3' to open Configure Local Display Name
        await pilot.press("3")
        await pilot.pause()
        assert isinstance(app.screen, DisplayNameModal)

        # Press Escape to dismiss modal
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, MainMenuScreen)


@pytest.mark.asyncio
async def test_create_room_form_validation():
    """Verify Create Room validates empty, invalid, and valid room IDs."""
    app = ClicomApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("1")
        await pilot.pause()
        assert isinstance(app.screen, CreateRoomScreen)

        # Try to submit empty room ID
        create_screen: CreateRoomScreen = app.screen  # type: ignore
        create_screen.submit_form()
        await pilot.pause()
        err_msg = str(create_screen.query_one("#form-error", Static).render())
        assert "cannot be empty" in err_msg
        assert isinstance(app.screen, CreateRoomScreen)

        # Try invalid room ID (spaces / special symbols)
        input_room = create_screen.query_one("#input-room-id", Input)
        input_room.value = "BAD ROOM !@#"
        create_screen.submit_form()
        await pilot.pause()
        err_msg = str(create_screen.query_one("#form-error", Static).render())
        assert "invalid characters" in err_msg

        # Enter valid room ID and submit
        input_room.value = "ALPHA-GRID-TEST"
        create_screen.submit_form()
        await pilot.pause()

        # Should transition to LiveRoomScreen
        assert isinstance(app.screen, LiveRoomScreen)
        room_state = app.engine.get_room_state()
        assert room_state.room_id == "ALPHA-GRID-TEST"

        # Press 'l' to leave room and return to Main Menu
        await pilot.press("l")
        await pilot.pause()
        assert isinstance(app.screen, MainMenuScreen)


@pytest.mark.asyncio
async def test_join_room_form_validation():
    """Verify Join Room validates empty input and transitions on valid input."""
    app = ClicomApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        assert isinstance(app.screen, JoinRoomScreen)

        join_screen: JoinRoomScreen = app.screen  # type: ignore
        join_screen.submit_form()
        await pilot.pause()
        err_msg = str(join_screen.query_one("#join-error", Static).render())
        assert "cannot be empty" in err_msg

        input_room = join_screen.query_one("#input-join-room-id", Input)
        input_room.value = "JOIN-TARGET-9"
        input_key = join_screen.query_one("#input-join-room-key", Input)
        input_key.value = "SEC-KEY-99"
        join_screen.submit_form()
        await pilot.pause()

        # Transitions to LiveRoomScreen
        assert isinstance(app.screen, LiveRoomScreen)
        room_state = app.engine.get_room_state()
        assert room_state.room_id == "JOIN-TARGET-9"
        assert room_state.join_key == "SEC-KEY-99"


@pytest.mark.asyncio
async def test_graceful_exit():
    """Verify app cleanly exits on quit action and tears down native engine."""
    app = ClicomApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.engine is not None and app.engine.is_alive
        app.action_quit()
        await pilot.pause()
        assert app.engine is None


def test_cli_argument_parsing():
    """Verify CLI parses node, server, port, and ca-cert options."""
    from client.cli import parse_args
    args = parse_args(["--node", "NODE-77", "--server", "192.168.1.100", "--port", "9000", "--ca-cert", "certs/ca.crt"])
    assert args.node_name == "NODE-77"
    assert args.server == "192.168.1.100"
    assert args.port == 9000
    assert args.ca_cert == "certs/ca.crt"

