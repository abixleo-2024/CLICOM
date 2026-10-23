"""
Command-line interface entry point for the CLICOM Textual client.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure project root is in sys.path if run directly as a script
if __package__ is None or __package__ == "":
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from client import __version__
from client.app import ClicomApp
from client.config import DEFAULT_DISPLAY_NAME


def parse_args(args=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="clicom",
        description="CLICOM Tactical Communications Terminal Client (Textual UI)",
    )
    parser.add_argument(
        "--node",
        "-n",
        dest="node_name",
        default=DEFAULT_DISPLAY_NAME,
        help=f"Initial operator display name (default: {DEFAULT_DISPLAY_NAME})",
    )
    parser.add_argument(
        "--server",
        "-s",
        dest="server",
        default=None,
        help="CLICOM server IP or hostname (TLS 1.3)",
    )
    parser.add_argument(
        "--port",
        "-p",
        dest="port",
        type=int,
        default=8443,
        help="CLICOM server port (default: 8443)",
    )
    parser.add_argument(
        "--ca-cert",
        dest="ca_cert",
        default=None,
        help="Path to CA certificate for TLS 1.3 server verification",
    )
    parser.add_argument(
        "--dll",
        "-d",
        dest="dll_path",
        default=None,
        help="Custom path to libclicom_engine.dll",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"CLICOM Client v{__version__}",
    )
    return parser.parse_args(args)


def main() -> int:
    args = parse_args()
    app = ClicomApp(
        dll_path=args.dll_path,
        display_name=args.node_name,
        server=args.server,
        port=args.port,
        ca_cert=args.ca_cert,
    )
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
