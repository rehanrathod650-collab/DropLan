"""
DropLAN Entrypoint
P2P Local File Transfer Application
Zero-configuration LAN discovery (UDP) + TLS 1.3 socket streaming (TCP)
"""

from __future__ import annotations

import argparse
from pathlib import Path
import signal
import socket
import sys
import uuid

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

from security import generate_ephemeral_certificate
from ui.main_window import MainWindow


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DropLAN — Secure P2P Local File Transfer")
    parser.add_argument(
        "--name",
        type=str,
        default="",
        help="Custom display name for this peer on the LAN mesh (defaults to machine hostname)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="TCP port to bind TLS 1.3 receiver (0 for automatic available port)",
    )
    parser.add_argument(
        "--download-dir",
        type=str,
        default="",
        help="Custom directory path for saving received files (defaults to ~/Downloads/DropLAN_Received)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    # Enable High DPI and Modern Qt Attributes
    if hasattr(Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(Qt.ApplicationAttribute, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("DropLAN")
    app.setOrganizationName("DropLAN P2P")

    # Generate Node ID and Hostname
    node_id = uuid.uuid4().hex[:12]
    local_hostname = socket.gethostname()
    display_name = args.name.strip() if args.name else local_hostname

    # 1. Generate Ephemeral In-Memory 2048-bit RSA Key and Self-Signed X.509 Certificate
    key_pem, cert_pem, cert_der = generate_ephemeral_certificate(common_name=f"DropLAN-{display_name}")

    # Resolve download directory
    download_dir = Path(args.download_dir).resolve() if args.download_dir else None

    # Instantiate Main Window
    window = MainWindow(
        node_id=node_id,
        node_name=display_name,
        key_pem=key_pem,
        cert_pem=cert_pem,
        cert_der=cert_der,
        download_dir=download_dir,
    )

    # Clean lifecycle shutdown hook
    def on_about_to_quit():
        if hasattr(window, "discovery_worker") and window.discovery_worker:
            window.discovery_worker.stop()
        if hasattr(window, "receiver_server") and window.receiver_server:
            window.receiver_server.stop()
        if window.active_sender and window.active_sender.isRunning():
            window.active_sender.cancel()
            window.active_sender.wait(1000)

    app.aboutToQuit.connect(on_about_to_quit)

    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, lambda *args: app.quit())

    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
