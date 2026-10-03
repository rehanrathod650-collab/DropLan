import os
from pathlib import Path
import pytest
from PyQt6.QtWidgets import QApplication

from security import generate_ephemeral_certificate
from ui.main_window import MainWindow
from ui.security_dialog import SecurityConfirmDialog


@pytest.fixture(scope="session")
def qapp():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app


def test_main_window_initialization(qapp):
    key_pem, cert_pem, cert_der = generate_ephemeral_certificate("UITestNode")

    window = MainWindow(
        node_id="test_node_ui",
        node_name="UI Test Host",
        key_pem=key_pem,
        cert_pem=cert_pem,
        cert_der=cert_der,
    )
    assert window is not None
    assert window.windowTitle() == "DropLAN — Zero-Trust P2P File Transfer"
    assert window.peer_list_widget is not None
    assert window.drop_zone is not None
    assert window.progress_bar is not None
    assert window.activity_log is not None

    # Simulate peer discovery
    window._on_peer_discovered({
        "node_id": "remote_1",
        "name": "Bob Device",
        "ip": "192.168.1.50",
        "port": 52345,
    })

    assert window.peer_list_widget.count() == 1
    assert "1 online" in window.peer_count_badge.text()

    # Simulate file selection
    window._on_file_selected(__file__)
    assert window.selected_file_path == __file__
    assert window.btn_clear_file.isEnabled()

    # Clean shutdown
    if hasattr(window, "discovery_worker") and window.discovery_worker:
        window.discovery_worker.stop()
    if hasattr(window, "receiver_server") and window.receiver_server:
        window.receiver_server.stop()
    window.close()


def test_security_dialog_creation(qapp):
    from PyQt6.QtWidgets import QLabel
    dialog = SecurityConfirmDialog(
        sender_name="SenderPC",
        sender_ip="192.168.1.80",
        filename="archive.zip",
        filesize=1048576,
        sas_pin="794924",
    )
    assert dialog is not None
    pin_label = dialog.findChild(QLabel, "PinDigits")
    assert pin_label is not None
    assert "794" in pin_label.text()
    assert dialog.btn_accept is not None
    assert dialog.btn_reject is not None
