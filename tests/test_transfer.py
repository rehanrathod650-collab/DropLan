import os
from pathlib import Path
import tempfile
import time
from PyQt6.QtCore import QCoreApplication

from security import generate_ephemeral_certificate, compute_file_sha256
from network.transfer import FileReceiverServer, FileSenderWorker


def test_full_tls_transfer_cycle():
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])

    # Generate certificates for server and client
    s_key, s_cert, s_der = generate_ephemeral_certificate("ReceiverNode")
    c_key, c_cert, c_der = generate_ephemeral_certificate("SenderNode")

    with tempfile.TemporaryDirectory() as download_dir, tempfile.TemporaryDirectory() as sender_dir:
        # Create a test file with 256 KB of content
        test_file = Path(sender_dir) / "test_document.dat"
        test_content = os.urandom(256 * 1024)
        with open(test_file, "wb") as f:
            f.write(test_content)
        original_hash = compute_file_sha256(test_file)

        # 1. Start Server
        server = FileReceiverServer(
            node_id="receiver_123",
            node_name="Receiver Host",
            key_pem=s_key,
            cert_pem=s_cert,
            cert_der=s_der,
            port=0,
            download_dir=Path(download_dir),
        )

        server_port_box = []
        receiver_pin_box = []
        receiver_completed_box = []

        def on_server_ready(port):
            server_port_box.append(port)

        def on_transfer_requested(transfer_id, sender_name, ip, filename, size, pin):
            receiver_pin_box.append(pin)
            # Simulate user clicking Accept immediately
            server.respond_to_transfer(transfer_id, True)

        def on_receiver_completed(transfer_id, filename, filepath):
            receiver_completed_box.append(filepath)

        server.signals.server_ready.connect(on_server_ready)
        server.signals.transfer_requested.connect(on_transfer_requested)
        server.signals.transfer_completed.connect(on_receiver_completed)

        server.start()

        # Wait for server to bind port
        for _ in range(50):
            app.processEvents()
            if server_port_box:
                break
            time.sleep(0.05)

        assert len(server_port_box) == 1
        bound_port = server_port_box[0]

        # 2. Start Sender
        sender = FileSenderWorker(
            peer_ip="127.0.0.1",
            peer_port=bound_port,
            peer_name="Receiver Host",
            filepath=test_file,
            local_node_id="sender_456",
            local_name="Sender Host",
            key_pem=c_key,
            cert_pem=c_cert,
            cert_der=c_der,
        )

        sender_pin_box = []
        sender_completed_box = []

        def on_sender_pin(pin, peer, fname, fsize):
            sender_pin_box.append(pin)

        def on_sender_completed(fname):
            sender_completed_box.append(fname)

        sender.pin_available.connect(on_sender_pin)
        sender.transfer_completed.connect(on_sender_completed)

        sender.start()

        # Wait for transfer completion
        for _ in range(100):
            app.processEvents()
            if sender_completed_box and receiver_completed_box:
                break
            time.sleep(0.05)

        # Stop server and sender
        sender.wait(2000)
        server.stop()

        # Verify results
        assert len(sender_completed_box) == 1
        assert len(receiver_completed_box) == 1

        # Verify SAS PIN match!
        assert len(sender_pin_box) == 1
        assert len(receiver_pin_box) == 1
        assert sender_pin_box[0] == receiver_pin_box[0]
        assert len(sender_pin_box[0]) == 6

        # Verify data integrity
        received_path = Path(receiver_completed_box[0])
        assert received_path.exists()
        assert received_path.stat().st_size == len(test_content)
        received_hash = compute_file_sha256(received_path)
        assert received_hash == original_hash


def test_transfer_rejection():
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])

    s_key, s_cert, s_der = generate_ephemeral_certificate("ReceiverNode")
    c_key, c_cert, c_der = generate_ephemeral_certificate("SenderNode")

    with tempfile.TemporaryDirectory() as download_dir, tempfile.TemporaryDirectory() as sender_dir:
        test_file = Path(sender_dir) / "secret.pdf"
        with open(test_file, "wb") as f:
            f.write(b"Important secret document contents")

        server = FileReceiverServer(
            node_id="receiver_rej",
            node_name="Receiver Host",
            key_pem=s_key,
            cert_pem=s_cert,
            cert_der=s_der,
            port=0,
            download_dir=Path(download_dir),
        )

        server_port_box = []

        def on_transfer_requested(transfer_id, *args):
            # User rejects the transfer
            server.respond_to_transfer(transfer_id, False)

        server.signals.server_ready.connect(lambda p: server_port_box.append(p))
        server.signals.transfer_requested.connect(on_transfer_requested)
        server.start()

        for _ in range(50):
            app.processEvents()
            if server_port_box:
                break
            time.sleep(0.05)

        bound_port = server_port_box[0]

        sender = FileSenderWorker(
            peer_ip="127.0.0.1",
            peer_port=bound_port,
            peer_name="Receiver Host",
            filepath=test_file,
            local_node_id="sender_rej",
            local_name="Sender Host",
            key_pem=c_key,
            cert_pem=c_cert,
            cert_der=c_der,
        )

        rejection_box = []
        sender.transfer_rejected.connect(lambda reason: rejection_box.append(reason))
        sender.start()

        for _ in range(60):
            app.processEvents()
            if rejection_box:
                break
            time.sleep(0.05)

        sender.wait(2000)
        server.stop()

        assert len(rejection_box) == 1
