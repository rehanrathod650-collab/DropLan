import os
from pathlib import Path
import tempfile
import time
from PyQt6.QtCore import QCoreApplication

from security import generate_ephemeral_certificate, compute_file_sha256
from network.discovery import PeerDiscoveryWorker
from network.transfer import FileReceiverServer, FileSenderWorker


def test_full_mesh_discovery_and_transfer():
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])

    # Node A setup
    a_key, a_cert, a_der = generate_ephemeral_certificate("Alice-Laptop")
    # Node B setup
    b_key, b_cert, b_der = generate_ephemeral_certificate("Bob-Workstation")

    with tempfile.TemporaryDirectory() as b_download_dir, tempfile.TemporaryDirectory() as a_source_dir:
        # Create a test file for Alice to send
        source_file = Path(a_source_dir) / "project_specs.pdf"
        file_payload = os.urandom(512 * 1024)  # 512 KB
        with open(source_file, "wb") as f:
            f.write(file_payload)
        original_sha = compute_file_sha256(source_file)

        # 1. Start Node A Server & Discovery
        server_a = FileReceiverServer(
            node_id="node_alice",
            node_name="Alice-Laptop",
            key_pem=a_key,
            cert_pem=a_cert,
            cert_der=a_der,
            port=0,
        )
        port_a_box = []
        server_a.signals.server_ready.connect(lambda p: port_a_box.append(p))
        server_a.start()

        # 2. Start Node B Server & Discovery
        server_b = FileReceiverServer(
            node_id="node_bob",
            node_name="Bob-Workstation",
            key_pem=b_key,
            cert_pem=b_cert,
            cert_der=b_der,
            port=0,
            download_dir=Path(b_download_dir),
        )
        port_b_box = []
        b_pin_box = []
        b_completed_box = []

        def on_b_transfer_req(t_id, sender_name, ip, fname, fsize, pin):
            b_pin_box.append(pin)
            # Bob approves transfer
            server_b.respond_to_transfer(t_id, True)

        def on_b_completed(t_id, fname, fpath):
            b_completed_box.append(fpath)

        server_b.signals.server_ready.connect(lambda p: port_b_box.append(p))
        server_b.signals.transfer_requested.connect(on_b_transfer_req)
        server_b.signals.transfer_completed.connect(on_b_completed)
        server_b.start()

        # Wait for both servers to bind
        for _ in range(50):
            app.processEvents()
            if port_a_box and port_b_box:
                break
            time.sleep(0.05)

        port_a = port_a_box[0]
        port_b = port_b_box[0]

        # Start Discovery for A and B
        disc_a = PeerDiscoveryWorker(node_id="node_alice", name="Alice-Laptop", tcp_port=port_a)
        disc_b = PeerDiscoveryWorker(node_id="node_bob", name="Bob-Workstation", tcp_port=port_b)

        a_found_peers = []
        b_found_peers = []

        disc_a.peer_discovered.connect(lambda p: a_found_peers.append(p))
        disc_b.peer_discovered.connect(lambda p: b_found_peers.append(p))

        disc_a.start()
        disc_b.start()

        # Wait for peer discovery
        for _ in range(60):
            app.processEvents()
            if a_found_peers and b_found_peers:
                break
            time.sleep(0.05)

        # Alice sends to Bob
        sender = FileSenderWorker(
            peer_ip="127.0.0.1",
            peer_port=port_b,
            peer_name="Bob-Workstation",
            filepath=source_file,
            local_node_id="node_alice",
            local_name="Alice-Laptop",
            key_pem=a_key,
            cert_pem=a_cert,
            cert_der=a_der,
        )

        a_pin_box = []
        a_completed_box = []

        sender.pin_available.connect(lambda pin, *args: a_pin_box.append(pin))
        sender.transfer_completed.connect(lambda fname: a_completed_box.append(fname))
        sender.start()

        # Wait for transfer completion
        for _ in range(100):
            app.processEvents()
            if a_completed_box and b_completed_box:
                break
            time.sleep(0.05)

        # Clean shutdown of all workers and threads
        sender.wait(2000)
        disc_a.stop()
        disc_b.stop()
        server_a.stop()
        server_b.stop()

        # Verify Assertions
        assert len(a_completed_box) == 1
        assert len(b_completed_box) == 1

        # Check SAS PIN match
        assert len(a_pin_box) == 1
        assert len(b_pin_box) == 1
        assert a_pin_box[0] == b_pin_box[0]
        assert len(a_pin_box[0]) == 6

        # Check Received File on Node B
        received_path = Path(b_completed_box[0])
        assert received_path.exists()
        assert received_path.stat().st_size == len(file_payload)
        assert compute_file_sha256(received_path) == original_sha
