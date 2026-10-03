import json
import socket
import time
from PyQt6.QtCore import QCoreApplication

from network.discovery import PeerDiscoveryWorker


def test_peer_packet_handling():
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])

    worker = PeerDiscoveryWorker(
        node_id="local_node_1",
        name="Local Machine",
        tcp_port=52345,
    )

    discovered = []
    updated = []

    worker.peer_discovered.connect(lambda p: discovered.append(p))
    worker.peer_updated.connect(lambda p: updated.append(p))

    # Test packet from another peer
    remote_packet = {
        "node_id": "remote_node_2",
        "name": "Alice Laptop",
        "port": 52346,
    }
    raw = json.dumps(remote_packet).encode("utf-8")
    worker._handle_peer_packet(raw, "192.168.1.100")

    assert len(discovered) == 1
    assert discovered[0]["name"] == "Alice Laptop"
    assert discovered[0]["ip"] == "192.168.1.100"
    assert discovered[0]["port"] == 52346

    # Test packet from self (must be ignored)
    self_packet = {
        "node_id": "local_node_1",
        "name": "Local Machine",
        "port": 52345,
    }
    worker._handle_peer_packet(json.dumps(self_packet).encode("utf-8"), "127.0.0.1")
    assert len(discovered) == 1

    # Test update from existing peer
    remote_packet["name"] = "Alice Laptop Updated"
    worker._handle_peer_packet(json.dumps(remote_packet).encode("utf-8"), "192.168.1.100")
    assert len(updated) == 1
    assert updated[0]["name"] == "Alice Laptop Updated"
