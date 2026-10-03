"""
DropLAN Peer Discovery Module
Implements zero-configuration LAN peer discovery via UDP mesh heartbeats.
Emits heartbeats every 2 seconds on 255.255.255.255:54545 and automatically
prunes inactive peers after 6 seconds of silence.
Operates on an isolated QThread to maintain 100% UI responsiveness.
"""

from __future__ import annotations

import json
import select
import socket
import time
from typing import Dict, Any

from PyQt6.QtCore import QThread, pyqtSignal

DEFAULT_BROADCAST_PORT: int = 54545
HEARTBEAT_INTERVAL: float = 2.0
PEER_TIMEOUT: float = 6.0


class PeerDiscoveryWorker(QThread):
    """
    QThread worker for UDP LAN discovery.
    Sends periodic heartbeat broadcasts and listens for peers on the LAN mesh.
    """
    peer_discovered = pyqtSignal(dict)  # Discovered new peer {node_id, name, ip, port, last_seen}
    peer_updated = pyqtSignal(dict)     # Refreshed heartbeat of known peer
    peer_lost = pyqtSignal(str)         # node_id of peer timed out
    status_message = pyqtSignal(str)    # Operational status / logs

    def __init__(
        self,
        node_id: str,
        name: str,
        tcp_port: int,
        broadcast_port: int = DEFAULT_BROADCAST_PORT,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.node_id = node_id
        self.name = name
        self.tcp_port = tcp_port
        self.broadcast_port = broadcast_port
        self._running = False
        self.peers: Dict[str, Dict[str, Any]] = {}

        self._send_sock: socket.socket | None = None
        self._recv_sock: socket.socket | None = None

    def update_tcp_port(self, port: int) -> None:
        """Update the TCP port to broadcast."""
        self.tcp_port = port

    def run(self) -> None:
        self._running = True
        self.status_message.emit(f"Discovery service started on UDP port {self.broadcast_port}")

        # Setup UDP Broadcast Sending Socket
        self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Setup UDP Broadcast Receiving Socket with SO_REUSEADDR
        self._recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except (AttributeError, OSError):
            pass

        try:
            self._recv_sock.bind(("", self.broadcast_port))
            self._recv_sock.setblocking(False)
        except Exception as exc:
            self.status_message.emit(f"Failed to bind UDP discovery listener: {exc}")
            return

        last_heartbeat = 0.0

        while self._running:
            now = time.time()

            # 1. Send Heartbeat Broadcast if interval elapsed
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                payload = {
                    "name": self.name,
                    "port": self.tcp_port,
                    "node_id": self.node_id,
                }
                data = json.dumps(payload).encode("utf-8")
                try:
                    # Broadcast to LAN
                    self._send_sock.sendto(data, ("255.255.255.255", self.broadcast_port))
                    # Also send to loopback for multi-instance local testing
                    self._send_sock.sendto(data, ("127.0.0.1", self.broadcast_port))
                except OSError as exc:
                    self.status_message.emit(f"Broadcast warning: {exc}")
                last_heartbeat = now

            # 2. Check for incoming peer packets using select (0.5s timeout)
            try:
                readable, _, _ = select.select([self._recv_sock], [], [], 0.5)
                if readable and self._running:
                    while True:
                        try:
                            raw_data, (sender_ip, _) = self._recv_sock.recvfrom(2048)
                            self._handle_peer_packet(raw_data, sender_ip)
                        except (BlockingIOError, socket.error):
                            break
            except Exception as exc:
                if self._running:
                    self.status_message.emit(f"Discovery select error: {exc}")

            # 3. Prune peers that timed out (> 6s)
            current_time = time.time()
            expired_ids = []
            for peer_id, info in self.peers.items():
                if current_time - info["last_seen"] > PEER_TIMEOUT:
                    expired_ids.append(peer_id)

            for expired_id in expired_ids:
                peer_info = self.peers.pop(expired_id, None)
                if peer_info:
                    self.peer_lost.emit(expired_id)
                    self.status_message.emit(f"Peer '{peer_info.get('name')}' timed out.")

        self._cleanup_sockets()
        self.status_message.emit("Discovery service stopped.")

    def _handle_peer_packet(self, raw_data: bytes, sender_ip: str) -> None:
        """Parse packet and update or register peer."""
        try:
            if len(raw_data) > 4096:
                return

            packet = json.loads(raw_data.decode("utf-8"))
            peer_id = str(packet.get("node_id", "")).strip()
            raw_name = str(packet.get("name", "Unknown")).strip()
            peer_port = int(packet.get("port", 0))

            # Validate fields
            if not peer_id or peer_id == self.node_id or len(peer_id) > 64:
                return
            if not (1 <= peer_port <= 65535):
                return

            # Sanitize peer name for safe UI display
            peer_name = "".join(c for c in raw_name if c.isprintable())[:40] or "Peer"

            now = time.time()
            peer_info = {
                "node_id": peer_id,
                "name": peer_name,
                "ip": sender_ip,
                "port": peer_port,
                "last_seen": now,
            }

            if peer_id not in self.peers:
                self.peers[peer_id] = peer_info
                self.peer_discovered.emit(peer_info)
                self.status_message.emit(f"Discovered peer: {peer_name} ({sender_ip}:{peer_port})")
            else:
                # Update existing peer record
                self.peers[peer_id].update(peer_info)
                self.peer_updated.emit(peer_info)

        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            pass

    def stop(self) -> None:
        """Gracefully request thread shutdown and release sockets."""
        self._running = False
        self._cleanup_sockets()
        self.wait(1500)

    def _cleanup_sockets(self) -> None:
        if self._send_sock:
            try:
                self._send_sock.close()
            except Exception:
                pass
            self._send_sock = None
        if self._recv_sock:
            try:
                self._recv_sock.close()
            except Exception:
                pass
            self._recv_sock = None
