"""
DropLAN Transfer Module
Implements multi-threaded TLS 1.3 TCP Server (Receiver) and Client (Sender).
Strictly decouples all network I/O and disk operations from the PyQt6 GUI thread.
Enforces mutual pairing verification via 6-digit SAS PIN before receiving file bytes.
Guarantees streaming SHA-256 data integrity and directory traversal protection.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path
import select
import socket
import sys
import threading
import time
from typing import Any, Dict, Optional, Tuple

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from protocol import (
    CHUNK_SIZE,
    FRAME_DATA_CHUNK,
    FRAME_EOF,
    FRAME_HANDSHAKE,
    FRAME_METADATA,
    FRAME_RESPONSE,
    read_frame,
    read_json_frame,
    send_frame,
    send_json_frame,
)
from security import (
    compute_file_sha256,
    create_tls_client_context,
    create_tls_server_context,
    derive_sas_pin,
    resolve_quarantine_path,
)


class ReceiverConnectionThread(threading.Thread):
    """
    Dedicated worker thread handling an individual inbound TLS connection.
    Protects the main server listener from blocking.
    """

    def __init__(
        self,
        raw_sock: socket.socket,
        client_addr: Tuple[str, int],
        server_ssl_ctx,
        local_node_id: str,
        local_name: str,
        local_cert_der: bytes,
        signals: "ReceiverSignals",
        pending_approvals: Dict[str, Tuple[threading.Event, Dict[str, Any]]],
        download_dir: Optional[Path] = None,
    ) -> None:
        super().__init__(daemon=True)
        self.raw_sock = raw_sock
        self.client_addr = client_addr
        self.server_ssl_ctx = server_ssl_ctx
        self.local_node_id = local_node_id
        self.local_name = local_name
        self.local_cert_der = local_cert_der
        self.signals = signals
        self.pending_approvals = pending_approvals
        self.download_dir = download_dir
        self.transfer_id = ""

    def run(self) -> None:
        ssl_sock = None
        part_filepath: Optional[Path] = None
        final_filepath: Optional[Path] = None

        try:
            # 1. Establish Ephemeral TLS 1.3 Server Connection
            ssl_sock = self.server_ssl_ctx.wrap_socket(self.raw_sock, server_side=True)
            ssl_sock.settimeout(60.0)

            # 2. Handshake Phase: Receive sender hello & public certificate
            frame_type, sender_hello = read_json_frame(ssl_sock)
            if frame_type != FRAME_HANDSHAKE:
                raise ConnectionError(f"Protocol error: Expected Handshake frame, got 0x{frame_type:02X}")

            sender_name = sender_hello.get("name", "Unknown Sender")
            sender_node_id = sender_hello.get("node_id", "")
            sender_cert_b64 = sender_hello.get("cert_der", "")
            if not sender_cert_b64:
                raise ConnectionError("Handshake error: Missing peer certificate.")
            sender_cert_der = base64.b64decode(sender_cert_b64)

            # Reply with Receiver Handshake frame containing local certificate
            send_json_frame(
                ssl_sock,
                FRAME_HANDSHAKE,
                {
                    "node_id": self.local_node_id,
                    "name": self.local_name,
                    "cert_der": base64.b64encode(self.local_cert_der).decode("utf-8"),
                },
            )

            # 3. Derive 6-digit SAS PIN
            sas_pin = derive_sas_pin(self.local_cert_der, sender_cert_der)

            # 4. Metadata Phase: Receive transfer metadata
            frame_type, metadata = read_json_frame(ssl_sock)
            if frame_type != FRAME_METADATA:
                raise ConnectionError(f"Protocol error: Expected Metadata frame, got 0x{frame_type:02X}")

            raw_filename = metadata.get("filename", "")
            filesize = int(metadata.get("filesize", 0))
            expected_sha256 = metadata.get("sha256", "").lower().strip()

            if not raw_filename or filesize <= 0 or not expected_sha256:
                raise ValueError("Invalid metadata received from sender.")

            # Validate SHA-256 hex format strictly
            if len(expected_sha256) != 64 or not all(c in "0123456789abcdef" for c in expected_sha256):
                raise ValueError("Security violation: Malformed SHA-256 digest in metadata.")

            # Max supported single file transfer size limit: 500 GB
            if filesize > 500 * 1024 * 1024 * 1024:
                raise ValueError("File exceeds maximum allowed transfer size limit (500 GB).")

            # Sanitize and resolve destination inside sandbox quarantine folder
            final_filepath = resolve_quarantine_path(raw_filename, self.download_dir)
            clean_filename = final_filepath.name
            part_filepath = final_filepath.parent / f"{clean_filename}.part"

            # 5. Interactive Mutual Pairing Modal Verification
            import uuid
            self.transfer_id = uuid.uuid4().hex[:8]
            approval_event = threading.Event()
            approval_result: Dict[str, Any] = {"accepted": False}
            self.pending_approvals[self.transfer_id] = (approval_event, approval_result)

            self.signals.transfer_requested.emit(
                self.transfer_id,
                sender_name,
                self.client_addr[0],
                clean_filename,
                filesize,
                sas_pin,
            )

            # Wait up to 60 seconds for user modal interaction
            approved = approval_event.wait(timeout=60.0)
            self.pending_approvals.pop(self.transfer_id, None)

            if not approved or not approval_result.get("accepted", False):
                send_json_frame(
                    ssl_sock,
                    FRAME_RESPONSE,
                    {"accepted": False, "reason": "Transfer was rejected by recipient or timed out."},
                )
                self.signals.transfer_rejected.emit(self.transfer_id, "Rejected by recipient.")
                return

            # Notify sender of acceptance
            send_json_frame(ssl_sock, FRAME_RESPONSE, {"accepted": True})
            self.signals.transfer_started.emit(self.transfer_id, clean_filename, filesize)

            # 6. Stream Data Chunks & Calculate On-the-fly SHA-256
            import hashlib
            hasher = hashlib.sha256()
            bytes_received = 0
            start_time = time.time()
            last_speed_calc_time = start_time
            last_bytes_speed = 0
            current_speed_mbps = 0.0

            with open(part_filepath, "wb") as out_file:
                while True:
                    frame_type, payload = read_frame(ssl_sock)
                    if frame_type == FRAME_DATA_CHUNK:
                        out_file.write(payload)
                        hasher.update(payload)
                        bytes_received += len(payload)

                        now = time.time()
                        if now - last_speed_calc_time >= 0.2:
                            time_delta = now - last_speed_calc_time
                            bytes_delta = bytes_received - last_bytes_speed
                            current_speed_mbps = (bytes_delta / (1024 * 1024)) / time_delta if time_delta > 0 else 0.0
                            last_speed_calc_time = now
                            last_bytes_speed = bytes_received
                            self.signals.transfer_progress.emit(
                                self.transfer_id,
                                bytes_received,
                                filesize,
                                current_speed_mbps,
                            )

                    elif frame_type == FRAME_EOF:
                        break
                    else:
                        raise ConnectionError(f"Unexpected frame during transfer: 0x{frame_type:02X}")

            # 7. Finalize & Verify SHA-256 Integrity
            calculated_sha256 = hasher.hexdigest().lower()
            if calculated_sha256 != expected_sha256 or bytes_received != filesize:
                if part_filepath.exists():
                    try:
                        part_filepath.unlink()
                    except OSError:
                        pass
                send_json_frame(
                    ssl_sock,
                    FRAME_RESPONSE,
                    {
                        "success": False,
                        "error": f"SHA-256 mismatch! Expected {expected_sha256[:8]}..., got {calculated_sha256[:8]}...",
                    },
                )
                self.signals.transfer_failed.emit(
                    self.transfer_id,
                    "Integrity check failed: Checksum mismatch. Corrupted data discarded.",
                )
                return

            # Atomically rename .part file to final destination
            if part_filepath.exists():
                part_filepath.replace(final_filepath)

            # Acknowledge success to sender
            send_json_frame(
                ssl_sock,
                FRAME_RESPONSE,
                {"success": True, "message": "File received and verified successfully."},
            )

            self.signals.transfer_progress.emit(self.transfer_id, filesize, filesize, 0.0)
            self.signals.transfer_completed.emit(self.transfer_id, clean_filename, str(final_filepath))

        except Exception as exc:
            # Clean up partial download on failure
            if part_filepath and part_filepath.exists():
                try:
                    part_filepath.unlink()
                except OSError:
                    pass
            err_msg = str(exc)
            if self.transfer_id:
                self.signals.transfer_failed.emit(self.transfer_id, f"Receiver error: {err_msg}")
        finally:
            if ssl_sock:
                try:
                    ssl_sock.close()
                except Exception:
                    pass
            elif self.raw_sock:
                try:
                    self.raw_sock.close()
                except Exception:
                    pass


class ReceiverSignals(QObject):
    """Signals emitted by the receiver server for UI consumption."""
    server_ready = pyqtSignal(int)                         # Emits bound TCP port
    transfer_requested = pyqtSignal(str, str, str, str, int, str)  # (id, sender, ip, filename, size, pin)
    transfer_started = pyqtSignal(str, str, int)           # (id, filename, size)
    transfer_progress = pyqtSignal(str, int, int, float)   # (id, received, total, speed_mbps)
    transfer_completed = pyqtSignal(str, str, str)         # (id, filename, filepath)
    transfer_rejected = pyqtSignal(str, str)               # (id, reason)
    transfer_failed = pyqtSignal(str, str)                 # (id, error_message)
    status_message = pyqtSignal(str)


class FileReceiverServer(QThread):
    """
    QThread running the TCP Listener server for incoming TLS 1.3 connections.
    """

    def __init__(
        self,
        node_id: str,
        node_name: str,
        key_pem: bytes,
        cert_pem: bytes,
        cert_der: bytes,
        port: int = 0,
        download_dir: Optional[Path] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.node_id = node_id
        self.node_name = node_name
        self.key_pem = key_pem
        self.cert_pem = cert_pem
        self.cert_der = cert_der
        self.requested_port = port
        self.bound_port = 0
        self.download_dir = download_dir
        self.signals = ReceiverSignals()

        self._running = False
        self._listener_sock: Optional[socket.socket] = None
        self._ssl_ctx = create_tls_server_context(key_pem, cert_pem)
        self.pending_approvals: Dict[str, Tuple[threading.Event, Dict[str, Any]]] = {}

    def respond_to_transfer(self, transfer_id: str, accept: bool) -> None:
        """Called by UI thread when user clicks Accept or Reject on security modal."""
        item = self.pending_approvals.get(transfer_id)
        if item:
            event, result = item
            result["accepted"] = accept
            event.set()

    def run(self) -> None:
        self._running = True

        self._listener_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            try:
                self._listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        elif hasattr(socket, "SO_REUSEADDR"):
            self._listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Try binding to requested port or fallback to dynamic port
        bound = False
        for candidate_port in ([self.requested_port] if self.requested_port > 0 else []) + [52345, 52346, 52347, 0]:
            try:
                self._listener_sock.bind(("0.0.0.0", candidate_port))
                bound = True
                break
            except OSError:
                continue

        if not bound:
            self._listener_sock.bind(("0.0.0.0", 0))

        self.bound_port = self._listener_sock.getsockname()[1]
        self._listener_sock.listen(10)
        self._listener_sock.setblocking(False)

        self.signals.server_ready.emit(self.bound_port)
        self.signals.status_message.emit(f"TLS 1.3 Receiver listening on TCP port {self.bound_port}")

        while self._running:
            try:
                readable, _, _ = select.select([self._listener_sock], [], [], 0.5)
                if readable and self._running:
                    raw_client_sock, client_addr = self._listener_sock.accept()
                    # Spawn dedicated worker thread for each connection
                    conn_worker = ReceiverConnectionThread(
                        raw_sock=raw_client_sock,
                        client_addr=client_addr,
                        server_ssl_ctx=self._ssl_ctx,
                        local_node_id=self.node_id,
                        local_name=self.node_name,
                        local_cert_der=self.cert_der,
                        signals=self.signals,
                        pending_approvals=self.pending_approvals,
                        download_dir=self.download_dir,
                    )
                    conn_worker.start()
            except Exception as exc:
                if self._running:
                    self.signals.status_message.emit(f"Server listener error: {exc}")

        self._cleanup()

    def stop(self) -> None:
        """Thread-safe shutdown hook."""
        self._running = False
        self._cleanup()
        self.wait(1500)

    def _cleanup(self) -> None:
        if self._listener_sock:
            try:
                self._listener_sock.close()
            except Exception:
                pass
            self._listener_sock = None


class FileSenderWorker(QThread):
    """
    QThread worker for initiating and streaming a file to a remote peer over TLS 1.3.
    """
    status_update = pyqtSignal(str)
    pin_available = pyqtSignal(str, str, str, int)         # (pin, peer_name, filename, filesize)
    waiting_peer = pyqtSignal(str)                         # (message)
    transfer_started = pyqtSignal(str, int)                # (filename, filesize)
    transfer_progress = pyqtSignal(int, int, float)        # (bytes_sent, filesize, speed_mbps)
    transfer_completed = pyqtSignal(str)                   # (filename)
    transfer_rejected = pyqtSignal(str)                    # (reason)
    transfer_failed = pyqtSignal(str)                      # (error_message)

    def __init__(
        self,
        peer_ip: str,
        peer_port: int,
        peer_name: str,
        filepath: str | Path,
        local_node_id: str,
        local_name: str,
        key_pem: bytes,
        cert_pem: bytes,
        cert_der: bytes,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.peer_name = peer_name
        self.filepath = Path(filepath)
        self.local_node_id = local_node_id
        self.local_name = local_name
        self.key_pem = key_pem
        self.cert_pem = cert_pem
        self.cert_der = cert_der
        self._cancelled = False
        self._ssl_sock: Optional[socket.socket] = None

    def cancel(self) -> None:
        self._cancelled = True
        if self._ssl_sock:
            try:
                self._ssl_sock.close()
            except Exception:
                pass

    def run(self) -> None:
        raw_sock = None
        try:
            if not self.filepath.exists() or not self.filepath.is_file():
                raise FileNotFoundError(f"Selected file not found: {self.filepath}")

            filename = self.filepath.name
            filesize = self.filepath.stat().st_size
            if filesize <= 0:
                raise ValueError("Cannot transfer an empty file (0 bytes).")

            # 1. Compute File SHA-256 Digest
            self.status_update.emit("Calculating SHA-256 checksum...")
            file_sha256 = compute_file_sha256(self.filepath)
            if self._cancelled:
                return

            # 2. Establish Secure TLS 1.3 TCP Socket
            self.status_update.emit(f"Connecting to {self.peer_name} ({self.peer_ip}:{self.peer_port})...")
            raw_sock = socket.create_connection((self.peer_ip, self.peer_port), timeout=10.0)

            client_ssl_ctx = create_tls_client_context(self.key_pem, self.cert_pem)
            self._ssl_sock = client_ssl_ctx.wrap_socket(raw_sock, server_hostname="DropLAN-Node")
            self._ssl_sock.settimeout(60.0)

            # 3. Handshake Phase
            send_json_frame(
                self._ssl_sock,
                FRAME_HANDSHAKE,
                {
                    "node_id": self.local_node_id,
                    "name": self.local_name,
                    "cert_der": base64.b64encode(self.cert_der).decode("utf-8"),
                },
            )

            frame_type, server_hello = read_json_frame(self._ssl_sock)
            if frame_type != FRAME_HANDSHAKE:
                raise ConnectionError(f"Expected server Handshake frame, got 0x{frame_type:02X}")

            server_cert_b64 = server_hello.get("cert_der", "")
            if not server_cert_b64:
                raise ConnectionError("Missing server certificate in Handshake response.")
            server_cert_der = base64.b64decode(server_cert_b64)

            # Derive SAS PIN
            sas_pin = derive_sas_pin(self.cert_der, server_cert_der)
            self.pin_available.emit(sas_pin, self.peer_name, filename, filesize)

            # 4. Metadata Phase
            send_json_frame(
                self._ssl_sock,
                FRAME_METADATA,
                {
                    "filename": filename,
                    "filesize": filesize,
                    "sha256": file_sha256,
                },
            )

            # 5. Await Recipient PIN Approval
            self.waiting_peer.emit(f"Waiting for {self.peer_name} to confirm pairing PIN...")
            frame_type, resp = read_json_frame(self._ssl_sock)
            if frame_type != FRAME_RESPONSE or not resp.get("accepted", False):
                reason = resp.get("reason", "Transfer rejected by recipient.")
                self.transfer_rejected.emit(reason)
                return

            if self._cancelled:
                return

            # 6. Stream File Chunks (64 KB window)
            self.transfer_started.emit(filename, filesize)
            bytes_sent = 0
            start_time = time.time()
            last_speed_calc_time = start_time
            last_bytes_speed = 0
            current_speed_mbps = 0.0

            with open(self.filepath, "rb") as in_file:
                while not self._cancelled:
                    chunk = in_file.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    send_frame(self._ssl_sock, FRAME_DATA_CHUNK, chunk)
                    bytes_sent += len(chunk)

                    now = time.time()
                    if now - last_speed_calc_time >= 0.2:
                        time_delta = now - last_speed_calc_time
                        bytes_delta = bytes_sent - last_bytes_speed
                        current_speed_mbps = (bytes_delta / (1024 * 1024)) / time_delta if time_delta > 0 else 0.0
                        last_speed_calc_time = now
                        last_bytes_speed = bytes_sent
                        self.transfer_progress.emit(bytes_sent, filesize, current_speed_mbps)

            if self._cancelled:
                self.transfer_failed.emit("Transfer cancelled by user.")
                return

            # 7. Send EOF Marker
            send_frame(self._ssl_sock, FRAME_EOF, b"")
            self.status_update.emit("Awaiting integrity confirmation from recipient...")

            # 8. Receive Final Confirmation
            frame_type, final_resp = read_json_frame(self._ssl_sock)
            if frame_type == FRAME_RESPONSE and final_resp.get("success", False):
                self.transfer_progress.emit(filesize, filesize, 0.0)
                self.transfer_completed.emit(filename)
            else:
                err_msg = final_resp.get("error", "Recipient reported integrity failure.")
                self.transfer_failed.emit(err_msg)

        except Exception as exc:
            if not self._cancelled:
                self.transfer_failed.emit(f"Sender error: {exc}")
        finally:
            if self._ssl_sock:
                try:
                    self._ssl_sock.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass
