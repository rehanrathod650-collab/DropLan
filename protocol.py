"""
DropLAN Wire Protocol & Framing Module
Implements binary framing with fixed struct header:
    struct.Struct("!BI") -> 1-byte Frame Type, 4-byte Big-Endian Length
Provides robust streaming chunking via recv_exact to prevent TCP window partial-read bugs.
"""

from __future__ import annotations

import json
import socket
import struct
from typing import Any, Dict, Tuple

# Header Format:
# ! = Network (big-endian)
# B = unsigned char (1 byte, Frame Type)
# I = unsigned int (4 bytes, Payload Length)
HEADER_STRUCT = struct.Struct("!BI")
HEADER_SIZE = HEADER_STRUCT.size  # 5 bytes

# Frame Types
FRAME_HANDSHAKE: int = 0x01   # Handshake / Hello (sender info, cert DER)
FRAME_METADATA: int = 0x02    # Transfer Metadata (filename, size, SHA-256)
FRAME_DATA_CHUNK: int = 0x03  # Raw File Data Chunk (64 KB window)
FRAME_EOF: int = 0x04         # Finish / EOF Marker
FRAME_RESPONSE: int = 0x05    # Mutual pairing response (Accepted / Rejected / Status)

# 64 KB streaming window
CHUNK_SIZE: int = 64 * 1024


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """
    Reads exactly `num_bytes` from the socket in a loop.
    Guarantees full payload extraction regardless of TCP fragmentation.
    Raises:
        ConnectionResetError: If the socket is cleanly closed before any bytes are read.
        ConnectionError: If the socket closes prematurely after receiving partial bytes.
    """
    buffer = bytearray()
    while len(buffer) < num_bytes:
        try:
            chunk = sock.recv(num_bytes - len(buffer))
        except (ConnectionResetError, ConnectionAbortedError) as exc:
            raise ConnectionError(f"Connection reset while reading exact bytes: {exc}") from exc

        if not chunk:
            if len(buffer) == 0:
                raise ConnectionResetError("Remote endpoint closed connection.")
            raise ConnectionError(
                f"Socket closed unexpectedly: expected {num_bytes} bytes, received {len(buffer)}."
            )
        buffer.extend(chunk)
    return bytes(buffer)


# Maximum allowed frame size (16 MB) to prevent memory exhaustion attacks
MAX_FRAME_SIZE: int = 16 * 1024 * 1024


def read_frame(sock: socket.socket) -> Tuple[int, bytes]:
    """
    Reads a single binary framed packet from the socket.
    Enforces MAX_FRAME_SIZE to guard against memory exhaustion attacks.
    Returns:
        (frame_type, payload_bytes)
    """
    header_bytes = recv_exact(sock, HEADER_SIZE)
    frame_type, length = HEADER_STRUCT.unpack(header_bytes)

    if length > MAX_FRAME_SIZE:
        raise ValueError(
            f"Security alert: Incoming frame length {length} exceeds maximum allowed {MAX_FRAME_SIZE} bytes."
        )

    if length == 0:
        return frame_type, b""

    payload = recv_exact(sock, length)
    return frame_type, payload


def send_frame(sock: socket.socket, frame_type: int, payload: bytes = b"") -> None:
    """
    Encodes and transmits a binary framed packet over the socket.
    """
    header_bytes = HEADER_STRUCT.pack(frame_type, len(payload))
    sock.sendall(header_bytes + payload)


def send_json_frame(sock: socket.socket, frame_type: int, data: Dict[str, Any]) -> None:
    """
    Serializes a Python dictionary to JSON and sends it as a framed payload.
    """
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    send_frame(sock, frame_type, payload)


def read_json_frame(sock: socket.socket) -> Tuple[int, Dict[str, Any]]:
    """
    Reads a frame and parses the UTF-8 payload as a JSON dictionary.
    """
    frame_type, payload = read_frame(sock)
    if not payload:
        return frame_type, {}
    try:
        data = json.loads(payload.decode("utf-8"))
        return frame_type, data
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Failed to parse JSON payload for frame 0x{frame_type:02X}: {exc}") from exc
