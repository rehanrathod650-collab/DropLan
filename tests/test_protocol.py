import socket
import threading
import pytest

from protocol import (
    HEADER_STRUCT,
    HEADER_SIZE,
    FRAME_HANDSHAKE,
    FRAME_METADATA,
    FRAME_DATA_CHUNK,
    FRAME_EOF,
    FRAME_RESPONSE,
    send_frame,
    read_frame,
    send_json_frame,
    read_json_frame,
    recv_exact,
)


def test_header_size():
    assert HEADER_SIZE == 5
    assert HEADER_STRUCT.size == 5


def test_frame_send_receive_raw():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def server_worker():
        client_sock, _ = listener.accept()
        # Read two frames
        f_type1, payload1 = read_frame(client_sock)
        assert f_type1 == FRAME_DATA_CHUNK
        assert payload1 == b"Sample 64KB chunk dummy data"

        f_type2, payload2 = read_frame(client_sock)
        assert f_type2 == FRAME_EOF
        assert payload2 == b""

        # Send response frame
        send_frame(client_sock, FRAME_RESPONSE, b"ACK")
        client_sock.close()

    t = threading.Thread(target=server_worker)
    t.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))

    send_frame(client, FRAME_DATA_CHUNK, b"Sample 64KB chunk dummy data")
    send_frame(client, FRAME_EOF, b"")

    resp_type, resp_payload = read_frame(client)
    assert resp_type == FRAME_RESPONSE
    assert resp_payload == b"ACK"

    client.close()
    t.join()
    listener.close()


def test_json_frame_send_receive():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    meta_data = {
        "filename": "archive.tar.gz",
        "filesize": 104857600,
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    }

    def server_worker():
        sock, _ = listener.accept()
        ftype, data = read_json_frame(sock)
        assert ftype == FRAME_METADATA
        assert data == meta_data

        send_json_frame(sock, FRAME_RESPONSE, {"accepted": True, "pin": "123456"})
        sock.close()

    t = threading.Thread(target=server_worker)
    t.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))

    send_json_frame(client, FRAME_METADATA, meta_data)
    resp_type, resp_data = read_json_frame(client)
    assert resp_type == FRAME_RESPONSE
    assert resp_data["accepted"] is True
    assert resp_data["pin"] == "123456"

    client.close()
    t.join()
    listener.close()


def test_recv_exact_incomplete():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def server_worker():
        sock, _ = listener.accept()
        # Send only 3 bytes then immediately close
        sock.sendall(b"123")
        sock.close()

    t = threading.Thread(target=server_worker)
    t.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))

    # Expecting 10 bytes should raise ConnectionError
    with pytest.raises(ConnectionError):
        recv_exact(client, 10)

    client.close()
    t.join()
    listener.close()
