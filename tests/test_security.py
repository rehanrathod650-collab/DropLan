import os
from pathlib import Path
import tempfile
import pytest

from security import (
    generate_ephemeral_certificate,
    create_tls_server_context,
    create_tls_client_context,
    derive_sas_pin,
    compute_file_sha256,
    sanitize_filename,
    resolve_quarantine_path,
)


def test_ephemeral_cert_generation():
    key_pem, cert_pem, cert_der = generate_ephemeral_certificate("TestNode")
    assert b"BEGIN RSA PRIVATE KEY" in key_pem or b"BEGIN PRIVATE KEY" in key_pem
    assert b"BEGIN CERTIFICATE" in cert_pem
    assert len(cert_der) > 0


def test_tls_contexts():
    key_pem, cert_pem, _ = generate_ephemeral_certificate("ContextTest")
    server_ctx = create_tls_server_context(key_pem, cert_pem)
    client_ctx = create_tls_client_context(key_pem, cert_pem)
    assert server_ctx is not None
    assert client_ctx is not None


def test_derive_sas_pin_symmetry():
    _, _, cert_a = generate_ephemeral_certificate("NodeA")
    _, _, cert_b = generate_ephemeral_certificate("NodeB")

    pin1 = derive_sas_pin(cert_a, cert_b)
    pin2 = derive_sas_pin(cert_b, cert_a)

    assert len(pin1) == 6
    assert pin1.isdigit()
    # Mutual pairing must produce the exact same PIN regardless of who is sender or receiver
    assert pin1 == pin2


def test_compute_file_sha256():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"DropLAN high performance P2P file sharing test data")
        f.flush()
        fpath = f.name

    try:
        h = compute_file_sha256(fpath)
        assert len(h) == 64
        # Known SHA256 of the above test string
        import hashlib
        expected = hashlib.sha256(b"DropLAN high performance P2P file sharing test data").hexdigest()
        assert h == expected
    finally:
        os.remove(fpath)


def test_sanitize_filename_traversal():
    assert sanitize_filename("safe_file.txt") == "safe_file.txt"
    assert sanitize_filename("folder/sub/safe.pdf") == "safe.pdf"
    assert sanitize_filename("C:\\Users\\Victim\\Desktop\\photo.png") == "photo.png"

    with pytest.raises(ValueError):
        sanitize_filename("../../etc/passwd")

    with pytest.raises(ValueError):
        sanitize_filename("..\\..\\Windows\\System32\\cmd.exe")

    with pytest.raises(ValueError):
        sanitize_filename("evil\x00file.exe")


def test_resolve_quarantine_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        p1 = resolve_quarantine_path("test.txt", base_dir=tmpdir)
        assert p1.name == "test.txt"
        assert p1.parent == Path(tmpdir).resolve()

        # Create the file and check collision handling
        p1.touch()
        p2 = resolve_quarantine_path("test.txt", base_dir=tmpdir)
        assert p2.name == "test (1).txt"
        assert p2.parent == Path(tmpdir).resolve()
