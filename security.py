"""
DropLAN Security Module
Handles ephemeral TLS 1.3 certificate generation, SSLContext configuration,
Short Authentication String (SAS) PIN derivation, SHA-256 data integrity,
and directory traversal hardening.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
from pathlib import Path
import ssl
import tempfile
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SAS_SALT = b"DropLAN-SAS-Salt"
DEFAULT_DOWNLOAD_DIR = Path.home() / "Downloads" / "DropLAN_Received"


def generate_ephemeral_certificate(
    common_name: str = "DropLAN-Node",
) -> Tuple[bytes, bytes, bytes]:
    """
    Generates an in-memory 2048-bit RSA key and a self-signed X.509 certificate.
    Returns:
        (private_key_pem, cert_pem, cert_der)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DropLAN P2P"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .sign(private_key, hashes.SHA256())
    )

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    return key_pem, cert_pem, cert_der


def create_tls_server_context(key_pem: bytes, cert_pem: bytes) -> ssl.SSLContext:
    """
    Creates an SSLContext configured strictly for TLS 1.3 server side.
    Loads ephemeral certificate and key securely, then unlinks temp files.
    """
    # Use TLS_SERVER protocol
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Strictly enforce TLS 1.3
    if hasattr(ssl.TLSVersion, "TLSv1_3"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_NONE

    key_fd, key_path = tempfile.mkstemp(prefix="droplan_sk_", suffix=".pem")
    cert_fd, cert_path = tempfile.mkstemp(prefix="droplan_sc_", suffix=".pem")

    try:
        with os.fdopen(key_fd, "wb") as f:
            f.write(key_pem)
        with os.fdopen(cert_fd, "wb") as f:
            f.write(cert_pem)

        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        try:
            os.remove(key_path)
        except OSError:
            pass
        try:
            os.remove(cert_path)
        except OSError:
            pass

    return ctx


def create_tls_client_context(key_pem: bytes, cert_pem: bytes) -> ssl.SSLContext:
    """
    Creates an SSLContext configured strictly for TLS 1.3 client side.
    Loads ephemeral certificate and key securely, then unlinks temp files.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if hasattr(ssl.TLSVersion, "TLSv1_3"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    key_fd, key_path = tempfile.mkstemp(prefix="droplan_ck_", suffix=".pem")
    cert_fd, cert_path = tempfile.mkstemp(prefix="droplan_cc_", suffix=".pem")

    try:
        with os.fdopen(key_fd, "wb") as f:
            f.write(key_pem)
        with os.fdopen(cert_fd, "wb") as f:
            f.write(cert_pem)

        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        try:
            os.remove(key_path)
        except OSError:
            pass
        try:
            os.remove(cert_path)
        except OSError:
            pass

    return ctx


def derive_sas_pin(cert_a_der: bytes, cert_b_der: bytes, salt: bytes = SAS_SALT) -> str:
    """
    Derives a deterministic 6-digit Short Authentication String (SAS) code:
    HMAC-SHA256(key=salt, sorted_certs) converted to a 6-digit decimal PIN.
    Sorting ensures both peers compute the identical PIN regardless of sender/receiver role.
    """
    sorted_certs = b"".join(sorted([cert_a_der, cert_b_der]))
    mac = hmac.new(salt, sorted_certs, hashlib.sha256).digest()
    # Take first 4 bytes as unsigned integer modulo 1,000,000
    pin_int = int.from_bytes(mac[:4], "big") % 1_000_000
    return f"{pin_int:06d}"


def compute_file_sha256(filepath: str | Path, chunk_size: int = 1024 * 1024) -> str:
    """
    Computes streaming SHA-256 digest of a local file.
    """
    path = Path(filepath)
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def sanitize_filename(filename: str) -> str:
    """
    Hardens against directory traversal attacks.
    Rejects paths containing '..' or null bytes, strips directory components,
    and returns a clean, safe basename.
    """
    if not filename or "\x00" in filename:
        raise ValueError("Filename contains invalid characters.")

    # Check for directory traversal attempts
    normalized = filename.replace("\\", "/")
    parts = normalized.split("/")
    if ".." in parts:
        raise ValueError("Directory traversal attempt detected ('..').")

    # Extract clean basename
    basename = os.path.basename(normalized)

    # Disallow Alternate Data Streams (colons) and drive letters
    if ":" in basename:
        raise ValueError("Filename contains illegal characters (colons / alternate data streams).")

    # Strip illegal characters across Windows and POSIX: < > : " / \ | ? *
    illegal_chars = set('<>:"/\\|?*')
    clean_name = "".join(c for c in basename if c.isprintable() and c not in illegal_chars).strip()
    # Strip trailing periods and spaces (Windows normalization hazard)
    clean_name = clean_name.rstrip(". ")

    if not clean_name or clean_name in (".", ".."):
        raise ValueError("Sanitized filename is empty or invalid.")

    # Check Windows reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    stem_upper = clean_name.split(".")[0].upper()
    reserved_names = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
    if stem_upper in reserved_names:
        clean_name = f"safe_{clean_name}"

    # Truncate length if exceeds 255
    if len(clean_name) > 255:
        stem = Path(clean_name).stem[:240]
        suffix = Path(clean_name).suffix[:10]
        clean_name = f"{stem}{suffix}"

    return clean_name


def resolve_quarantine_path(
    filename: str,
    base_dir: Path | str | None = None,
) -> Path:
    """
    Resolves safe quarantine path in ~/Downloads/DropLAN_Received.
    Ensures path does not escape quarantine root.
    Handles filename collisions by appending (1), (2), etc.
    """
    clean_name = sanitize_filename(filename)
    dest_dir = Path(base_dir).resolve() if base_dir else DEFAULT_DOWNLOAD_DIR.resolve()
    dest_dir.mkdir(parents=True, exist_ok=True)

    target_path = (dest_dir / clean_name).resolve()

    # Verify target path is strictly within dest_dir
    try:
        target_path.relative_to(dest_dir)
    except ValueError:
        raise ValueError("Destination path escapes designated quarantine directory.")

    # Avoid overwriting existing files
    if not target_path.exists():
        return target_path

    stem = target_path.stem
    suffix = target_path.suffix
    counter = 1
    while True:
        candidate = dest_dir / f"{stem} ({counter}){suffix}"
        if not candidate.exists():
            return candidate
        counter += 1
