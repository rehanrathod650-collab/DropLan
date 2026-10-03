# DropLAN — Zero-Trust P2P Local File Transfer

**DropLAN** is a secure, high-performance, production-ready peer-to-peer desktop file transfer application built with **Python 3** and **PyQt6**. It enables zero-configuration file sharing across local area networks (LAN) with ephemeral end-to-end **TLS 1.3** encryption, deterministic Short Authentication String (**SAS**) pairing verification, and streaming **SHA-256** integrity validation.

---

## 🚀 Key Features

* **Zero-Configuration LAN Discovery:** Auto-discovers active peers on your local subnet using UDP heartbeat mesh broadcasts (`255.255.255.255:54545`) every 2 seconds, pruning silent nodes after 6 seconds.
* **Ephemeral TLS 1.3 Encryption:** Per-session in-memory 2048-bit RSA keys and self-signed X.509 certificates generated dynamically using `cryptography`. TLS 1.3 is strictly enforced (`ssl.TLSVersion.TLSv1_3`).
* **Mutual SAS PIN Verification:** Derives a deterministic 6-digit PIN via `HMAC-SHA256(key=b"DropLAN-SAS-Salt", sorted_certs)`. An interactive confirmation modal prompts the receiver to visually verify the PIN against the sender's screen before a single file byte is accepted or written.
* **Sanitized Quarantine Storage:** Hardened against directory traversal (`..`, null bytes, and path escape attempts). Files are safely written to `~/Downloads/DropLAN_Received/<filename>.part` and atomically finalized only upon checksum match.
* **Streaming SHA-256 Data Integrity:** Real-time hash calculation during transfer; corrupted or partially downloaded files are automatically purged.
* **Binary Framing Protocol:** 5-byte fixed header (`!BI`: 1-byte frame type, 4-byte big-endian length) with a 64 KB streaming window and explicit `recv_exact()` buffering to eliminate TCP window fragmentation bugs.
* **Non-Blocking PyQt6 Architecture:** Network I/O, cryptographic operations, and disk streaming run on isolated background threads (`QThread`), keeping the dark-themed UI completely responsive.

---

## 📁 Project Architecture

```
P2P File Sharing/
├── requirements.txt         # Dependencies (PyQt6, cryptography, pytest)
├── security.py              # Ephemeral TLS 1.3, SAS PIN derivation, SHA-256 & path sanitization
├── protocol.py              # Binary framing encoder/decoder, 64KB chunking, recv_exact loop
├── network/
│   ├── __init__.py
│   ├── discovery.py         # UDP mesh emitter & peer state tracker (QThread)
│   └── transfer.py          # Multi-threaded TLS 1.3 TCP Server (Receiver) & Client (Sender)
├── ui/
│   ├── __init__.py
│   ├── main_window.py       # Main PyQt6 interface, drag & drop zone, transfer monitor
│   ├── security_dialog.py   # Interactive SAS PIN pairing confirmation modal
│   └── styles.py            # Modern dark theme QSS styling & design tokens
├── main.py                  # Application entrypoint & graceful lifecycle management
├── tests/
│   ├── test_security.py     # Crypto & sanitization unit tests
│   ├── test_protocol.py     # Wire framing unit tests
│   ├── test_discovery.py    # UDP mesh packet unit tests
│   ├── test_transfer.py     # TLS 1.3 socket streaming & rejection tests
│   ├── test_mesh_multi_node.py # Dual-node discovery & transfer integration test
│   └── test_ui.py           # GUI & dialog validation tests
└── README.md                # Documentation & usage guide
```

---

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.10+ (tested on Python 3.10, 3.11, 3.12, 3.13, 3.14)
* Windows, macOS, or Linux

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 💻 Running DropLAN

### Single Instance (Normal LAN usage)
```bash
python main.py
```
This automatically uses your machine hostname and binds to an available TCP port.

### Multiple Instances on the Same Machine (Testing Guide)
To test peer-to-peer discovery and transfer on a single development workstation, open two separate terminal sessions:

#### Terminal 1 (Node A — Alice):
```bash
python main.py --name "Alice-PC" --port 52345
```

#### Terminal 2 (Node B — Bob):
```bash
python main.py --name "Bob-Laptop" --port 52346
```

1. **Auto-Discovery:** Within 2 seconds, "Bob-Laptop" will appear in Alice's sidebar list under **Discovered Peers**, and "Alice-PC" will appear in Bob's list.
2. **Select Recipient:** On Alice's screen, click on "Bob-Laptop" in the left sidebar.
3. **Choose File:** Drag and drop any file into the central **Drop Zone**, or click **Browse File...**.
4. **Initiate Transfer:** Click **Send to Bob-Laptop 🚀**.
5. **SAS PIN Verification:**
   * Alice's screen displays: `PAIRING PIN: [ XXX XXX ] — Waiting for Bob-Laptop to verify...`
   * Bob's screen pops up an interactive **Security Pairing Request** modal displaying Alice's hostname, IP, file name, file size, and the identical 6-digit PIN.
6. **Accept Transfer:** Bob confirms the PIN matches Alice's screen and clicks **Accept & Receive File**.
7. **Streaming & Integrity:** Chunks stream in real-time with speed readouts (MB/s) and a smooth progress bar. Once complete, SHA-256 is verified, and the file is saved to `~/Downloads/DropLAN_Received`.
8. **Open Received Files:** Click the **📁 Downloads** button in the header bar to immediately view received files in your file manager.

---

## 🔒 Wire Protocol Specification

Binary packets consist of a fixed 5-byte header followed by variable-length payload:

```
+---------------+------------------------+---------------------------------------+
| Type (1 Byte) | Length (4 Bytes uint)  | Payload (0 to Length Bytes)           |
+---------------+------------------------+---------------------------------------+
```

| Frame Type | Code | Description |
|---|---|---|
| `FRAME_HANDSHAKE` | `0x01` | Exchange sender/receiver metadata and DER-encoded public certificates |
| `FRAME_METADATA`  | `0x02` | JSON payload containing `filename`, `filesize`, and expected `sha256` |
| `FRAME_DATA_CHUNK`| `0x03` | Raw binary chunk (up to 64 KB) |
| `FRAME_EOF`       | `0x04` | Signals the end of the file stream |
| `FRAME_RESPONSE`  | `0x05` | JSON response payload (`accepted`, `success`, `error`, `reason`) |

---

## 🧪 Running the Automated Test Suite

Run the full suite of 16 unit and end-to-end integration tests using `pytest`:

```bash
python -m pytest tests/ -v
```

All tests execute fully in memory and offscreen with zero GUI popups or manual steps required.
