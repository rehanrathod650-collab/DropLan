# DropLAN — Zero-Trust P2P Local File Transfer

**DropLAN** is a secure, high-performance, production-ready peer-to-peer desktop file transfer application built with **Python 3** and **PyQt6**. It enables zero-configuration file sharing across local area networks (LAN) with ephemeral end-to-end **TLS 1.3** encryption, deterministic Short Authentication String (**SAS**) pairing verification, and streaming **SHA-256** integrity validation.

---

## ⚡ Quick Download (No Installation Required)

For students, lab computers, or anyone who doesn't want to install Python:

[![Download DropLAN.exe](https://img.shields.io/badge/Download-DropLAN.exe%20(v1.0.0)-00d2ff?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/rehanrathod650-collab/DropLan/releases/latest)

* 👉 **[Download DropLAN.exe from GitHub Releases](https://github.com/rehanrathod650-collab/DropLan/releases/latest)**
* **Direct Download Link:** [DropLAN.exe (v1.0.0)](https://github.com/rehanrathod650-collab/DropLan/releases/download/v1.0.0/DropLAN.exe)

> **No setup required:** Runs directly on any Windows 10/11 PC. No Python, no command line, and no administrator privileges needed!

---

## 📖 How to Use in a Lab / Wi-Fi (Step-by-Step)

```
+-----------------------------------------------------------------------------------------+
| [⚡ DropLAN]                          Node: Alice-PC | TCP: 52345       [📁 Downloads]   |
+------------------------------+----------------------------------------------------------+
| DISCOVERED PEERS             | SEND FILE                                                |
|                              | +------------------------------------------------------+ |
| [💻 Bob-Laptop   ● Ready]    | |   📁 Drag & drop any file here, or click Browse      | |
|    192.168.1.105:52346       | +------------------------------------------------------+ |
|                              | [📄 assignment.zip (45.2 MB)]      [Send to Bob-Laptop 🚀]|
|                              +----------------------------------------------------------+
|                              | TRANSFER MONITOR                                         |
|                              | [======= 75% =======]  Speed: 42.1 MB/s                  |
+------------------------------+----------------------------------------------------------+
```

### Step 1: Open DropLAN on Both Computers
* Download [`DropLAN.exe`](https://github.com/rehanrathod650-collab/DropLan/releases/latest) and double-click to run it on both computers.
* Make sure both machines are connected to the same Wi-Fi, Ethernet switch, or phone hotspot.

### Step 2: Automatic Peer Discovery
* Within 2 seconds, both devices will automatically discover each other and appear in the **Discovered Peers** sidebar on the left with a green `● Ready` badge.

### Step 3: Select Recipient & File
1. In the left sidebar, **click on the peer** you want to send files to (e.g., `Bob-Laptop`).
2. **Drag & drop** any file into the central dotted box, or click **Browse File...**.
3. Click the bright cyan **Send File 🚀** button.

### Step 4: Verify 6-Digit SAS PIN (Zero-Trust Security)
* The sender will see: `PAIRING PIN: [ 794 924 ] — Waiting for recipient approval...`
* The recipient's screen pops up an interactive **Security Pairing Request** showing the file name, size, sender info, and the matching `794 924` PIN.
* The recipient verifies the PIN matches the sender's screen and clicks **Accept & Receive File**.

### Step 5: Transfer & Open File
* The file streams directly over an encrypted TLS 1.3 socket with real-time speed readouts (MB/s).
* Upon completion, DropLAN validates the SHA-256 integrity hash.
* Click the **📁 Downloads** button in the top-right header to view your received files in `~/Downloads/DropLAN_Received`.

---

## 🚀 Key Features

* **100% Offline & Private:** Operates strictly on your local network. No internet connection, cloud servers, or third-party accounts are used.
* **Zero-Configuration LAN Discovery:** Auto-discovers active peers on your local subnet using UDP heartbeat mesh broadcasts (`255.255.255.255:54545`) every 2 seconds, pruning silent nodes after 6 seconds.
* **Ephemeral TLS 1.3 Encryption:** Per-session in-memory 2048-bit RSA keys and self-signed X.509 certificates generated dynamically using `cryptography`. TLS 1.3 is strictly enforced (`ssl.TLSVersion.TLSv1_3`).
* **Mutual SAS PIN Verification:** Derives a deterministic 6-digit PIN via `HMAC-SHA256(key=b"DropLAN-SAS-Salt", sorted_certs)`. An interactive confirmation modal prompts the receiver to visually verify the PIN against the sender's screen before a single file byte is accepted or written.
* **Sanitized Quarantine Storage:** Hardened against directory traversal (`..`, null bytes, Windows reserved device names, and Alternate Data Streams). Files are safely written to `~/Downloads/DropLAN_Received/<filename>.part` and atomically finalized only upon checksum match.
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

## 🛠️ Developer Setup (Running from Source)

### Prerequisites
* Python 3.10+ (tested on Python 3.10 through 3.14)
* Windows, macOS, or Linux

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run Locally
```bash
python main.py
```

### Multi-Instance Local Testing (Same Machine)
Open two separate terminal sessions to simulate two devices:

* **Terminal 1:**
  ```powershell
  python main.py --name "Alice-PC" --port 52345
  ```
* **Terminal 2:**
  ```powershell
  python main.py --name "Bob-Laptop" --port 52346
  ```

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

## 🧪 Automated Test Suite

Run the full suite of 16 unit and end-to-end integration tests using `pytest`:

```bash
python -m pytest tests/ -v
```

All tests execute fully in memory and offscreen with zero manual intervention required.
