"""
DropLAN Mobile Web Portal Module
Enables seamless bidirectional file transfer between PC and smartphones (Android & iOS)
over the local Wi-Fi network without requiring any mobile app installation.
Runs an embedded, high-performance HTTP server with modern mobile UI and QR code pairing.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import threading
from typing import Any, Dict, List, Optional
import urllib.parse
import uuid

from PyQt6.QtCore import QObject, QThread, pyqtSignal

from security import DEFAULT_DOWNLOAD_DIR, resolve_quarantine_path, sanitize_filename


def get_local_lan_ip() -> str:
    """
    Determines the active local network (LAN / Wi-Fi) IPv4 address.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connecting to link-local broadcast forces OS to pick the active LAN interface
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip


MOBILE_WEB_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>DropLAN Mobile</title>
    <style>
        :root {
            --bg-primary: #0f1117;
            --bg-card: #181c28;
            --bg-card-hover: #212638;
            --accent: #00d2ff;
            --accent-green: #00e676;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border: #283045;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            padding: 16px;
            max-width: 600px;
            margin: 0 auto;
            line-height: 1.5;
        }
        header {
            text-align: center;
            padding: 18px 0 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 20px;
        }
        .logo-box {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
        }
        .logo-icon { font-size: 26px; }
        h1 { font-size: 22px; font-weight: 800; letter-spacing: 0.5px; }
        .node-pill {
            display: inline-block;
            background: #1e293b;
            color: var(--accent);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-top: 4px;
        }
        .card {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 18px;
            margin-bottom: 20px;
        }
        h2 {
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .badge {
            background: #252e42;
            color: var(--accent-green);
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
        }
        .drop-box {
            border: 2px dashed #334155;
            border-radius: 12px;
            padding: 24px 16px;
            text-align: center;
            background: #131620;
            cursor: pointer;
            transition: all 0.2s;
        }
        .drop-box:active {
            background: #1c2333;
            border-color: var(--accent);
        }
        .drop-icon { font-size: 36px; margin-bottom: 8px; }
        .drop-text { font-size: 14px; color: var(--text-secondary); font-weight: 500; }
        input[type="file"] { display: none; }
        .btn {
            display: block;
            width: 100%;
            background: linear-gradient(135deg, #00b4db, #0083b0);
            color: #ffffff;
            border: none;
            border-radius: 10px;
            padding: 14px;
            font-size: 15px;
            font-weight: 700;
            cursor: pointer;
            margin-top: 14px;
            text-align: center;
            text-decoration: none;
        }
        .btn:disabled {
            background: #1e293b;
            color: #64748b;
            cursor: not-allowed;
        }
        .file-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px;
            background: #131620;
            border: 1px solid #232a3d;
            border-radius: 10px;
            margin-bottom: 10px;
        }
        .file-item-info {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            padding-right: 12px;
        }
        .file-name { font-weight: 600; font-size: 14px; color: #f1f5f9; }
        .file-size { font-size: 11px; color: var(--text-secondary); }
        .btn-dl {
            background: #059669;
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 8px 14px;
            font-size: 12px;
            font-weight: 700;
            text-decoration: none;
            flex-shrink: 0;
        }
        .progress-container {
            margin-top: 14px;
            display: none;
        }
        .progress-bar-bg {
            background: #1e293b;
            border-radius: 8px;
            height: 10px;
            overflow: hidden;
        }
        .progress-bar-fill {
            background: linear-gradient(90deg, #00d2ff, #00e676);
            height: 100%;
            width: 0%;
            transition: width 0.15s;
        }
        .progress-status {
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 6px;
            text-align: center;
        }
        .empty-msg {
            color: #64748b;
            font-size: 13px;
            text-align: center;
            padding: 16px 0;
        }
        .footer {
            text-align: center;
            font-size: 11px;
            color: #64748b;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-box">
            <span class="logo-icon">⚡</span>
            <h1>DropLAN Mobile</h1>
        </div>
        <div><span class="node-pill">Connected to __PC_NAME__</span></div>
    </header>

    <!-- Upload to PC -->
    <div class="card">
        <h2><span>📤 Send Files to PC</span> <span class="badge">Wi-Fi Direct</span></h2>
        <div class="drop-box" onclick="document.getElementById('fileInput').click()">
            <div class="drop-icon">📱</div>
            <div class="drop-text" id="selectedLabel">Tap to select photos, videos, or files</div>
        </div>
        <input type="file" id="fileInput" multiple onchange="onFilesSelected(this.files)">
        <button class="btn" id="uploadBtn" disabled onclick="uploadSelectedFiles()">Upload to PC 🚀</button>

        <div class="progress-container" id="progressContainer">
            <div class="progress-bar-bg">
                <div class="progress-bar-fill" id="progressFill"></div>
            </div>
            <div class="progress-status" id="progressStatus">Uploading... 0%</div>
        </div>
    </div>

    <!-- Download from PC -->
    <div class="card">
        <h2><span>📥 Available Files from PC</span> <span class="badge" id="fileCountBadge">0 files</span></h2>
        <div id="downloadsList">
            <div class="empty-msg">No files currently shared by the PC.<br>Files shared on your computer will appear here.</div>
        </div>
    </div>

    <div class="footer">
        DropLAN Local Wi-Fi Mesh • 100% Offline & Private
    </div>

    <script>
        let selectedFiles = [];

        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        function onFilesSelected(files) {
            if (!files || files.length === 0) return;
            selectedFiles = Array.from(files);
            const label = document.getElementById('selectedLabel');
            const btn = document.getElementById('uploadBtn');

            if (selectedFiles.length === 1) {
                label.textContent = selectedFiles[0].name + ' (' + formatBytes(selectedFiles[0].size) + ')';
            } else {
                let totalSize = selectedFiles.reduce((acc, f) => acc + f.size, 0);
                label.textContent = selectedFiles.length + ' files selected (' + formatBytes(totalSize) + ')';
            }
            btn.disabled = false;
        }

        async function uploadSelectedFiles() {
            if (!selectedFiles.length) return;
            const btn = document.getElementById('uploadBtn');
            const progressContainer = document.getElementById('progressContainer');
            const progressFill = document.getElementById('progressFill');
            const progressStatus = document.getElementById('progressStatus');

            btn.disabled = true;
            progressContainer.style.display = 'block';

            for (let i = 0; i < selectedFiles.length; i++) {
                const file = selectedFiles[i];
                progressStatus.textContent = `Uploading ${file.name} (${i + 1}/${selectedFiles.length})...`;

                await new Promise((resolve, reject) => {
                    const xhr = new XMLHttpRequest();
                    xhr.open('POST', '/api/upload?filename=' + encodeURIComponent(file.name));
                    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
                    xhr.setRequestHeader('X-Filename', encodeURIComponent(file.name));

                    xhr.upload.onprogress = (e) => {
                        if (e.lengthComputable) {
                            const pct = Math.round((e.loaded / e.total) * 100);
                            progressFill.style.width = pct + '%';
                            progressStatus.textContent = `Uploading ${file.name} (${i + 1}/${selectedFiles.length}): ${pct}%`;
                        }
                    };

                    xhr.onload = () => {
                        if (xhr.status >= 200 && xhr.status < 300) {
                            resolve(xhr.response);
                        } else {
                            reject(new Error('Upload failed'));
                        }
                    };
                    xhr.onerror = () => reject(new Error('Network error'));
                    xhr.send(file);
                });
            }

            progressStatus.textContent = '✅ All files uploaded to PC successfully!';
            progressFill.style.width = '100%';
            document.getElementById('selectedLabel').textContent = 'Tap to select more files';
            selectedFiles = [];
            setTimeout(() => {
                progressContainer.style.display = 'none';
                progressFill.style.width = '0%';
            }, 3000);
        }

        async function refreshFilesList() {
            try {
                const resp = await fetch('/api/files');
                const files = await resp.json();
                const listEl = document.getElementById('downloadsList');
                const badgeEl = document.getElementById('fileCountBadge');

                badgeEl.textContent = files.length + ' file' + (files.length === 1 ? '' : 's');

                if (!files.length) {
                    listEl.innerHTML = '<div class="empty-msg">No files currently shared by the PC.<br>Files shared on your computer will appear here.</div>';
                    return;
                }

                let html = '';
                files.forEach(f => {
                    html += `
                    <div class="file-item">
                        <div class="file-item-info">
                            <div class="file-name">${f.name}</div>
                            <div class="file-size">${formatBytes(f.size)}</div>
                        </div>
                        <a href="/download/${f.id}" class="btn-dl" download="${f.name}">Download ⬇️</a>
                    </div>`;
                });
                listEl.innerHTML = html;
            } catch (err) {
                console.error('Error fetching files:', err);
            }
        }

        // Poll for newly shared files every 3 seconds
        refreshFilesList();
        setInterval(refreshFilesList, 3000);
    </script>
</body>
</html>
"""


class WebPortalHTTPHandler(BaseHTTPRequestHandler):
    """
    Handles HTTP GET/POST requests from mobile browser clients.
    """

    def log_message(self, format: str, *args) -> None:
        # Suppress noisy standard stdout logs, handled via server signals
        pass

    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # 1. Root: Serve mobile HTML page
        if path == "/" or path == "/index.html":
            html_content = MOBILE_WEB_PAGE_HTML.replace("__PC_NAME__", self.server.node_name)
            encoded = html_content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        # 2. API: List shared files available for download
        if path == "/api/files":
            files_list = []
            for file_id, info in self.server.shared_files.items():
                files_list.append({
                    "id": file_id,
                    "name": info["name"],
                    "size": info["size"],
                })
            payload = json.dumps(files_list).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # 3. Download endpoint: /download/<file_id>
        if path.startswith("/download/"):
            file_id = path.split("/download/")[1]
            file_info = self.server.shared_files.get(file_id)
            if not file_info or not os.path.exists(file_info["path"]):
                self.send_error(404, "File not found or no longer shared.")
                return

            filepath = Path(file_info["path"])
            filename = file_info["name"]
            filesize = filepath.stat().st_size

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            quoted_filename = urllib.parse.quote(filename)
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quoted_filename}")
            self.send_header("Content-Length", str(filesize))
            self.end_headers()

            # Stream file in 64KB blocks
            with open(filepath, "rb") as f:
                while chunk := f.read(64 * 1024):
                    self.wfile.write(chunk)

            client_ip = self.client_address[0]
            self.server.signals.file_downloaded_by_phone.emit(client_ip, filename)
            return

        self.send_error(404, "Endpoint not found.")

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Upload endpoint: /api/upload
        if path == "/api/upload" or path == "/upload":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                self.send_error(400, "Missing or invalid Content-Length.")
                return

            # Extract filename from query parameter or X-Filename header
            query_params = urllib.parse.parse_qs(parsed_url.query)
            raw_filename = ""
            if "filename" in query_params:
                raw_filename = query_params["filename"][0]
            elif "X-Filename" in self.headers:
                raw_filename = urllib.parse.unquote(self.headers["X-Filename"])

            if not raw_filename:
                raw_filename = f"phone_upload_{uuid.uuid4().hex[:6]}.bin"

            # Sanitize and resolve inside designated quarantine directory
            dest_dir = self.server.download_dir
            target_path = resolve_quarantine_path(raw_filename, dest_dir)
            clean_name = target_path.name
            part_path = target_path.parent / f"{clean_name}.part"

            # Stream request body to part file
            bytes_left = content_length
            with open(part_path, "wb") as f:
                while bytes_left > 0:
                    read_len = min(bytes_left, 64 * 1024)
                    chunk = self.rfile.read(read_len)
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_left -= len(chunk)

            # Finalize file
            if part_path.exists():
                part_path.replace(target_path)

            client_ip = self.client_address[0]
            self.server.signals.file_uploaded_from_phone.emit(client_ip, clean_name, content_length)

            resp_payload = json.dumps({"success": True, "filename": clean_name, "size": content_length}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp_payload)))
            self.end_headers()
            self.wfile.write(resp_payload)
            return

        self.send_error(404, "Endpoint not found.")


class WebPortalSignals(QObject):
    server_started = pyqtSignal(str, str, int)  # (url, lan_ip, port)
    server_stopped = pyqtSignal()
    file_uploaded_from_phone = pyqtSignal(str, str, int)  # (client_ip, filename, filesize)
    file_downloaded_by_phone = pyqtSignal(str, str)       # (client_ip, filename)
    log_message = pyqtSignal(str)


class WebPortalServer(QThread):
    """
    QThread running the lightweight HTTPServer for Phone Web Portal sharing.
    """

    def __init__(
        self,
        node_name: str,
        port: int = 8080,
        download_dir: Optional[Path] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.node_name = node_name
        self.requested_port = port
        self.download_dir = (download_dir or DEFAULT_DOWNLOAD_DIR).resolve()
        self.download_dir.mkdir(parents=True, exist_ok=True)
        self.signals = WebPortalSignals()

        self.shared_files: Dict[str, Dict[str, Any]] = {}
        self._httpd: Optional[HTTPServer] = None
        self._running = False
        self.lan_ip = get_local_lan_ip()
        self.bound_port = 0

    def add_shared_file(self, filepath: str | Path) -> str:
        """Add a file to the list of files phones can download."""
        path = Path(filepath).resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        file_id = uuid.uuid4().hex[:8]
        self.shared_files[file_id] = {
            "id": file_id,
            "name": path.name,
            "path": str(path),
            "size": path.stat().st_size,
        }
        return file_id

    def remove_shared_file(self, file_id: str) -> None:
        self.shared_files.pop(file_id, None)

    def clear_shared_files(self) -> None:
        self.shared_files.clear()

    def run(self) -> None:
        self._running = True
        self.lan_ip = get_local_lan_ip()

        # Try binding to requested port or fallback
        bound = False
        for port in [self.requested_port, 8080, 8081, 8082, 0]:
            try:
                self._httpd = HTTPServer(("0.0.0.0", port), WebPortalHTTPHandler)
                self._httpd.node_name = self.node_name
                self._httpd.shared_files = self.shared_files
                self._httpd.download_dir = self.download_dir
                self._httpd.signals = self.signals
                self.bound_port = self._httpd.server_address[1]
                bound = True
                break
            except OSError:
                continue

        if not bound:
            self.signals.log_message.emit("Failed to bind Mobile Web Portal port.")
            return

        portal_url = f"http://{self.lan_ip}:{self.bound_port}"
        self.signals.server_started.emit(portal_url, self.lan_ip, self.bound_port)
        self.signals.log_message.emit(f"Mobile Web Portal active at {portal_url}")

        try:
            self._httpd.serve_forever(poll_interval=0.2)
        except Exception:
            pass

        self.signals.server_stopped.emit()

    def stop(self) -> None:
        self._running = False
        if self._httpd:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            try:
                self._httpd.server_close()
            except Exception:
                pass
            self._httpd = None
        self.wait(1500)
