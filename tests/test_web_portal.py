import json
import os
from pathlib import Path
import tempfile
import time
import urllib.request
from PyQt6.QtCore import QCoreApplication

from network.web_portal import WebPortalServer, get_local_lan_ip


def test_web_portal_lifecycle_and_transfer():
    app = QCoreApplication.instance()
    if app is None:
        app = QCoreApplication([])

    with tempfile.TemporaryDirectory() as tmp_download_dir, tempfile.TemporaryDirectory() as tmp_source_dir:
        # Create a sample file for PC to share with phone
        pc_file = Path(tmp_source_dir) / "pc_document.txt"
        pc_file.write_text("Hello from PC to Smartphone via DropLAN Web Portal!")

        # 1. Start WebPortalServer on port 0 (dynamic port)
        server = WebPortalServer(
            node_name="TestPC",
            port=0,
            download_dir=Path(tmp_download_dir),
        )

        started_box = []
        uploaded_box = []
        downloaded_box = []

        server.signals.server_started.connect(lambda url, ip, port: started_box.append((url, ip, port)))
        server.signals.file_uploaded_from_phone.connect(lambda ip, fn, sz: uploaded_box.append((fn, sz)))
        server.signals.file_downloaded_by_phone.connect(lambda ip, fn: downloaded_box.append(fn))

        server.start()

        # Wait for server to bind port
        for _ in range(50):
            app.processEvents()
            if started_box:
                break
            time.sleep(0.05)

        assert len(started_box) == 1
        portal_url, lan_ip, port = started_box[0]
        base_url = f"http://127.0.0.1:{port}"

        # 2. Add shared file for phone to download
        file_id = server.add_shared_file(pc_file)
        assert file_id in server.shared_files

        # 3. Simulate phone requesting GET / (HTML page)
        req_root = urllib.request.Request(f"{base_url}/")
        with urllib.request.urlopen(req_root) as resp:
            html = resp.read().decode("utf-8")
            assert "DropLAN Mobile" in html
            assert "TestPC" in html

        # 4. Simulate phone requesting GET /api/files (JSON list)
        req_api = urllib.request.Request(f"{base_url}/api/files")
        with urllib.request.urlopen(req_api) as resp:
            files_list = json.loads(resp.read().decode("utf-8"))
            assert len(files_list) == 1
            assert files_list[0]["name"] == "pc_document.txt"

        # 5. Simulate phone downloading file: GET /download/<file_id>
        req_dl = urllib.request.Request(f"{base_url}/download/{file_id}")
        with urllib.request.urlopen(req_dl) as resp:
            dl_content = resp.read().decode("utf-8")
            assert dl_content == "Hello from PC to Smartphone via DropLAN Web Portal!"

        # 6. Simulate phone uploading file: POST /api/upload
        phone_payload = b"Photo data taken on smartphone camera"
        req_up = urllib.request.Request(
            f"{base_url}/api/upload?filename=camera_shot.jpg",
            data=phone_payload,
            headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )
        with urllib.request.urlopen(req_up) as resp:
            up_resp = json.loads(resp.read().decode("utf-8"))
            assert up_resp["success"] is True
            assert up_resp["filename"] == "camera_shot.jpg"

        # Wait for signal events to process
        for _ in range(20):
            app.processEvents()
            time.sleep(0.05)

        # Verify uploaded file on disk
        saved_file = Path(tmp_download_dir) / "camera_shot.jpg"
        assert saved_file.exists()
        assert saved_file.read_bytes() == phone_payload

        # Clean shutdown
        server.stop()
