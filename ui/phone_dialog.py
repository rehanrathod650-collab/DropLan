"""
DropLAN Mobile Phone Sharing Dialog
Presents a QR code and local network link to transfer files with any smartphone.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QColor, QDesktopServices, QImage, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)
import qrcode

from network.web_portal import WebPortalServer
from ui.security_dialog import format_bytes


def generate_qr_pixmap(data: str, target_size: int = 220) -> QPixmap:
    """Generate crisp pixel-perfect QPixmap from QR code matrix."""
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    dim = len(matrix)

    img = QImage(dim, dim, QImage.Format.Format_RGB32)
    for y in range(dim):
        for x in range(dim):
            color = QColor("#0f1117") if matrix[y][x] else QColor("#ffffff")
            img.setPixelColor(x, y, color)

    return QPixmap.fromImage(img).scaled(
        target_size,
        target_size,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.FastTransformation,
    )


class MobileShareDialog(QDialog):
    """
    Modal dialog displaying the Phone Web Portal QR code and active transfer management.
    """

    def __init__(self, portal_server: WebPortalServer, parent=None) -> None:
        super().__init__(parent)
        self.portal = portal_server
        self.setWindowTitle("DropLAN — Share with Phone (Android & iPhone)")
        self.setMinimumWidth(500)
        self.setStyleSheet("""
            QDialog {
                background-color: #12151e;
                color: #f1f5f9;
            }
            QLabel#Title {
                font-size: 17px;
                font-weight: 700;
                color: #ffffff;
            }
            QLabel#Subtitle {
                font-size: 12px;
                color: #94a3b8;
            }
            QFrame#QRCard {
                background-color: #ffffff;
                border-radius: 14px;
                padding: 10px;
            }
            QLineEdit#UrlInput {
                background-color: #181d2a;
                border: 1px solid #283045;
                border-radius: 8px;
                padding: 8px 12px;
                color: #00d2ff;
                font-weight: 700;
                font-size: 13px;
            }
            QListWidget#SharedList {
                background-color: #181d2a;
                border: 1px solid #283045;
                border-radius: 8px;
                padding: 4px;
                min-height: 80px;
                max-height: 120px;
            }
            QListWidget#SharedList::item {
                background-color: #21283a;
                border-radius: 6px;
                padding: 6px 10px;
                margin: 2px;
                color: #f1f5f9;
            }
        """)

        portal_url = f"http://{self.portal.lan_ip}:{self.portal.bound_port}"

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(22, 20, 22, 20)

        # Header
        title = QLabel("📱 Share with Any Smartphone")
        title.setObjectName("Title")
        subtitle = QLabel("Connect phone to the same Wi-Fi, then scan this QR code or open the link.")
        subtitle.setObjectName("Subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)

        # Centered QR Code
        qr_container = QHBoxLayout()
        qr_container.setAlignment(Qt.AlignmentFlag.AlignCenter)

        qr_card = QFrame()
        qr_card.setObjectName("QRCard")
        qr_card_layout = QVBoxLayout(qr_card)
        qr_card_layout.setContentsMargins(8, 8, 8, 8)

        self.qr_label = QLabel()
        self.qr_label.setPixmap(generate_qr_pixmap(portal_url, target_size=200))
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        qr_card_layout.addWidget(self.qr_label)
        qr_container.addWidget(qr_card)
        layout.addLayout(qr_container)

        # URL and Copy Button
        url_layout = QHBoxLayout()
        self.url_input = QLineEdit(portal_url)
        self.url_input.setObjectName("UrlInput")
        self.url_input.setReadOnly(True)

        self.btn_copy = QPushButton("Copy Link")
        self.btn_copy.clicked.connect(self._copy_link)

        self.btn_open = QPushButton("Open in Browser")
        self.btn_open.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(portal_url)))

        url_layout.addWidget(self.url_input)
        url_layout.addWidget(self.btn_copy)
        url_layout.addWidget(self.btn_open)
        layout.addLayout(url_layout)

        # Shared Files Section (Files for phone to download)
        files_hdr = QHBoxLayout()
        files_title = QLabel("Files Shared for Phone to Download:")
        files_title.setStyleSheet("font-weight: 600; font-size: 12px; color: #94a3b8;")
        btn_add_file = QPushButton("+ Add File...")
        btn_add_file.setStyleSheet("padding: 3px 10px; font-size: 11px;")
        btn_add_file.clicked.connect(self._add_file_to_share)
        files_hdr.addWidget(files_title)
        files_hdr.addStretch()
        files_hdr.addWidget(btn_add_file)
        layout.addLayout(files_hdr)

        self.shared_list = QListWidget()
        self.shared_list.setObjectName("SharedList")
        layout.addWidget(self.shared_list)
        self._refresh_shared_list()

        # Status and Close Button
        bottom_layout = QHBoxLayout()
        status_label = QLabel("🟢 Portal Active on Local Wi-Fi")
        status_label.setStyleSheet("color: #00e676; font-size: 11px; font-weight: 600;")
        btn_done = QPushButton("Done / Close")
        btn_done.setObjectName("PrimaryButton")
        btn_done.clicked.connect(self.accept)

        bottom_layout.addWidget(status_label)
        bottom_layout.addStretch()
        bottom_layout.addWidget(btn_done)
        layout.addLayout(bottom_layout)

    def _copy_link(self) -> None:
        QApplication.clipboard().setText(self.url_input.text())
        self.btn_copy.setText("Copied! ✓")

    def _add_file_to_share(self) -> None:
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Share with Phone",
            "",
            "All Files (*.*)",
        )
        if filepath:
            self.portal.add_shared_file(filepath)
            self._refresh_shared_list()

    def _refresh_shared_list(self) -> None:
        self.shared_list.clear()
        files = self.portal.shared_files.values()
        if not files:
            item = QListWidgetItem("No files shared yet. Click '+ Add File...' to make a file downloadable on your phone.")
            item.setFlags(Qt.ItemFlag.NoItemFlags)
            self.shared_list.addItem(item)
            return

        for f in files:
            text = f"📄 {f['name']} ({format_bytes(f['size'])})"
            self.shared_list.addItem(QListWidgetItem(text))
