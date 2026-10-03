"""
DropLAN Security Confirmation Dialog
Interactive modal displaying sender info, file details, and the 6-digit SAS PIN
for mutual verification before accepting any file bytes into local storage.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFrame,
)

from ui.styles import SECURITY_DIALOG_QSS


def format_bytes(num_bytes: int) -> str:
    """Format bytes to human readable string (KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


class SecurityConfirmDialog(QDialog):
    """
    Modal dialog requiring the recipient to inspect the SAS PIN before accepting transfer.
    """

    def __init__(
        self,
        sender_name: str,
        sender_ip: str,
        filename: str,
        filesize: int,
        sas_pin: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("DropLAN — Security Pairing Request")
        self.setModal(True)
        self.setMinimumWidth(460)
        self.setStyleSheet(SECURITY_DIALOG_QSS)

        # Space out PIN digits: e.g. "123456" -> "1 2 3   4 5 6"
        spaced_pin = f"{sas_pin[:3]}  {sas_pin[3:]}"

        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)

        # Header Title
        title_label = QLabel("Incoming File Transfer")
        title_label.setObjectName("DialogTitle")
        subtitle_label = QLabel("A verified LAN device wants to establish an encrypted file stream.")
        subtitle_label.setObjectName("DialogSubtitle")
        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)

        # File & Sender Information Card
        info_card = QFrame()
        info_card.setObjectName("InfoCard")
        info_layout = QVBoxLayout(info_card)
        info_layout.setSpacing(8)

        def add_detail_row(key: str, value: str):
            row = QHBoxLayout()
            lbl_key = QLabel(key)
            lbl_key.setStyleSheet("color: #94a3b8; font-weight: 600; font-size: 12px; min-width: 90px;")
            lbl_val = QLabel(value)
            lbl_val.setStyleSheet("color: #f1f5f9; font-weight: 500; font-size: 12px;")
            lbl_val.setWordWrap(True)
            row.addWidget(lbl_key)
            row.addWidget(lbl_val)
            row.addStretch()
            info_layout.addLayout(row)

        add_detail_row("Sender:", f"{sender_name} ({sender_ip})")
        add_detail_row("File:", filename)
        add_detail_row("Size:", format_bytes(filesize))
        add_detail_row("Destination:", "~/Downloads/DropLAN_Received")
        layout.addWidget(info_card)

        # SAS PIN Verification Box
        pin_box = QFrame()
        pin_box.setObjectName("PinBox")
        pin_layout = QVBoxLayout(pin_box)
        pin_layout.setSpacing(6)
        pin_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        pin_title = QLabel("MUTUAL PAIRING CODE (SAS PIN)")
        pin_title.setStyleSheet("color: #94a3b8; font-size: 10px; font-weight: 700; letter-spacing: 1px;")
        pin_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        pin_label = QLabel(spaced_pin)
        pin_label.setObjectName("PinDigits")
        pin_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        pin_instruction = QLabel("Confirm this 6-digit PIN matches the code displayed on the sender's screen.")
        pin_instruction.setObjectName("PinInstruction")
        pin_instruction.setAlignment(Qt.AlignmentFlag.AlignCenter)
        pin_instruction.setWordWrap(True)

        pin_layout.addWidget(pin_title)
        pin_layout.addWidget(pin_label)
        pin_layout.addWidget(pin_instruction)
        layout.addWidget(pin_box)

        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self.btn_reject = QPushButton("Decline")
        self.btn_reject.setObjectName("DangerButton")
        self.btn_reject.clicked.connect(self.reject)

        self.btn_accept = QPushButton("Accept & Receive File")
        self.btn_accept.setObjectName("SuccessButton")
        self.btn_accept.clicked.connect(self.accept)

        btn_layout.addWidget(self.btn_reject)
        btn_layout.addWidget(self.btn_accept)
        layout.addLayout(btn_layout)
