"""
DropLAN Main Window & UI Controller
Modern PyQt6 Desktop GUI with dark theme, dynamic peer discovery sidebar,
drag-and-drop file target, transfer monitor with speed readout, and IPC wiring.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import socket
import time
from typing import Any, Dict, Optional

from PyQt6.QtCore import QPoint, Qt, QUrl, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QDesktopServices, QDragEnterEvent, QDragMoveEvent, QDropEvent, QIcon, QPainter, QPen
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from network.discovery import PeerDiscoveryWorker
from network.transfer import FileReceiverServer, FileSenderWorker
from security import DEFAULT_DOWNLOAD_DIR
from ui.security_dialog import SecurityConfirmDialog, format_bytes
from ui.styles import DARK_THEME_QSS


class DropZoneWidget(QFrame):
    """
    Interactive drag-and-drop target zone and file selector card.
    """
    file_selected = pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setProperty("dragActive", False)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 24, 20, 24)

        # Drop instruction icon/text
        self.icon_label = QLabel("📁")
        self.icon_label.setStyleSheet("font-size: 32px;")
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.text_label = QLabel("Drag & drop any file here, or click Browse")
        self.text_label.setObjectName("DropZoneText")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.browse_btn = QPushButton("Browse File...")
        self.browse_btn.setObjectName("PrimaryButton")
        self.browse_btn.clicked.connect(self._open_file_dialog)

        layout.addWidget(self.icon_label)
        layout.addWidget(self.text_label)
        layout.addWidget(self.browse_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def _open_file_dialog(self) -> None:
        filepath, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Send via DropLAN",
            "",
            "All Files (*.*)",
        )
        if filepath:
            self.file_selected.emit(filepath)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.setProperty("dragActive", True)
            self.style().unpolish(self)
            self.style().polish(self)

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragLeaveEvent(self, event) -> None:
        self.setProperty("dragActive", False)
        self.style().unpolish(self)
        self.style().polish(self)

    def dropEvent(self, event: QDropEvent) -> None:
        self.setProperty("dragActive", False)
        self.style().unpolish(self)
        self.style().polish(self)

        urls = event.mimeData().urls()
        if urls:
            filepath = urls[0].toLocalFile()
            if filepath and os.path.isfile(filepath):
                self.file_selected.emit(filepath)
                event.acceptProposedAction()


class PeerCardWidget(QWidget):
    """
    Custom widget item rendered inside the Peer List sidebar.
    """

    def __init__(self, name: str, ip: str, port: int, parent=None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(10)

        # Avatar indicator
        avatar = QLabel("💻")
        avatar.setStyleSheet("font-size: 20px; background-color: #242a3b; border-radius: 8px; padding: 4px;")
        layout.addWidget(avatar)

        # Name and Address details
        details_layout = QVBoxLayout()
        details_layout.setSpacing(2)

        name_label = QLabel(name)
        name_label.setStyleSheet("font-weight: 700; color: #f8fafc; font-size: 13px;")

        addr_label = QLabel(f"{ip}:{port}")
        addr_label.setStyleSheet("color: #64748b; font-size: 11px;")

        details_layout.addWidget(name_label)
        details_layout.addWidget(addr_label)
        layout.addLayout(details_layout)
        layout.addStretch()

        # Online badge
        badge = QLabel("● Ready")
        badge.setStyleSheet("color: #00e676; font-size: 11px; font-weight: 600; padding-right: 4px;")
        layout.addWidget(badge)


class MainWindow(QMainWindow):
    """
    Main Application Window coordinating UI and background threads.
    """

    def __init__(
        self,
        node_id: str,
        node_name: str,
        key_pem: bytes,
        cert_pem: bytes,
        cert_der: bytes,
        download_dir: Optional[Path] = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.node_id = node_id
        self.node_name = node_name
        self.key_pem = key_pem
        self.cert_pem = cert_pem
        self.cert_der = cert_der
        self.download_dir = download_dir or DEFAULT_DOWNLOAD_DIR

        self.selected_file_path: Optional[str] = None
        self.selected_peer: Optional[Dict[str, Any]] = None
        self.active_sender: Optional[FileSenderWorker] = None

        self.setWindowTitle("DropLAN — Zero-Trust P2P File Transfer")
        self.resize(1020, 680)
        self.setMinimumSize(850, 560)
        self.setStyleSheet(DARK_THEME_QSS)

        self._build_ui()
        self._init_backend()

    def _build_ui(self) -> None:
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(16, 12, 16, 16)
        main_layout.setSpacing(12)

        # 1. Top Header Bar
        main_layout.addWidget(self._create_header_bar())

        # 2. Main Content Splitter (Sidebar + Transfer Center)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(2)
        splitter.setStyleSheet("QSplitter::handle { background-color: #232736; }")

        splitter.addWidget(self._create_sidebar())
        splitter.addWidget(self._create_main_content())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter, stretch=1)

    def _create_header_bar(self) -> QWidget:
        header = QFrame()
        header.setObjectName("HeaderBar")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(14)

        # Logo and Title
        title_box = QHBoxLayout()
        title_box.setSpacing(8)
        logo_icon = QLabel("⚡")
        logo_icon.setStyleSheet("font-size: 20px;")
        app_title = QLabel("DropLAN")
        app_title.setObjectName("AppTitle")
        app_badge = QLabel("TLS 1.3 MESH")
        app_badge.setObjectName("AppBadge")

        title_box.addWidget(logo_icon)
        title_box.addWidget(app_title)
        title_box.addWidget(app_badge)
        layout.addLayout(title_box)

        layout.addStretch()

        # Node Info Pill
        self.node_info_label = QLabel(f"Node: {self.node_name} | Initializing...")
        self.node_info_label.setObjectName("NodePill")
        layout.addWidget(self.node_info_label)

        # Open Downloads Button
        open_downloads_btn = QPushButton("📁 Downloads")
        open_downloads_btn.setToolTip("Open received files directory")
        open_downloads_btn.clicked.connect(self._open_downloads_folder)
        layout.addWidget(open_downloads_btn)

        return header

    def _create_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("SidebarFrame")
        sidebar.setMinimumWidth(280)
        sidebar.setMaximumWidth(360)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(12, 14, 12, 14)
        layout.setSpacing(10)

        # Header row
        hdr_layout = QHBoxLayout()
        title = QLabel("Discovered Peers")
        title.setObjectName("SectionTitle")
        self.peer_count_badge = QLabel("0 online")
        self.peer_count_badge.setStyleSheet(
            "background-color: #1e293b; color: #94a3b8; font-size: 11px; "
            "padding: 2px 6px; border-radius: 6px; font-weight: 600;"
        )
        hdr_layout.addWidget(title)
        hdr_layout.addStretch()
        hdr_layout.addWidget(self.peer_count_badge)
        layout.addLayout(hdr_layout)

        # Peer List
        self.peer_list_widget = QListWidget()
        self.peer_list_widget.setObjectName("PeerList")
        self.peer_list_widget.itemSelectionChanged.connect(self._on_peer_selection_changed)
        layout.addWidget(self.peer_list_widget, stretch=1)

        # Placeholder label when list is empty
        self.empty_peers_label = QLabel("Scanning LAN for peers...\nEnsure DropLAN is running on other devices.")
        self.empty_peers_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_peers_label.setStyleSheet("color: #64748b; font-size: 11px; padding: 20px 8px; line-height: 1.4;")
        layout.addWidget(self.empty_peers_label)

        return sidebar

    def _create_main_content(self) -> QWidget:
        panel = QFrame()
        panel.setObjectName("MainContentFrame")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # Section: File Drop & Select
        section_title = QLabel("Send File")
        section_title.setObjectName("SectionTitle")
        layout.addWidget(section_title)

        self.drop_zone = DropZoneWidget()
        self.drop_zone.file_selected.connect(self._on_file_selected)
        layout.addWidget(self.drop_zone)

        # Selected File Info & Actions Card
        self.file_card = QFrame()
        self.file_card.setObjectName("SelectedFileCard")
        file_card_layout = QHBoxLayout(self.file_card)
        file_card_layout.setContentsMargins(12, 10, 12, 10)
        file_card_layout.setSpacing(12)

        file_icon = QLabel("📄")
        file_icon.setStyleSheet("font-size: 22px;")
        file_card_layout.addWidget(file_icon)

        file_details = QVBoxLayout()
        file_details.setSpacing(2)
        self.file_name_label = QLabel("No file selected")
        self.file_name_label.setStyleSheet("font-weight: 700; color: #f8fafc;")
        self.file_meta_label = QLabel("Select a file above and choose a recipient from the sidebar")
        self.file_meta_label.setStyleSheet("color: #94a3b8; font-size: 11px;")
        file_details.addWidget(self.file_name_label)
        file_details.addWidget(self.file_meta_label)
        file_card_layout.addLayout(file_details)
        file_card_layout.addStretch()

        self.btn_clear_file = QPushButton("Clear")
        self.btn_clear_file.clicked.connect(self._clear_selected_file)
        self.btn_clear_file.setEnabled(False)

        self.btn_send_file = QPushButton("Send File 🚀")
        self.btn_send_file.setObjectName("PrimaryButton")
        self.btn_send_file.setEnabled(False)
        self.btn_send_file.clicked.connect(self._send_file_to_selected_peer)

        file_card_layout.addWidget(self.btn_clear_file)
        file_card_layout.addWidget(self.btn_send_file)
        layout.addWidget(self.file_card)

        # Section: Active Transfer Monitor
        monitor_hdr = QHBoxLayout()
        monitor_title = QLabel("Transfer Monitor")
        monitor_title.setObjectName("SectionTitle")

        self.transfer_state_badge = QLabel("Idle")
        self.transfer_state_badge.setStyleSheet(
            "background-color: #1e293b; color: #94a3b8; font-size: 11px; "
            "padding: 3px 8px; border-radius: 6px; font-weight: 600;"
        )
        monitor_hdr.addWidget(monitor_title)
        monitor_hdr.addStretch()
        monitor_hdr.addWidget(self.transfer_state_badge)
        layout.addLayout(monitor_hdr)

        # Security PIN Banner (Shown during active pairing)
        self.pin_banner = QFrame()
        self.pin_banner.setStyleSheet(
            "background-color: #162438; border: 1px solid #00d2ff88; border-radius: 8px; padding: 8px 14px;"
        )
        pin_banner_layout = QHBoxLayout(self.pin_banner)
        pin_banner_layout.setContentsMargins(6, 4, 6, 4)
        self.pin_banner_text = QLabel("Pairing PIN: [ 000 000 ] — Waiting for recipient approval...")
        self.pin_banner_text.setStyleSheet("color: #00d2ff; font-weight: 700; font-size: 13px;")
        pin_banner_layout.addWidget(self.pin_banner_text)
        self.pin_banner.setVisible(False)
        layout.addWidget(self.pin_banner)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)

        # Metrics row: Speed & Transferred bytes
        metrics_layout = QHBoxLayout()
        self.speed_label = QLabel("Speed: 0.0 MB/s")
        self.speed_label.setStyleSheet("color: #00d2ff; font-weight: 600; font-size: 12px;")
        self.progress_detail_label = QLabel("0 B / 0 B (0%)")
        self.progress_detail_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        metrics_layout.addWidget(self.speed_label)
        metrics_layout.addStretch()
        metrics_layout.addWidget(self.progress_detail_label)
        layout.addLayout(metrics_layout)

        # Real-time Activity Log
        log_hdr = QHBoxLayout()
        log_title = QLabel("Security & Transfer Activity Log")
        log_title.setStyleSheet("font-size: 12px; font-weight: 600; color: #94a3b8;")
        btn_clear_log = QPushButton("Clear Log")
        btn_clear_log.setStyleSheet("padding: 2px 8px; font-size: 10px; min-height: 14px;")
        btn_clear_log.clicked.connect(lambda: self.activity_log.clear())
        log_hdr.addWidget(log_title)
        log_hdr.addStretch()
        log_hdr.addWidget(btn_clear_log)
        layout.addLayout(log_hdr)

        self.activity_log = QTextEdit()
        self.activity_log.setObjectName("ActivityLog")
        self.activity_log.setReadOnly(True)
        layout.addWidget(self.activity_log, stretch=1)

        return panel

    def _init_backend(self) -> None:
        """Initialize background network threads for TLS Receiver and UDP Discovery."""
        self._log("SYSTEM", f"Starting DropLAN node '{self.node_name}' (ID: {self.node_id})")

        # 1. Start TLS Receiver Server (TCP)
        self.receiver_server = FileReceiverServer(
            node_id=self.node_id,
            node_name=self.node_name,
            key_pem=self.key_pem,
            cert_pem=self.cert_pem,
            cert_der=self.cert_der,
            port=0,
            download_dir=self.download_dir,
        )

        self.receiver_server.signals.server_ready.connect(self._on_server_ready)
        self.receiver_server.signals.transfer_requested.connect(self._on_transfer_requested)
        self.receiver_server.signals.transfer_started.connect(self._on_transfer_started)
        self.receiver_server.signals.transfer_progress.connect(self._on_transfer_progress)
        self.receiver_server.signals.transfer_completed.connect(self._on_receiver_completed)
        self.receiver_server.signals.transfer_rejected.connect(self._on_transfer_rejected)
        self.receiver_server.signals.transfer_failed.connect(self._on_transfer_failed)
        self.receiver_server.signals.status_message.connect(lambda m: self._log("SERVER", m))

        self.receiver_server.start()

    @pyqtSlot(int)
    def _on_server_ready(self, bound_port: int) -> None:
        """Called once TCP listener is bound and ready."""
        self.node_info_label.setText(f"Node: {self.node_name} | TCP Port: {bound_port} | ID: {self.node_id[:8]}")
        self._log("SECURITY", f"TLS 1.3 Ephemeral Listener active on TCP port {bound_port}")

        # 2. Start UDP Discovery Worker broadcasting our bound TCP port
        self.discovery_worker = PeerDiscoveryWorker(
            node_id=self.node_id,
            name=self.node_name,
            tcp_port=bound_port,
        )

        self.discovery_worker.peer_discovered.connect(self._on_peer_discovered)
        self.discovery_worker.peer_updated.connect(self._on_peer_updated)
        self.discovery_worker.peer_lost.connect(self._on_peer_lost)
        self.discovery_worker.status_message.connect(lambda m: self._log("DISCOVERY", m))

        self.discovery_worker.start()

    # --- Discovery Slots ---

    @pyqtSlot(dict)
    def _on_peer_discovered(self, peer: Dict[str, Any]) -> None:
        item = QListWidgetItem()
        card = PeerCardWidget(peer["name"], peer["ip"], peer["port"])
        item.setSizeHint(card.sizeHint())
        item.setData(Qt.ItemDataRole.UserRole, peer)

        self.peer_list_widget.addItem(item)
        self.peer_list_widget.setItemWidget(item, card)
        self._update_peer_count()
        self._log("DISCOVERY", f"Peer discovered: {peer['name']} ({peer['ip']}:{peer['port']})")

    @pyqtSlot(dict)
    def _on_peer_updated(self, peer: Dict[str, Any]) -> None:
        for i in range(self.peer_list_widget.count()):
            item = self.peer_list_widget.item(i)
            data = item.data(Qt.ItemDataRole.UserRole)
            if data and data.get("node_id") == peer["node_id"]:
                item.setData(Qt.ItemDataRole.UserRole, peer)
                # If currently selected, keep selection state
                break

    @pyqtSlot(str)
    def _on_peer_lost(self, node_id: str) -> None:
        for i in range(self.peer_list_widget.count()):
            item = self.peer_list_widget.item(i)
            data = item.data(Qt.ItemDataRole.UserRole)
            if data and data.get("node_id") == node_id:
                peer_name = data.get("name", "Unknown")
                self.peer_list_widget.takeItem(i)
                self._update_peer_count()
                self._log("DISCOVERY", f"Peer disconnected/pruned: {peer_name}")
                if self.selected_peer and self.selected_peer.get("node_id") == node_id:
                    self.selected_peer = None
                    self._update_send_button_state()
                break

    def _update_peer_count(self) -> None:
        count = self.peer_list_widget.count()
        self.peer_count_badge.setText(f"{count} online")
        self.empty_peers_label.setVisible(count == 0)

    def _on_peer_selection_changed(self) -> None:
        selected_items = self.peer_list_widget.selectedItems()
        if selected_items:
            self.selected_peer = selected_items[0].data(Qt.ItemDataRole.UserRole)
            if self.selected_peer:
                self._log("PEER", f"Selected target peer: {self.selected_peer['name']} ({self.selected_peer['ip']})")
        else:
            self.selected_peer = None
        self._update_send_button_state()

    # --- File Selection Slots ---

    @pyqtSlot(str)
    def _on_file_selected(self, filepath: str) -> None:
        if not os.path.exists(filepath) or not os.path.isfile(filepath):
            return

        self.selected_file_path = filepath
        fname = os.path.basename(filepath)
        fsize = os.path.getsize(filepath)

        self.file_name_label.setText(fname)
        self.file_meta_label.setText(f"Size: {format_bytes(fsize)} | Path: {filepath}")
        self.btn_clear_file.setEnabled(True)
        self._update_send_button_state()
        self._log("FILE", f"Loaded file for transfer: {fname} ({format_bytes(fsize)})")

    def _clear_selected_file(self) -> None:
        self.selected_file_path = None
        self.file_name_label.setText("No file selected")
        self.file_meta_label.setText("Select a file above and choose a recipient from the sidebar")
        self.btn_clear_file.setEnabled(False)
        self._update_send_button_state()

    def _update_send_button_state(self) -> None:
        ready = bool(self.selected_file_path and self.selected_peer)
        self.btn_send_file.setEnabled(ready)
        if ready and self.selected_peer:
            self.btn_send_file.setText(f"Send to {self.selected_peer['name']} 🚀")
        else:
            self.btn_send_file.setText("Send File 🚀")

    # --- Sending Flow ---

    def _send_file_to_selected_peer(self) -> None:
        if not self.selected_file_path or not self.selected_peer:
            return

        if self.active_sender and self.active_sender.isRunning():
            self._log("WARNING", "A file transfer is already in progress.")
            return

        peer = self.selected_peer
        filepath = self.selected_file_path

        self._set_transfer_state("Connecting...", "#3b82f6")
        self.progress_bar.setValue(0)
        self.btn_send_file.setEnabled(False)

        self.active_sender = FileSenderWorker(
            peer_ip=peer["ip"],
            peer_port=peer["port"],
            peer_name=peer["name"],
            filepath=filepath,
            local_node_id=self.node_id,
            local_name=self.node_name,
            key_pem=self.key_pem,
            cert_pem=self.cert_pem,
            cert_der=self.cert_der,
        )

        self.active_sender.status_update.connect(lambda s: self._log("TRANSFER", s))
        self.active_sender.pin_available.connect(self._on_sender_pin_available)
        self.active_sender.waiting_peer.connect(self._on_sender_waiting_peer)
        self.active_sender.transfer_started.connect(self._on_sender_transfer_started)
        self.active_sender.transfer_progress.connect(self._on_sender_progress)
        self.active_sender.transfer_completed.connect(self._on_sender_completed)
        self.active_sender.transfer_rejected.connect(self._on_sender_rejected)
        self.active_sender.transfer_failed.connect(self._on_sender_failed)

        self.active_sender.start()

    @pyqtSlot(str, str, str, int)
    def _on_sender_pin_available(self, pin: str, peer_name: str, filename: str, filesize: int) -> None:
        spaced_pin = f"{pin[:3]} {pin[3:]}"
        self.pin_banner_text.setText(f"PAIRING PIN: [ {spaced_pin} ] — Waiting for {peer_name} to verify...")
        self.pin_banner.setVisible(True)
        self._set_transfer_state("Verifying PIN...", "#ffb300")
        self._log("SECURITY", f"Mutual TLS Handshake complete. Verification PIN: {pin}")

    @pyqtSlot(str)
    def _on_sender_waiting_peer(self, msg: str) -> None:
        self._log("TRANSFER", msg)

    @pyqtSlot(str, int)
    def _on_sender_transfer_started(self, filename: str, filesize: int) -> None:
        self.pin_banner.setVisible(False)
        self._set_transfer_state("Sending...", "#00d2ff")
        self._log("TRANSFER", f"Transfer approved by recipient! Streaming {filename} ({format_bytes(filesize)})...")

    @pyqtSlot(int, int, float)
    def _on_sender_progress(self, sent: int, total: int, speed: float) -> None:
        pct = int((sent / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.speed_label.setText(f"Speed: {speed:.1f} MB/s")
        self.progress_detail_label.setText(f"{format_bytes(sent)} / {format_bytes(total)} ({pct}%)")

    @pyqtSlot(str)
    def _on_sender_completed(self, filename: str) -> None:
        self.pin_banner.setVisible(False)
        self._set_transfer_state("Completed", "#00e676")
        self.progress_bar.setValue(100)
        self.speed_label.setText("Speed: 0.0 MB/s")
        self._log("SUCCESS", f"File '{filename}' transferred and verified successfully by recipient!")
        self._update_send_button_state()

    @pyqtSlot(str)
    def _on_sender_rejected(self, reason: str) -> None:
        self.pin_banner.setVisible(False)
        self._set_transfer_state("Rejected", "#ef4444")
        self.speed_label.setText("Speed: 0.0 MB/s")
        self._log("SECURITY", f"Transfer was rejected: {reason}")
        self._update_send_button_state()

    @pyqtSlot(str)
    def _on_sender_failed(self, error: str) -> None:
        self.pin_banner.setVisible(False)
        self._set_transfer_state("Failed", "#ef4444")
        self.speed_label.setText("Speed: 0.0 MB/s")
        self._log("ERROR", f"Transfer error: {error}")
        self._update_send_button_state()

    # --- Receiving Flow (Incoming Transfers) ---

    @pyqtSlot(str, str, str, str, int, str)
    def _on_transfer_requested(
        self,
        transfer_id: str,
        sender_name: str,
        sender_ip: str,
        filename: str,
        filesize: int,
        sas_pin: str,
    ) -> None:
        self._log("SECURITY", f"Incoming transfer request from {sender_name} ({sender_ip}) for '{filename}'")
        self._log("SECURITY", f"Derived SAS PIN: {sas_pin}")

        # Show Security Pairing Modal Dialog
        dialog = SecurityConfirmDialog(
            sender_name=sender_name,
            sender_ip=sender_ip,
            filename=filename,
            filesize=filesize,
            sas_pin=sas_pin,
            parent=self,
        )

        accepted = (dialog.exec() == SecurityConfirmDialog.DialogCode.Accepted)

        if accepted:
            self._log("SECURITY", f"User approved transfer from {sender_name}. Starting download...")
            self._set_transfer_state("Receiving...", "#00d2ff")
        else:
            self._log("SECURITY", f"User declined transfer request from {sender_name}.")
            self._set_transfer_state("Declined", "#ef4444")

        self.receiver_server.respond_to_transfer(transfer_id, accepted)

    @pyqtSlot(str, str, int)
    def _on_transfer_started(self, transfer_id: str, filename: str, filesize: int) -> None:
        self._set_transfer_state("Receiving...", "#00d2ff")
        self.progress_bar.setValue(0)
        self._log("TRANSFER", f"Receiving file stream: '{filename}' ({format_bytes(filesize)})")

    @pyqtSlot(str, int, int, float)
    def _on_transfer_progress(self, transfer_id: str, received: int, total: int, speed: float) -> None:
        pct = int((received / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(pct)
        self.speed_label.setText(f"Speed: {speed:.1f} MB/s")
        self.progress_detail_label.setText(f"{format_bytes(received)} / {format_bytes(total)} ({pct}%)")

    @pyqtSlot(str, str, str)
    def _on_receiver_completed(self, transfer_id: str, filename: str, filepath: str) -> None:
        self._set_transfer_state("Received", "#00e676")
        self.progress_bar.setValue(100)
        self.speed_label.setText("Speed: 0.0 MB/s")
        self._log("SUCCESS", f"File '{filename}' received, SHA-256 verified, saved to {filepath}")

    @pyqtSlot(str, str)
    def _on_transfer_rejected(self, transfer_id: str, reason: str) -> None:
        self._set_transfer_state("Rejected", "#ef4444")
        self._log("TRANSFER", f"Transfer {transfer_id} rejected: {reason}")

    @pyqtSlot(str, str)
    def _on_transfer_failed(self, transfer_id: str, error_message: str) -> None:
        self._set_transfer_state("Failed", "#ef4444")
        self.speed_label.setText("Speed: 0.0 MB/s")
        self._log("ERROR", f"Transfer failed: {error_message}")

    # --- Utility Helpers ---

    def _set_transfer_state(self, text: str, color_hex: str) -> None:
        self.transfer_state_badge.setText(text)
        self.transfer_state_badge.setStyleSheet(
            f"background-color: {color_hex}22; color: {color_hex}; "
            f"border: 1px solid {color_hex}66; font-size: 11px; padding: 3px 8px; border-radius: 6px; font-weight: 700;"
        )

    def _open_downloads_folder(self) -> None:
        dest_dir = self.download_dir.resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(dest_dir)))

    def _log(self, tag: str, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        color_map = {
            "SYSTEM": "#94a3b8",
            "SECURITY": "#00d2ff",
            "DISCOVERY": "#a78bfa",
            "TRANSFER": "#38bdf8",
            "SUCCESS": "#00e676",
            "WARNING": "#fbbf24",
            "ERROR": "#f87171",
            "FILE": "#e2e8f0",
            "PEER": "#34d399",
            "SERVER": "#818cf8",
        }
        color = color_map.get(tag, "#e2e8f0")
        formatted = f"<span style='color: #64748b;'>[{timestamp}]</span> <b style='color: {color};'>[{tag}]</b> {message}"
        self.activity_log.append(formatted)

    def closeEvent(self, event) -> None:
        """Application shutdown lifecycle hook."""
        self._log("SYSTEM", "Shutting down DropLAN services...")
        if hasattr(self, "discovery_worker") and self.discovery_worker:
            self.discovery_worker.stop()
        if hasattr(self, "receiver_server") and self.receiver_server:
            self.receiver_server.stop()
        if self.active_sender and self.active_sender.isRunning():
            self.active_sender.cancel()
            self.active_sender.wait(1000)
        event.accept()
