"""
DropLAN UI Stylesheet & Design System
Modern Dark Theme with vibrant accents, glassmorphic touches, and clean typography.
"""

DARK_THEME_QSS = """
/* Global Window & Fonts */
QWidget {
    background-color: #0f1117;
    color: #e2e8f0;
    font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif;
    font-size: 13px;
    selection-background-color: #00d2ff;
    selection-color: #0f1117;
}

/* Main Window */
QMainWindow {
    background-color: #0f1117;
}

/* Header & Status Bar */
#HeaderBar {
    background-color: #161922;
    border-bottom: 1px solid #232736;
    padding: 10px 16px;
}

#AppTitle {
    font-size: 18px;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: 0.5px;
}

#AppBadge {
    background-color: #1e293b;
    color: #00d2ff;
    border: 1px solid #00d2ff44;
    border-radius: 6px;
    padding: 3px 8px;
    font-size: 11px;
    font-weight: 600;
}

#NodePill {
    background-color: #1a1e2b;
    border: 1px solid #2a3144;
    border-radius: 8px;
    padding: 5px 12px;
    font-size: 11px;
    color: #94a3b8;
}

/* Panels & Cards */
QFrame#SidebarFrame, QFrame#MainContentFrame {
    background-color: #141720;
    border: 1px solid #232736;
    border-radius: 12px;
}

#SectionTitle {
    font-size: 14px;
    font-weight: 600;
    color: #f8fafc;
    margin-bottom: 6px;
}

/* Peer List / Sidebar */
QListWidget#PeerList {
    background-color: transparent;
    border: none;
    outline: none;
    padding: 4px;
}

QListWidget#PeerList::item {
    background-color: #1a1e2b;
    border: 1px solid #272d3f;
    border-radius: 10px;
    margin: 4px 2px;
    padding: 10px;
    color: #f1f5f9;
}

QListWidget#PeerList::item:hover {
    background-color: #212738;
    border: 1px solid #3b82f6;
}

QListWidget#PeerList::item:selected {
    background-color: #1e2d4a;
    border: 1.5px solid #00d2ff;
}

/* Drop Zone Area */
QFrame#DropZone {
    background-color: #161924;
    border: 2px dashed #2d3748;
    border-radius: 14px;
    min-height: 160px;
}

QFrame#DropZone:hover {
    background-color: #191e2c;
    border-color: #00d2ff;
}

QFrame#DropZone[dragActive="true"] {
    background-color: #1b283d;
    border-color: #00e676;
}

#DropZoneText {
    color: #94a3b8;
    font-size: 13px;
    font-weight: 500;
}

#SelectedFileCard {
    background-color: #1b202e;
    border: 1px solid #2e374d;
    border-radius: 10px;
    padding: 10px 14px;
}

/* Buttons */
QPushButton {
    background-color: #222736;
    color: #f8fafc;
    border: 1px solid #32394d;
    border-radius: 8px;
    padding: 7px 16px;
    font-weight: 600;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #2b3245;
    border-color: #4b556f;
}

QPushButton:pressed {
    background-color: #1a1d29;
}

QPushButton:disabled {
    background-color: #171923;
    color: #475569;
    border-color: #232736;
}

QPushButton#PrimaryButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00b4db, stop:1 #0083b0);
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 8px 20px;
    font-weight: 700;
}

QPushButton#PrimaryButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00c6ed, stop:1 #0099cc);
}

QPushButton#PrimaryButton:disabled {
    background: #1e293b;
    color: #475569;
    border: 1px solid #334155;
}

QPushButton#DangerButton {
    background-color: #ef444422;
    color: #f87171;
    border: 1px solid #ef444455;
    border-radius: 8px;
    padding: 7px 16px;
    font-weight: 600;
}

QPushButton#DangerButton:hover {
    background-color: #ef444433;
    border-color: #ef444488;
}

QPushButton#SuccessButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10b981);
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 8px 20px;
    font-weight: 700;
}

QPushButton#SuccessButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #10b981, stop:1 #34d399);
}

/* Progress Bar */
QProgressBar {
    background-color: #171a24;
    border: 1px solid #282f42;
    border-radius: 8px;
    text-align: center;
    color: #ffffff;
    font-weight: 600;
    font-size: 11px;
    min-height: 18px;
    max-height: 18px;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #00d2ff, stop:1 #3a7bd5);
    border-radius: 7px;
}

/* Activity Log */
QTextEdit#ActivityLog {
    background-color: #0c0e14;
    border: 1px solid #1f2433;
    border-radius: 8px;
    padding: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 11px;
    color: #cbd5e1;
    line-height: 1.4;
}

/* Scrollbars */
QScrollBar:vertical {
    background-color: #10121a;
    width: 8px;
    margin: 0px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background-color: #272d3f;
    min-height: 24px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #3b445f;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Tooltips */
QToolTip {
    background-color: #1e2230;
    color: #f8fafc;
    border: 1px solid #374151;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
}
"""

SECURITY_DIALOG_QSS = """
QDialog {
    background-color: #12151e;
    color: #f1f5f9;
}

#DialogTitle {
    font-size: 17px;
    font-weight: 700;
    color: #ffffff;
}

#DialogSubtitle {
    font-size: 12px;
    color: #94a3b8;
}

#InfoCard {
    background-color: #181c28;
    border: 1px solid #283045;
    border-radius: 10px;
    padding: 14px;
}

#PinBox {
    background-color: #1a2236;
    border: 2px solid #00d2ff;
    border-radius: 12px;
    padding: 16px;
}

#PinDigits {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 32px;
    font-weight: 800;
    color: #00d2ff;
    letter-spacing: 12px;
}

#PinInstruction {
    font-size: 11px;
    color: #94a3b8;
}
"""
