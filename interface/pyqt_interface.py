import sys
import csv
from datetime import datetime
from collections import defaultdict, deque
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QListWidget, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QComboBox, QMessageBox, QFileDialog,
    QHeaderView, QSplitter, QGroupBox, QFormLayout, QDialog,
    QDialogButtonBox, QLineEdit, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg
from matplotlib.figure import Figure

from models.segment import NetworkSegment
from models.node import NetworkNode
from models.traffic import TrafficFlow
from collectors.interface_scanner import InterfaceScanner
from collectors.scapy_collector import ScapyCollector
from tools.analyzer import NetworkAnalyzer
from tools.storage import DataStore
from features import FeatureExtractor
from ai import AnomalyDetector, AlertEngine
import ipaddress


class HackerPalette:
    BACKGROUND = "#0a0e12"
    PANEL = "#11161d"
    PANEL_ALT = "#161c24"
    BORDER = "#1e2730"
    PRIMARY = "#00ff9d"
    PRIMARY_DIM = "#00cc7d"
    SECONDARY = "#00b8ff"
    WARNING = "#ffb800"
    DANGER = "#ff3366"
    TEXT = "#e6f1ff"
    TEXT_DIM = "#8b9bb4"
    SUCCESS = "#00ff9d"
    LOCAL_BG = "#0d3320"
    OUTBOUND_BG = "#332b0d"
    INBOUND_BG = "#0d2833"
    EXTERNAL_BG = "#330d1a"
    LOCAL_TEXT = "#00ff9d"
    OUTBOUND_TEXT = "#ffb800"
    INBOUND_TEXT = "#00b8ff"
    EXTERNAL_TEXT = "#ff3366"
    FONT_MAIN = "Segoe UI"
    FONT_MONO = "Consolas, 'Courier New', monospace"
    RADIUS = 8


class StatCard(QFrame):
    def __init__(self, title, value, color=HackerPalette.PRIMARY, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(f"""
            StatCard {{
                background: {HackerPalette.PANEL};
                border: 1px solid {HackerPalette.BORDER};
                border-radius: {HackerPalette.RADIUS}px;
                padding: 12px;
            }}
            StatCard:hover {{
                border: 1px solid {color};
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(12, 12, 12, 12)

        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {HackerPalette.TEXT_DIM}; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;")
        layout.addWidget(title_label)

        value_label = QLabel(str(value))
        value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: 700; font-family: {HackerPalette.FONT_MONO};")
        layout.addWidget(value_label)

        self.value_label = value_label

    def update_value(self, value):
        self.value_label.setText(str(value))


class TerminalLog(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet(f"""
            QTextEdit {{
                background: {HackerPalette.BACKGROUND};
                color: {HackerPalette.PRIMARY};
                font-family: {HackerPalette.FONT_MONO};
                font-size: 11px;
                border: 1px solid {HackerPalette.BORDER};
                border-radius: {HackerPalette.RADIUS}px;
                padding: 8px;
            }}
        """)

    def append_log(self, text, color=None):
        if color is None:
            color = HackerPalette.PRIMARY
        self.setTextColor(QColor(color))
        self.append(f">> {text}")
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

    def append_error(self, text):
        self.append_log(text, HackerPalette.DANGER)

    def append_warning(self, text):
        self.append_log(text, HackerPalette.WARNING)

    def append_info(self, text):
        self.append_log(text, HackerPalette.SECONDARY)


class MplCanvas(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.figure = Figure(facecolor=HackerPalette.BACKGROUND)
        self.canvas = FigureCanvasQTAgg(self.figure)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)

    def clear(self):
        self.figure.clear()
        self.canvas.draw()


class TrafficPieChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.canvas = MplCanvas(self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)
        self.classification = {"LOCAL": 0, "OUTBOUND": 0, "INBOUND": 0, "EXTERNAL": 0}

    def update_data(self, classification):
        self.classification = classification
        self.canvas.figure.clear()
        ax = self.canvas.figure.add_subplot(111)
        labels = []
        sizes = []
        colors = []
        color_map = {
            "LOCAL": HackerPalette.SUCCESS,
            "OUTBOUND": HackerPalette.WARNING,
            "INBOUND": HackerPalette.SECONDARY,
            "EXTERNAL": HackerPalette.DANGER,
        }
        for key, value in classification.items():
            if value > 0:
                labels.append(key)
                sizes.append(value)
                colors.append(color_map.get(key, HackerPalette.TEXT_DIM))
        if sizes:
            ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct="%1.0f%%",
                startangle=90,
                textprops={"color": HackerPalette.TEXT, "fontsize": 9},
            )
            ax.set_title("Traffic Classification", color=HackerPalette.PRIMARY, fontsize=10, pad=10)
        else:
            ax.text(0.5, 0.5, "No Data", ha="center", va="center", color=HackerPalette.TEXT_DIM, fontsize=10)
            ax.set_xticks([])
            ax.set_yticks([])
        self.canvas.figure.tight_layout()
        self.canvas.canvas.draw()


class ProtocolBarChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.canvas = MplCanvas(self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)

    def update_data(self, flows):
        self.canvas.figure.clear()
        ax = self.canvas.figure.add_subplot(111)
        proto_counts = defaultdict(int)
        for flow in flows:
            proto_counts[str(flow.protocol)] += 1
        if proto_counts:
            labels = list(proto_counts.keys())
            values = list(proto_counts.values())
            ax.bar(labels, values, color=HackerPalette.PRIMARY_DIM, edgecolor=HackerPalette.PRIMARY)
            ax.set_title("Protocol Distribution", color=HackerPalette.PRIMARY, fontsize=10, pad=10)
            ax.tick_params(colors=HackerPalette.TEXT, labelsize=9)
            ax.set_facecolor(HackerPalette.BACKGROUND)
            ax.spines["bottom"].set_color(HackerPalette.BORDER)
            ax.spines["left"].set_color(HackerPalette.BORDER)
            ax.spines["top"].set_color(HackerPalette.BORDER)
            ax.spines["right"].set_color(HackerPalette.BORDER)
        else:
            ax.text(0.5, 0.5, "No Data", ha="center", va="center", color=HackerPalette.TEXT_DIM, fontsize=10)
            ax.set_xticks([])
            ax.set_yticks([])
        self.canvas.figure.tight_layout()
        self.canvas.canvas.draw()


class BandwidthTimeline(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.canvas = MplCanvas(self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)
        self.timeline = deque(maxlen=50)

    def update_data(self, flows):
        total = sum(flow.size for flow in flows[-50:])
        self.timeline.append(total)
        self.canvas.figure.clear()
        ax = self.canvas.figure.add_subplot(111)
        if len(self.timeline) > 1:
            ax.plot(list(self.timeline), color=HackerPalette.PRIMARY, linewidth=1.5)
            ax.set_title("Bandwidth Timeline", color=HackerPalette.PRIMARY, fontsize=10, pad=10)
            ax.tick_params(colors=HackerPalette.TEXT, labelsize=9)
            ax.set_facecolor(HackerPalette.BACKGROUND)
            ax.spines["bottom"].set_color(HackerPalette.BORDER)
            ax.spines["left"].set_color(HackerPalette.BORDER)
            ax.spines["top"].set_color(HackerPalette.BORDER)
            ax.spines["right"].set_color(HackerPalette.BORDER)
            ax.set_xlabel("Sample", color=HackerPalette.TEXT_DIM, fontsize=9)
            ax.set_ylabel("Bytes", color=HackerPalette.TEXT_DIM, fontsize=9)
        else:
            ax.text(0.5, 0.5, "Collecting...", ha="center", va="center", color=HackerPalette.TEXT_DIM, fontsize=10)
            ax.set_xticks([])
            ax.set_yticks([])
        self.canvas.figure.tight_layout()
        self.canvas.canvas.draw()


class NodeActivityChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.canvas = MplCanvas(self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.canvas)

    def update_data(self, nodes):
        self.canvas.figure.clear()
        ax = self.canvas.figure.add_subplot(111)
        if nodes:
            labels = [node.ip for node in nodes[:10]]
            values = [len(getattr(node, "services", []) or []) for node in nodes[:10]]
            ax.barh(labels, values, color=HackerPalette.SECONDARY, edgecolor=HackerPalette.PRIMARY)
            ax.set_title("Top Nodes by Services", color=HackerPalette.PRIMARY, fontsize=10, pad=10)
            ax.tick_params(colors=HackerPalette.TEXT, labelsize=9)
            ax.set_facecolor(HackerPalette.BACKGROUND)
            ax.spines["bottom"].set_color(HackerPalette.BORDER)
            ax.spines["left"].set_color(HackerPalette.BORDER)
            ax.spines["top"].set_color(HackerPalette.BORDER)
            ax.spines["right"].set_color(HackerPalette.BORDER)
        else:
            ax.text(0.5, 0.5, "No Data", ha="center", va="center", color=HackerPalette.TEXT_DIM, fontsize=10)
            ax.set_xticks([])
            ax.set_yticks([])
        self.canvas.figure.tight_layout()
        self.canvas.canvas.draw()


class CaptureThread(QThread):
    flow_received = pyqtSignal(object)
    log_message = pyqtSignal(str)
    finished = pyqtSignal(list)

    def __init__(self, interface, parent=None):
        super().__init__(parent)
        self.interface = interface
        self._active = True

    def run(self):
        collector = ScapyCollector(self.interface)
        flows = []

        def on_flow(flow):
            flows.append(flow)
            self.flow_received.emit(flow)

        try:
            collector.capture(on_flow=on_flow, stop_flag=lambda: self._active)
        except Exception as e:
            self.log_message.emit(f"Capture error: {e}")
        self.finished.emit(flows)

    def stop(self):
        self._active = False


class DiscoverThread(QThread):
    node_discovered = pyqtSignal(object)
    log_message = pyqtSignal(str)
    finished = pyqtSignal(list)

    def __init__(self, interface, cidr, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.cidr = cidr

    def run(self):
        collector = ScapyCollector(self.interface)
        segment = NetworkSegment("temp", self.cidr)
        nodes = []

        def on_node(node):
            nodes.append(node)
            self.node_discovered.emit(node)

        try:
            collector.discover_nodes(segment, on_node=on_node)
        except Exception as e:
            self.log_message.emit(f"Discovery error: {e}")
        self.finished.emit(nodes)


class NewSegmentDialog(QDialog):
    def __init__(self, interfaces, parent=None):
        super().__init__(parent)
        self.interfaces = interfaces
        self.selected = None
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("New Network Segment")
        layout = QFormLayout(self)

        self.interface_combo = QComboBox()
        for iface in self.interfaces:
            label = f"{iface['name']} - {iface['ip'] or 'No IP'}"
            self.interface_combo.addItem(label, iface)
        layout.addRow("Interface:", self.interface_combo)

        self.name_edit = QLineEdit()
        layout.addRow("Segment Name:", self.name_edit)

        self.cidr_edit = QLineEdit()
        layout.addRow("CIDR:", self.cidr_edit)

        self.network_edit = QLineEdit()
        self.network_edit.setReadOnly(True)
        layout.addRow("Network:", self.network_edit)

        self.broadcast_edit = QLineEdit()
        self.broadcast_edit.setReadOnly(True)
        layout.addRow("Broadcast:", self.broadcast_edit)

        self.hosts_edit = QLineEdit()
        self.hosts_edit.setReadOnly(True)
        layout.addRow("Available Hosts:", self.hosts_edit)

        self.update_details()
        self.interface_combo.currentIndexChanged.connect(self.update_details)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def update_details(self):
        iface = self.interface_combo.currentData()
        if iface and iface.get("ip") and iface.get("netmask"):
            try:
                network = ipaddress.ip_network(
                    f"{iface['ip']}/{iface['netmask']}", strict=False
                )
                self.cidr_edit.setText(str(network))
                self.network_edit.setText(str(network.network_address))
                self.broadcast_edit.setText(str(network.broadcast_address))
                hosts = network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2
                self.hosts_edit.setText(str(hosts))
            except ValueError:
                self.cidr_edit.setText("")
                self.network_edit.setText("")
                self.broadcast_edit.setText("")
                self.hosts_edit.setText("")
        else:
            self.cidr_edit.setText("")
            self.network_edit.setText("")
            self.broadcast_edit.setText("")
            self.hosts_edit.setText("")

    def accept(self):
        iface = self.interface_combo.currentData()
        cidr = self.cidr_edit.text().strip()
        name = self.name_edit.text().strip()
        if not cidr or not name:
            QMessageBox.warning(self, "Error", "Please fill all fields")
            return
        if iface is None or not iface.get("ip"):
            QMessageBox.warning(self, "Error", "Selected interface has no IP")
            return
        self.selected = {
            "interface": iface,
            "cidr": cidr,
            "name": name,
            "network": self.network_edit.text(),
            "broadcast": self.broadcast_edit.text(),
            "hosts": self.hosts_edit.text(),
            "netmask": iface.get("netmask"),
        }
        super().accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scanner = InterfaceScanner()
        self.analyzer = NetworkAnalyzer()
        self.segments = {}
        self.current_segment = None
        self.capture_thread = None
        self.discover_thread = None

        self.storage = DataStore()
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector(self.storage)
        self.alert_engine = AlertEngine(self.storage)

        self.traffic_pie = TrafficPieChart()
        self.protocol_bar = ProtocolBarChart()
        self.bandwidth_timeline = BandwidthTimeline()
        self.node_activity = NodeActivityChart()

        self.apply_stylesheet()
        self.setup_ui()
        self.refresh_interfaces()
        self.setup_status_bar()

    def apply_stylesheet(self):
        self.setStyleSheet(f"""
            QMainWindow {{
                background: {HackerPalette.BACKGROUND};
            }}
            QWidget {{
                background: {HackerPalette.BACKGROUND};
                color: {HackerPalette.TEXT};
                font-family: {HackerPalette.FONT_MAIN};
                font-size: 13px;
            }}
            QListWidget {{
                background: {HackerPalette.PANEL};
                color: {HackerPalette.TEXT};
                border: 1px solid {HackerPalette.BORDER};
                border-radius: {HackerPalette.RADIUS}px;
                padding: 4px;
                font-family: {HackerPalette.FONT_MONO};
                font-size: 12px;
            }}
            QListWidget::item {{
                padding: 10px 12px;
                border-radius: 6px;
                margin: 2px 0px;
            }}
            QListWidget::item:hover {{
                background: {HackerPalette.PANEL_ALT};
            }}
            QListWidget::item:selected {{
                background: {HackerPalette.PRIMARY_DIM};
                color: {HackerPalette.BACKGROUND};
                font-weight: 600;
            }}
            QPushButton {{
                background: {HackerPalette.PANEL};
                color: {HackerPalette.PRIMARY};
                border: 1px solid {HackerPalette.BORDER};
                border-radius: {HackerPalette.RADIUS}px;
                padding: 8px 16px;
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            QPushButton:hover {{
                background: {HackerPalette.PRIMARY_DIM};
                color: {HackerPalette.BACKGROUND};
                border: 1px solid {HackerPalette.PRIMARY};
            }}
            QPushButton:pressed {{
                background: {HackerPalette.PRIMARY};
                color: {HackerPalette.BACKGROUND};
            }}
            QPushButton:disabled {{
                color: {HackerPalette.TEXT_DIM};
                border: 1px solid {HackerPalette.BORDER};
                background: {HackerPalette.PANEL};
            }}
            QTabWidget::pane {{
                border: 1px solid {HackerPalette.BORDER};
                border-radius: {HackerPalette.RADIUS}px;
                background: {HackerPalette.PANEL};
                top: -1px;
            }}
            QTabBar::tab {{
                background: {HackerPalette.PANEL};
                color: {HackerPalette.TEXT_DIM};
                border: 1px solid {HackerPalette.BORDER};
                border-bottom: none;
                border-top-left-radius: {HackerPalette.RADIUS}px;
                border-top-right-radius: {HackerPalette.RADIUS}px;
                padding: 10px 20px;
                margin-right: 4px;
                font-weight: 600;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            QTabBar::tab:selected {{
                background: {HackerPalette.PANEL};
                color: {HackerPalette.PRIMARY};
                border-bottom: 2px solid {HackerPalette.PRIMARY};
            }}
            QTabBar::tab:hover {{
                color: {HackerPalette.TEXT};
                background: {HackerPalette.PANEL_ALT};
            }}
            QTableWidget {{
                background: {HackerPalette.BACKGROUND};
                color: {HackerPalette.TEXT};
                border: 1px solid {HackerPalette.BORDER};
                border-radius: {HackerPalette.RADIUS}px;
                gridline-color: {HackerPalette.BORDER};
                font-family: {HackerPalette.FONT_MONO};
                font-size: 11px;
            }}
            QTableWidget::item {{
                padding: 8px;
                border-bottom: 1px solid {HackerPalette.BORDER};
            }}
            QTableWidget::item:selected {{
                background: {HackerPalette.PRIMARY_DIM};
                color: {HackerPalette.BACKGROUND};
            }}
            QHeaderView::section {{
                background: {HackerPalette.PANEL};
                color: {HackerPalette.PRIMARY};
                border: 1px solid {HackerPalette.BORDER};
                border-bottom: 2px solid {HackerPalette.PRIMARY};
                padding: 10px 8px;
                font-weight: 700;
                font-size: 11px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            QGroupBox {{
                border: 1px solid {HackerPalette.BORDER};
                border-radius: {HackerPalette.RADIUS}px;
                margin-top: 12px;
                padding-top: 12px;
                font-weight: 700;
                color: {HackerPalette.PRIMARY};
                text-transform: uppercase;
                letter-spacing: 0.5px;
                font-size: 12px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 10px;
                left: 12px;
            }}
            QComboBox {{
                background: {HackerPalette.BACKGROUND};
                color: {HackerPalette.TEXT};
                border: 1px solid {HackerPalette.BORDER};
                border-radius: {HackerPalette.RADIUS}px;
                padding: 8px 12px;
                font-family: {HackerPalette.FONT_MONO};
                font-size: 12px;
            }}
            QComboBox::drop-down {{
                border: none;
                width: 24px;
            }}
            QComboBox QAbstractItemView {{
                background: {HackerPalette.PANEL};
                color: {HackerPalette.TEXT};
                selection-background-color: {HackerPalette.PRIMARY_DIM};
                border: 1px solid {HackerPalette.BORDER};
            }}
            QScrollBar:vertical {{
                background: {HackerPalette.PANEL};
                width: 12px;
                border-radius: 6px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background: {HackerPalette.BORDER};
                border-radius: 6px;
                min-height: 30px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {HackerPalette.PRIMARY_DIM};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                border: none;
                background: none;
                height: 0px;
            }}
            QScrollBar:horizontal {{
                background: {HackerPalette.PANEL};
                height: 12px;
                border-radius: 6px;
                margin: 0px;
            }}
            QScrollBar::handle:horizontal {{
                background: {HackerPalette.BORDER};
                border-radius: 6px;
                min-width: 30px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background: {HackerPalette.PRIMARY_DIM};
            }}
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                border: none;
                background: none;
                width: 0px;
            }}
            QStatusBar {{
                background: {HackerPalette.PANEL};
                color: {HackerPalette.TEXT_DIM};
                border-top: 1px solid {HackerPalette.BORDER};
                font-family: {HackerPalette.FONT_MONO};
                font-size: 11px;
            }}
            QSplitter::handle {{
                background: {HackerPalette.BORDER};
                width: 1px;
            }}
        """)

    def setup_status_bar(self):
        self.status_label = QLabel("SYSTEM READY")
        self.status_label.setStyleSheet(f"color: {HackerPalette.PRIMARY}; font-weight: 700; padding: 0 10px;")
        self.statusBar().addWidget(self.status_label, 1)

        self.clock_label = QLabel()
        self.clock_label.setStyleSheet(f"color: {HackerPalette.TEXT_DIM}; font-family: {HackerPalette.FONT_MONO}; padding: 0 10px;")
        self.statusBar().addPermanentWidget(self.clock_label)

        timer = QTimer(self)
        timer.timeout.connect(self.update_clock)
        timer.start(1000)
        self.update_clock()

    def update_clock(self):
        self.clock_label.setText(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def setup_ui(self):
        self.setWindowTitle("EYE Network Vision")
        self.resize(1280, 800)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # Left Panel
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

        left_layout.addWidget(QLabel("Network Segments"))
        self.segment_list = QListWidget()
        left_layout.addWidget(self.segment_list)

        btn_layout = QHBoxLayout()
        self.new_segment_btn = QPushButton("New Segment")
        self.new_segment_btn.clicked.connect(self.create_segment)
        btn_layout.addWidget(self.new_segment_btn)
        left_layout.addLayout(btn_layout)

        splitter.addWidget(left_panel)

        # Right Panel
        right_panel = QTabWidget()
        splitter.addWidget(right_panel)

        # Overview Tab
        self.overview_tab = QWidget()
        overview_layout = QVBoxLayout(self.overview_tab)

        info_group = QGroupBox("Segment Information")
        info_layout = QFormLayout(info_group)
        self.info_name = QLabel("-")
        self.info_cidr = QLabel("-")
        self.info_network = QLabel("-")
        self.info_broadcast = QLabel("-")
        self.info_hosts = QLabel("-")
        self.info_nodes = QLabel("-")
        self.info_traffic = QLabel("-")
        info_layout.addRow("Name:", self.info_name)
        info_layout.addRow("CIDR:", self.info_cidr)
        info_layout.addRow("Network:", self.info_network)
        info_layout.addRow("Broadcast:", self.info_broadcast)
        info_layout.addRow("Available Hosts:", self.info_hosts)
        info_layout.addRow("Nodes:", self.info_nodes)
        info_layout.addRow("Traffic Flows:", self.info_traffic)
        overview_layout.addWidget(info_group)

        overview_layout.addWidget(QLabel("Nodes"))
        self.nodes_table = QTableWidget()
        self.nodes_table.setColumnCount(6)
        self.nodes_table.setHorizontalHeaderLabels(
            ["IP", "MAC", "Hostname", "Status", "Last Seen", "Services"]
        )
        self.nodes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        overview_layout.addWidget(self.nodes_table)

        overview_layout.addWidget(QLabel("Traffic Flows"))
        self.traffic_table = QTableWidget()
        self.traffic_table.setColumnCount(5)
        self.traffic_table.setHorizontalHeaderLabels(
            ["Source", "Destination", "Protocol", "Size", "Type"]
        )
        self.traffic_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        overview_layout.addWidget(self.traffic_table)

        right_panel.addTab(self.overview_tab, "Overview")

        # Capture Tab
        self.capture_tab = QWidget()
        capture_layout = QVBoxLayout(self.capture_tab)

        capture_control = QHBoxLayout()
        capture_layout.addLayout(capture_control)

        capture_control.addWidget(QLabel("Interface:"))
        self.capture_interface_combo = QComboBox()
        capture_control.addWidget(self.capture_interface_combo)

        self.discover_btn = QPushButton("Discover Nodes (ARP)")
        self.discover_btn.clicked.connect(self.discover_nodes)
        capture_control.addWidget(self.discover_btn)

        self.start_capture_btn = QPushButton("Start Capture")
        self.start_capture_btn.clicked.connect(self.start_capture)
        capture_control.addWidget(self.start_capture_btn)

        self.stop_capture_btn = QPushButton("Stop Capture")
        self.stop_capture_btn.clicked.connect(self.stop_capture)
        self.stop_capture_btn.setEnabled(False)
        capture_control.addWidget(self.stop_capture_btn)

        capture_control.addStretch()

        self.capture_log = TerminalLog()
        capture_layout.addWidget(self.capture_log)

        self.capture_count_label = QLabel("Captured: 0 flows")
        capture_layout.addWidget(self.capture_count_label)

        right_panel.addTab(self.capture_tab, "Capture")

        # Nodes Tab
        self.nodes_tab = QWidget()
        nodes_layout = QVBoxLayout(self.nodes_tab)
        self.nodes_detail_table = QTableWidget()
        self.nodes_detail_table.setColumnCount(6)
        self.nodes_detail_table.setHorizontalHeaderLabels(
            ["IP", "MAC", "Hostname", "Status", "Last Seen", "Services"]
        )
        self.nodes_detail_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.nodes_detail_table.itemClicked.connect(self.on_node_selected)
        nodes_layout.addWidget(self.nodes_detail_table)
        right_panel.addTab(self.nodes_tab, "Nodes")

        # Traffic Tab
        self.traffic_tab = QWidget()
        traffic_layout = QVBoxLayout(self.traffic_tab)
        self.traffic_detail_table = QTableWidget()
        self.traffic_detail_table.setColumnCount(5)
        self.traffic_detail_table.setHorizontalHeaderLabels(
            ["Source", "Destination", "Protocol", "Size", "Type"]
        )
        self.traffic_detail_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        traffic_layout.addWidget(self.traffic_detail_table)
        right_panel.addTab(self.traffic_tab, "Traffic")

        # Dashboard Tab
        self.dashboard_tab = QWidget()
        dashboard_layout = QVBoxLayout(self.dashboard_tab)
        dashboard_layout.setContentsMargins(16, 16, 16, 16)
        dashboard_layout.setSpacing(12)

        charts_top = QHBoxLayout()
        charts_top.addWidget(self.traffic_pie)
        charts_top.addWidget(self.protocol_bar)
        dashboard_layout.addLayout(charts_top, stretch=1)

        charts_bottom = QHBoxLayout()
        charts_bottom.addWidget(self.bandwidth_timeline)
        charts_bottom.addWidget(self.node_activity)
        dashboard_layout.addLayout(charts_bottom, stretch=1)

        right_panel.addTab(self.dashboard_tab, "Dashboard")

        # Reports Tab
        self.reports_tab = QWidget()
        reports_layout = QVBoxLayout(self.reports_tab)

        btn_export_nodes = QPushButton("Export Nodes to CSV")
        btn_export_nodes.clicked.connect(self.export_nodes)
        reports_layout.addWidget(btn_export_nodes)

        btn_export_traffic = QPushButton("Export Traffic to CSV")
        btn_export_traffic.clicked.connect(self.export_traffic)
        reports_layout.addWidget(btn_export_traffic)

        btn_export_report = QPushButton("Export Full Report")
        btn_export_report.clicked.connect(self.export_report)
        reports_layout.addWidget(btn_export_report)

        reports_layout.addStretch()
        right_panel.addTab(self.reports_tab, "Reports")

        # Alerts Tab
        self.alerts_tab = QWidget()
        alerts_layout = QVBoxLayout(self.alerts_tab)
        alerts_layout.setContentsMargins(16, 16, 16, 16)
        alerts_layout.setSpacing(12)

        alerts_group = QGroupBox("Security Alerts")
        alerts_group_layout = QVBoxLayout(alerts_group)
        alerts_group_layout.setContentsMargins(16, 20, 16, 16)
        alerts_group_layout.setSpacing(8)

        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(6)
        self.alerts_table.setHorizontalHeaderLabels(
            ["Severity", "Category", "Description", "Score", "Time", "ID"]
        )
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.alerts_table.verticalHeader().setVisible(False)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.alerts_table.setAlternatingRowColors(True)
        self.alerts_table.setStyleSheet(f"""
            QTableWidget {{
                alternate-background-color: {HackerPalette.PANEL};
            }}
        """)
        self.alerts_table.hideColumn(5)
        self.alerts_table.cellDoubleClicked.connect(self.show_alert_detail)
        alerts_group_layout.addWidget(self.alerts_table)

        alerts_layout.addWidget(alerts_group)

        btn_layout = QHBoxLayout()
        btn_ack = QPushButton("Acknowledge Selected")
        btn_ack.clicked.connect(self.acknowledge_alert)
        btn_layout.addWidget(btn_ack)
        btn_layout.addStretch()
        alerts_layout.addLayout(btn_layout)

        self.alerts_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.alerts_table.customContextMenuRequested.connect(self.show_alerts_context_menu)

        right_panel.addTab(self.alerts_tab, "Alerts")

        self.statusBar().showMessage("Ready")

        self.segment_list.itemClicked.connect(self.load_segment)

    def refresh_interfaces(self):
        interfaces = self.scanner.get_interfaces()
        self.capture_interface_combo.clear()
        for iface in interfaces:
            label = f"{iface['name']} - {iface['ip'] or 'No IP'}"
            self.capture_interface_combo.addItem(label, iface)

    def create_segment(self):
        interfaces = self.scanner.get_interfaces()
        dlg = NewSegmentDialog(interfaces, self)
        if dlg.exec():
            data = dlg.selected
            name = data["name"]
            if name in self.segments:
                QMessageBox.warning(self, "Error", "Segment with this name already exists")
                return

            segment = NetworkSegment(name, data["cidr"])
            segment.interface = data["interface"]["name"]
            segment.netmask = data.get("netmask")
            segment.network = data.get("network")
            segment.broadcast = data.get("broadcast")
            segment.hosts = int(data.get("hosts") or 0)

            self.segments[name] = segment
            self.segment_list.addItem(f"{name} ({data['cidr']})")
            self.current_segment = segment
            self.update_overview()
            self.update_stats()
            self.select_segment_interface()
            QMessageBox.information(self, "Success", "Segment created successfully!")

    def load_segment(self, item):
        text = item.text()
        name = text.split(" (")[0]
        self.current_segment = self.segments.get(name)
        self.update_overview()
        self.update_stats()
        self.select_segment_interface()

    def select_segment_interface(self):
        seg = self.current_segment
        if not seg:
            return
        for i in range(self.capture_interface_combo.count()):
            data = self.capture_interface_combo.itemData(i)
            if data and data.get("name") == seg.interface:
                self.capture_interface_combo.setCurrentIndex(i)
                return

    def validate_segment_interface(self):
        seg = self.current_segment
        if not seg or not seg.interface:
            return False
        iface_data = None
        for i in range(self.capture_interface_combo.count()):
            data = self.capture_interface_combo.itemData(i)
            if data and data.get("name") == seg.interface:
                iface_data = data
                break
        if not iface_data:
            return False
        iface_ip = iface_data.get("ip")
        if not iface_ip:
            return False
        try:
            network = ipaddress.ip_network(seg.cidr, strict=False)
            return ipaddress.ip_address(iface_ip) in network
        except ValueError:
            return False

    def update_overview(self):
        seg = self.current_segment
        if not seg:
            return

        self.info_name.setText(seg.name)
        self.info_cidr.setText(seg.cidr)
        self.info_network.setText(getattr(seg, "network", "-"))
        self.info_broadcast.setText(getattr(seg, "broadcast", "-"))
        self.info_hosts.setText(str(getattr(seg, "hosts", "-")))
        self.info_nodes.setText(str(len(seg.nodes)))
        self.info_traffic.setText(str(len(seg.traffic)))

        self.nodes_table.setRowCount(len(seg.nodes))
        for row, node in enumerate(seg.nodes):
            self.nodes_table.setItem(row, 0, QTableWidgetItem(node.ip))
            self.nodes_table.setItem(row, 1, QTableWidgetItem(node.mac or "-"))
            self.nodes_table.setItem(row, 2, QTableWidgetItem(node.hostname or "-"))
            self.nodes_table.setItem(row, 3, QTableWidgetItem(node.status))
            self.nodes_table.setItem(row, 4, QTableWidgetItem(node.last_seen or "-"))
            services_str = ", ".join(node.services) if node.services else "-"
            self.nodes_table.setItem(row, 5, QTableWidgetItem(services_str))

        self.traffic_table.setRowCount(len(seg.traffic))
        for row, flow in enumerate(seg.traffic):
            self.traffic_table.setItem(row, 0, QTableWidgetItem(flow.source))
            self.traffic_table.setItem(row, 1, QTableWidgetItem(flow.destination))
            self.traffic_table.setItem(row, 2, QTableWidgetItem(str(flow.protocol)))
            self.traffic_table.setItem(row, 3, QTableWidgetItem(str(flow.size)))
            cat = self.analyzer.classify_traffic(seg, flow)
            item = QTableWidgetItem(cat)
            if cat == "LOCAL":
                item.setBackground(QColor(HackerPalette.LOCAL_BG))
                item.setForeground(QColor(HackerPalette.LOCAL_TEXT))
            elif cat == "OUTBOUND":
                item.setBackground(QColor(HackerPalette.OUTBOUND_BG))
                item.setForeground(QColor(HackerPalette.OUTBOUND_TEXT))
            elif cat == "INBOUND":
                item.setBackground(QColor(HackerPalette.INBOUND_BG))
                item.setForeground(QColor(HackerPalette.INBOUND_TEXT))
            elif cat == "EXTERNAL":
                item.setBackground(QColor(HackerPalette.EXTERNAL_BG))
                item.setForeground(QColor(HackerPalette.EXTERNAL_TEXT))
            self.traffic_table.setItem(row, 4, item)

        self.nodes_detail_table.setRowCount(len(seg.nodes))
        for row, node in enumerate(seg.nodes):
            self.nodes_detail_table.setItem(row, 0, QTableWidgetItem(node.ip))
            self.nodes_detail_table.setItem(row, 1, QTableWidgetItem(node.mac or "-"))
            self.nodes_detail_table.setItem(row, 2, QTableWidgetItem(node.hostname or "-"))
            self.nodes_detail_table.setItem(row, 3, QTableWidgetItem(node.status))
            self.nodes_detail_table.setItem(row, 4, QTableWidgetItem(node.last_seen or "-"))
            services_str = ", ".join(node.services) if node.services else "-"
            self.nodes_detail_table.setItem(row, 5, QTableWidgetItem(services_str))

        self.traffic_detail_table.setRowCount(len(seg.traffic))
        for row, flow in enumerate(seg.traffic):
            self.traffic_detail_table.setItem(row, 0, QTableWidgetItem(flow.source))
            self.traffic_detail_table.setItem(row, 1, QTableWidgetItem(flow.destination))
            self.traffic_detail_table.setItem(row, 2, QTableWidgetItem(str(flow.protocol)))
            self.traffic_detail_table.setItem(row, 3, QTableWidgetItem(str(flow.size)))
            cat = self.analyzer.classify_traffic(seg, flow)
            item = QTableWidgetItem(cat)
            if cat == "LOCAL":
                item.setBackground(QColor(HackerPalette.LOCAL_BG))
                item.setForeground(QColor(HackerPalette.LOCAL_TEXT))
            elif cat == "OUTBOUND":
                item.setBackground(QColor(HackerPalette.OUTBOUND_BG))
                item.setForeground(QColor(HackerPalette.OUTBOUND_TEXT))
            elif cat == "INBOUND":
                item.setBackground(QColor(HackerPalette.INBOUND_BG))
                item.setForeground(QColor(HackerPalette.INBOUND_TEXT))
            elif cat == "EXTERNAL":
                item.setBackground(QColor(HackerPalette.EXTERNAL_BG))
                item.setForeground(QColor(HackerPalette.EXTERNAL_TEXT))
            self.traffic_detail_table.setItem(row, 4, item)

        self.statusBar().showMessage(
            f"Segment loaded: {seg.name} | {len(seg.nodes)} nodes | {len(seg.traffic)} flows"
        )

    def update_stats(self):
        seg = self.current_segment
        if not seg:
            return
        classification = self.analyzer.analyze_traffic(seg) if seg.traffic else {
            "LOCAL": 0, "OUTBOUND": 0, "INBOUND": 0, "EXTERNAL": 0
        }
        self.stat_nodes.update_value(len(seg.nodes))
        self.stat_traffic.update_value(len(seg.traffic))
        self.stat_local.update_value(classification["LOCAL"])
        self.stat_outbound.update_value(classification["OUTBOUND"])
        self.stat_inbound.update_value(classification["INBOUND"])
        self.stat_external.update_value(classification["EXTERNAL"])
        self.update_dashboard()

    def update_dashboard(self):
        seg = self.current_segment
        if not seg:
            self.traffic_pie.update_data({"LOCAL": 0, "OUTBOUND": 0, "INBOUND": 0, "EXTERNAL": 0})
            self.protocol_bar.update_data([])
            self.bandwidth_timeline.update_data([])
            self.node_activity.update_data([])
            return
        classification = self.analyzer.analyze_traffic(seg) if seg.traffic else {
            "LOCAL": 0, "OUTBOUND": 0, "INBOUND": 0, "EXTERNAL": 0
        }
        self.traffic_pie.update_data(classification)
        self.protocol_bar.update_data(seg.traffic)
        self.bandwidth_timeline.update_data(seg.traffic)
        self.node_activity.update_data(seg.nodes)

    def update_alerts(self):
        alerts = self.alert_engine.get_recent_alerts(limit=200)
        self.alerts_table.setRowCount(len(alerts))
        severity_colors = {
            "LOW": HackerPalette.TEXT_DIM,
            "MEDIUM": HackerPalette.WARNING,
            "HIGH": HackerPalette.DANGER,
            "CRITICAL": HackerPalette.DANGER,
        }
        for row, alert in enumerate(alerts):
            self.alerts_table.setItem(row, 0, QTableWidgetItem(alert.get("severity", "")))
            severity = alert.get("severity", "")
            color = severity_colors.get(severity, HackerPalette.TEXT)
            self.alerts_table.item(row, 0).setForeground(QColor(color))
            self.alerts_table.setItem(row, 1, QTableWidgetItem(alert.get("category", "")))
            self.alerts_table.setItem(row, 2, QTableWidgetItem(alert.get("description", "")))
            self.alerts_table.setItem(row, 3, QTableWidgetItem(str(alert.get("score", 0.0))))
            self.alerts_table.setItem(row, 4, QTableWidgetItem(alert.get("timestamp", "")))
            alert_id_item = QTableWidgetItem(str(alert.get("id", "")))
            self.alerts_table.setItem(row, 5, alert_id_item)
            self.alerts_table.item(row, 5).setData(Qt.ItemDataRole.UserRole, alert)

    def acknowledge_alert(self):
        current_row = self.alerts_table.currentRow()
        if current_row < 0:
            return
        alert_item = self.alerts_table.item(current_row, 5)
        if not alert_item:
            return
        alert_data = alert_item.data(Qt.ItemDataRole.UserRole)
        if alert_data:
            alert_id = alert_data.get("id")
            if alert_id:
                self.storage.acknowledge_alert(alert_id)
        self.update_alerts()

    def show_alert_detail(self):
        current_row = self.alerts_table.currentRow()
        if current_row < 0:
            return
        alert_item = self.alerts_table.item(current_row, 5)
        if not alert_item:
            return
        alert_data = alert_item.data(Qt.ItemDataRole.UserRole)
        if not alert_data:
            return

        dialog = AlertDetailDialog(alert_data, self)
        flow_id = alert_data.get("flow_id")
        if flow_id and self.storage:
            features = self.storage.get_features_for_flow(flow_id)
            if features:
                feature_names = features.get("feature_names", [])
                feature_values = features.get("features", [])
                payload_text = ""
                for name, value in zip(feature_names, feature_values):
                    payload_text += f"{name}: {value}\n"
                dialog.payload_text.setText(payload_text)
        dialog.exec()

    def show_alerts_context_menu(self, position):
        current_row = self.alerts_table.currentRow()
        if current_row < 0:
            return
        alert_item = self.alerts_table.item(current_row, 5)
        if not alert_item:
            return
        alert_data = alert_item.data(Qt.ItemDataRole.UserRole)
        if not alert_data:
            return

        menu = QMenu()
        menu.setStyleSheet(f"""
            QMenu {{
                background: {HackerPalette.PANEL};
                color: {HackerPalette.TEXT};
                border: 1px solid {HackerPalette.BORDER};
                padding: 4px;
            }}
            QMenu::item {{
                padding: 8px 12px;
            }}
            QMenu::item:selected {{
                background: {HackerPalette.PRIMARY_DIM};
                color: {HackerPalette.BACKGROUND};
            }}
        """)

        detail_action = menu.addAction("View Details")
        fp_action = menu.addAction("Mark as False Positive")
        tp_action = menu.addAction("Mark as True Positive")
        ack_action = menu.addAction("Acknowledge")

        action = menu.exec(self.alerts_table.viewport().mapToGlobal(position))
        if action == detail_action:
            self.show_alert_detail()
        elif action == fp_action:
            self._label_alert(alert_data, "false_positive")
        elif action == tp_action:
            self._label_alert(alert_data, "true_positive")
        elif action == ack_action:
            self.acknowledge_alert()

    def _label_alert(self, alert_data, label):
        flow_id = alert_data.get("flow_id")
        if flow_id and self.storage:
            self.storage.add_label(flow_id, label)
            self.capture_log.append_log(
                f"Alert labeled as {label}: {alert_data.get('description', '')}",
                HackerPalette.SUCCESS,
            )

    def start_capture(self):
        if not self.current_segment:
            QMessageBox.warning(self, "Warning", "Select a segment first")
            return

        seg = self.current_segment
        if not seg.interface:
            QMessageBox.warning(self, "Warning", "Segment has no associated interface")
            return

        if not self.validate_segment_interface():
            QMessageBox.warning(
                self,
                "Interface Mismatch",
                f"Interface {seg.interface} does not belong to segment CIDR {seg.cidr}.\n"
                f"Capture will not work correctly.\n\n"
                f"Please create a new segment with the correct interface."
            )
            return

        iface_data = None
        for i in range(self.capture_interface_combo.count()):
            data = self.capture_interface_combo.itemData(i)
            if data and data.get("name") == seg.interface:
                iface_data = data
                break

        if not iface_data:
            QMessageBox.warning(self, "Warning", f"Interface {seg.interface} not found")
            return

        interface = iface_data["name"]
        self.capture_thread = CaptureThread(interface)
        self.capture_thread.flow_received.connect(self.on_flow_received)
        self.capture_thread.log_message.connect(self.on_capture_log)
        self.capture_thread.finished.connect(self.on_capture_finished)

        self.start_capture_btn.setEnabled(False)
        self.stop_capture_btn.setEnabled(True)
        self.capture_log.clear()
        self.capture_log.append_log(f"Starting capture on {interface}...", HackerPalette.PRIMARY)
        self.capture_thread.start()

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_log.append_log("Stopping capture...", HackerPalette.WARNING)

    def on_capture_log(self, message, level="info"):
        if level == "error":
            self.capture_log.append_error(message)
        elif level == "warning":
            self.capture_log.append_warning(message)
        elif level == "info":
            self.capture_log.append_info(message)
        else:
            self.capture_log.append_log(message)

    def on_flow_received(self, flow):
        if self.current_segment:
            self.current_segment.add_traffic(flow)
            self.capture_count_label.setText(
                f"Captured: {len(self.current_segment.traffic)} flows"
            )
            classification = self.analyzer.classify_traffic(self.current_segment, flow)
            color = HackerPalette.PRIMARY
            if classification == "LOCAL":
                color = HackerPalette.SUCCESS
            elif classification == "OUTBOUND":
                color = HackerPalette.WARNING
            elif classification == "INBOUND":
                color = HackerPalette.SECONDARY
            elif classification == "EXTERNAL":
                color = HackerPalette.DANGER
            self.capture_log.append_log(
                f"{flow.source} -> {flow.destination} | Proto: {flow.protocol} | Size: {flow.size} | [{classification}]",
                color=color
            )

            # AI pipeline
            try:
                flow_id = self.storage.insert_flow(self.current_segment.name, flow)
                features = self.feature_extractor.extract(flow)
                feature_vector = self.feature_extractor.get_feature_vector(features)
                self.storage.insert_features(flow_id, features, self.feature_extractor.get_feature_names())

                anomaly_result = self.anomaly_detector.detect(self.current_segment.name, flow, features)
                alerts = self.alert_engine.evaluate(
                    self.current_segment.name,
                    flow,
                    features,
                    anomaly_result,
                    payload=getattr(flow, "payload", None),
                )
                if alerts:
                    self.update_alerts()
            except Exception as e:
                self.capture_log.append_error(f"AI error: {e}")

            self.update_stats()

    def on_capture_finished(self, flows):
        self.start_capture_btn.setEnabled(True)
        self.stop_capture_btn.setEnabled(False)
        self.capture_log.append_info(f"Capture finished. Total flows: {len(flows)}")
        if self.current_segment:
            self.analyzer.discover_nodes(self.current_segment)
        self.update_overview()
        self.update_stats()
        self.statusBar().showMessage(f"Capture complete: {len(flows)} flows")

    def discover_nodes(self):
        if not self.current_segment:
            QMessageBox.warning(self, "Warning", "Select a segment first")
            return

        seg = self.current_segment
        if not seg.interface:
            QMessageBox.warning(self, "Warning", "Segment has no associated interface")
            return

        if not self.validate_segment_interface():
            QMessageBox.warning(
                self,
                "Interface Mismatch",
                f"Interface {seg.interface} does not belong to segment CIDR {seg.cidr}.\n"
                f"ARP discovery will not work correctly.\n\n"
                f"Please create a new segment with the correct interface."
            )
            return

        iface_data = None
        for i in range(self.capture_interface_combo.count()):
            data = self.capture_interface_combo.itemData(i)
            if data and data.get("name") == seg.interface:
                iface_data = data
                break

        if not iface_data:
            QMessageBox.warning(self, "Warning", f"Interface {seg.interface} not found")
            return

        interface = iface_data["name"]
        cidr = seg.cidr

        self.discover_thread = DiscoverThread(interface, cidr)
        self.discover_thread.node_discovered.connect(self.on_node_discovered)
        self.discover_thread.log_message.connect(self.on_capture_log)
        self.discover_thread.finished.connect(self.on_discover_finished)

        self.discover_btn.setEnabled(False)
        self.capture_log.append_log(f"Discovering nodes on {interface} ({cidr})...", HackerPalette.SECONDARY)
        self.discover_thread.start()

    def on_node_discovered(self, node):
        if self.current_segment:
            exists = any(n.ip == node.ip for n in self.current_segment.nodes)
            if not exists:
                self.current_segment.add_node(node)
            self.capture_log.append_log(f"Discovered: {node.ip} | MAC: {node.mac}", HackerPalette.PRIMARY)
            self.update_stats()

    def on_discover_finished(self, nodes):
        self.discover_btn.setEnabled(True)
        self.capture_log.append_info(f"Discovery finished. Nodes found: {len(nodes)}")
        self.update_overview()
        self.update_stats()

    def on_node_selected(self, item):
        if not self.current_segment:
            return
        row = item.row()
        if row < len(self.current_segment.nodes):
            node = self.current_segment.nodes[row]
            self.statusBar().showMessage(
                f"Selected: {node.ip} | MAC: {node.mac or 'N/A'} | Status: {node.status}"
            )

    def export_nodes(self):
        if not self.current_segment or not self.current_segment.nodes:
            QMessageBox.warning(self, "Warning", "No nodes to export")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Nodes", "", "CSV Files (*.csv)"
        )
        if path:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    ["IP", "MAC", "Hostname", "Status", "Last Seen", "Services", "Discovery Method"]
                )
                for node in self.current_segment.nodes:
                    writer.writerow([
                        node.ip,
                        node.mac or "",
                        node.hostname or "",
                        node.status,
                        node.last_seen or "",
                        ", ".join(node.services) if node.services else "",
                        getattr(node, "discovery_method", "UNKNOWN"),
                    ])
            QMessageBox.information(self, "Success", f"Nodes exported to {path}")

    def export_traffic(self):
        if not self.current_segment or not self.current_segment.traffic:
            QMessageBox.warning(self, "Warning", "No traffic to export")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Traffic", "", "CSV Files (*.csv)"
        )
        if path:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Source", "Destination", "Protocol", "Size", "Type"])
                for flow in self.current_segment.traffic:
                    writer.writerow([
                        flow.source,
                        flow.destination,
                        flow.protocol,
                        flow.size,
                        self.analyzer.classify_traffic(self.current_segment, flow),
                    ])
            QMessageBox.information(self, "Success", f"Traffic exported to {path}")

    def export_report(self):
        if not self.current_segment:
            QMessageBox.warning(self, "Warning", "No segment selected")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "", "Text Files (*.txt)"
        )
        if path:
            seg = self.current_segment
            classification = self.analyzer.analyze_traffic(seg)
            with open(path, "w") as f:
                f.write("=" * 50 + "\n")
                f.write("EYE Network Vision - Report\n")
                f.write("=" * 50 + "\n")
                f.write(
                    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                )
                f.write(f"Segment: {seg.name}\n")
                f.write(f"CIDR: {seg.cidr}\n")
                f.write(f"Network: {getattr(seg, 'network', '-')}\n")
                f.write(f"Broadcast: {getattr(seg, 'broadcast', '-')}\n")
                f.write(f"Available Hosts: {getattr(seg, 'hosts', '-')}\n\n")
                f.write(f"Total Nodes: {len(seg.nodes)}\n")
                f.write(f"Total Traffic Flows: {len(seg.traffic)}\n\n")
                f.write("Traffic Classification:\n")
                for k, v in classification.items():
                    f.write(f"  {k}: {v}\n")
                f.write("\nNodes:\n")
                for node in seg.nodes:
                    f.write(
                        f"  {node.ip} | MAC: {node.mac or 'N/A'} | Status: {node.status}\n"
                    )
            QMessageBox.information(self, "Success", f"Report exported to {path}")

    def closeEvent(self, event):
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait(2000)
        if self.discover_thread and self.discover_thread.isRunning():
            self.discover_thread.wait(2000)
        event.accept()


class AlertDetailDialog(QDialog):
    def __init__(self, alert, parent=None):
        super().__init__(parent)
        self.alert = alert
        self.setWindowTitle("Alert Details")
        self.setFixedWidth(600)
        layout = QVBoxLayout(self)

        form = QFormLayout()
        form.addRow("Severity:", QLabel(alert.get("severity", "")))
        form.addRow("Category:", QLabel(alert.get("category", "")))
        form.addRow("Score:", QLabel(str(alert.get("score", 0.0))))
        form.addRow("Time:", QLabel(alert.get("timestamp", "")))
        form.addRow("Description:", QLabel(alert.get("description", "")))
        layout.addLayout(form)

        if alert.get("flow_id"):
            flow_layout = QVBoxLayout()
            flow_layout.addWidget(QLabel("Flow Information:"))
            flow_text = QTextEdit()
            flow_text.setReadOnly(True)
            flow_text.setText(
                f"Flow ID: {alert.get('flow_id')}\n"
                f"Segment: {alert.get('segment_id', 'N/A')}"
            )
            flow_layout.addWidget(flow_text)
            layout.addLayout(flow_layout)

        payload_group = QGroupBox("Payload")
        payload_layout = QVBoxLayout(payload_group)
        self.payload_text = QTextEdit()
        self.payload_text.setReadOnly(True)
        self.payload_text.setStyleSheet(f"""
            QTextEdit {{
                background: {HackerPalette.BACKGROUND};
                color: {HackerPalette.PRIMARY};
                font-family: {HackerPalette.FONT_MONO};
                font-size: 11px;
                border: 1px solid {HackerPalette.BORDER};
                border-radius: {HackerPalette.RADIUS}px;
                padding: 8px;
            }}
        """)
        payload_layout.addWidget(self.payload_text)
        layout.addWidget(payload_group)

        btn_layout = QHBoxLayout()
        btn_fp = QPushButton("Mark False Positive")
        btn_fp.clicked.connect(lambda: self._label("false_positive"))
        btn_tp = QPushButton("Mark True Positive")
        btn_tp.clicked.connect(lambda: self._label("true_positive"))
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_fp)
        btn_layout.addWidget(btn_tp)
        btn_layout.addWidget(btn_close)
        layout.addLayout(btn_layout)

    def set_payload(self, payload: bytes):
        if payload:
            hex_text = payload.hex()
            ascii_text = payload.decode("utf-8", errors="replace")
            display = f"HEX:\n{hex_text}\n\nASCII:\n{ascii_text}"
            self.payload_text.setText(display)
        else:
            self.payload_text.setText("No payload available")

    def _label(self, label: str):
        flow_id = self.alert.get("flow_id")
        if flow_id and self.parent() and hasattr(self.parent(), "storage"):
            self.parent().storage.add_label(flow_id, label)
        self.accept()


def run_gui():
    from os import name, geteuid
    if name != "nt" and geteuid() != 0:
        app = QApplication(sys.argv)
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle("Permission Error")
        msg.setText("Root privileges are required")
        msg.setInformativeText(
            "Root privileges are required for network packet capture.\n\nPlease run:\n\nsudo python3 main.py"
        )
        msg.setStyleSheet(f"""
            QMessageBox {{
                background: {HackerPalette.BACKGROUND};
                color: {HackerPalette.TEXT};
                font-family: {HackerPalette.FONT_MAIN};
                font-size: 13px;
            }}
            QLabel {{
                color: {HackerPalette.TEXT};
                background: transparent;
            }}
            QPushButton {{
                background: {HackerPalette.PRIMARY_DIM};
                color: {HackerPalette.BACKGROUND};
                border: 1px solid {HackerPalette.PRIMARY};
                border-radius: {HackerPalette.RADIUS}px;
                padding: 8px 16px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            QPushButton:hover {{
                background: {HackerPalette.PRIMARY};
            }}
        """)
        msg.exec()
        sys.exit(1)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
