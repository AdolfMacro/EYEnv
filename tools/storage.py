import sqlite3
import json
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any


class DataStore:
    def __init__(self, db_path: str = "eye_network.db"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        self._ensure_tables(conn)
        return conn

    def _ensure_tables(self, conn: sqlite3.Connection):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                segment_id TEXT,
                source TEXT,
                destination TEXT,
                protocol INTEGER,
                size INTEGER,
                timestamp TEXT,
                classification TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS features (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER,
                features TEXT,
                feature_names TEXT,
                timestamp TEXT,
                FOREIGN KEY (flow_id) REFERENCES flows(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity TEXT,
                category TEXT,
                description TEXT,
                flow_id INTEGER,
                score REAL,
                timestamp TEXT,
                acknowledged BOOLEAN DEFAULT FALSE
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                baseline TEXT,
                last_seen TEXT,
                flow_count INTEGER DEFAULT 0
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS labels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER,
                label TEXT,
                feedback TEXT,
                timestamp TEXT,
                FOREIGN KEY (flow_id) REFERENCES flows(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS segments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                cidr TEXT,
                interface TEXT,
                netmask TEXT,
                network TEXT,
                broadcast TEXT,
                hosts INTEGER,
                created_at TEXT
            )
        """)
        conn.commit()

    def _initialize_database(self):
        with self._get_connection() as conn:
            pass

    def insert_flow(self, segment_id: str, flow) -> int:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO flows (segment_id, source, destination, protocol, size, timestamp, classification)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        segment_id,
                        getattr(flow, "source", ""),
                        getattr(flow, "destination", ""),
                        self._safe_int(getattr(flow, "protocol", 0)),
                        self._safe_int(getattr(flow, "size", 0)),
                        datetime.now().isoformat(),
                        getattr(flow, "classification", "UNKNOWN"),
                    ),
                )
                conn.commit()
                return cursor.lastrowid

    def insert_features(self, flow_id: int, features: Dict[str, Any], feature_names: List[str]):
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO features (flow_id, features, feature_names, timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        flow_id,
                        json.dumps(features),
                        json.dumps(feature_names),
                        datetime.now().isoformat(),
                    ),
                )
                conn.commit()

    def insert_alert(
        self,
        severity: str,
        category: str,
        description: str,
        flow_id: Optional[int] = None,
        score: float = 0.0,
    ):
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO alerts (severity, category, description, flow_id, score, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        severity,
                        category,
                        description,
                        flow_id,
                        score,
                        datetime.now().isoformat(),
                    ),
                )
                conn.commit()
                return cursor.lastrowid

    def upsert_profile(self, ip: str, baseline: Dict[str, Any], flow_count: int):
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO profiles (ip, baseline, last_seen, flow_count)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        baseline = excluded.baseline,
                        last_seen = excluded.last_seen,
                        flow_count = excluded.flow_count
                    """,
                    (ip, json.dumps(baseline), datetime.now().isoformat(), flow_count),
                )
                conn.commit()

    def get_profile(self, ip: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT baseline, last_seen, flow_count FROM profiles WHERE ip = ?",
                    (ip,),
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "baseline": json.loads(row["baseline"]),
                        "last_seen": row["last_seen"],
                        "flow_count": row["flow_count"],
                    }
                return None

    def get_recent_flows(self, segment_id: str, limit: int = 1000) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT * FROM flows
                    WHERE segment_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (segment_id, limit),
                )
                return [dict(row) for row in cursor.fetchall()]

    def get_features_for_flow(self, flow_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "SELECT features, feature_names FROM features WHERE flow_id = ?",
                    (flow_id,),
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "features": json.loads(row["features"]),
                        "feature_names": json.loads(row["feature_names"]),
                    }
                return None

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    SELECT * FROM alerts
                    ORDER BY timestamp DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                return [dict(row) for row in cursor.fetchall()]

    def acknowledge_alert(self, alert_id: int):
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    "UPDATE alerts SET acknowledged = TRUE WHERE id = ?",
                    (alert_id,),
                )
                conn.commit()

    def add_label(self, flow_id: int, label: str, feedback: str = ""):
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO labels (flow_id, label, feedback, timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    (flow_id, label, feedback, datetime.now().isoformat()),
                )
                conn.commit()

    def get_labels(self) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT * FROM labels ORDER BY timestamp DESC")
                return [dict(row) for row in cursor.fetchall()]

    def insert_segment(self, segment) -> int:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO segments (name, cidr, interface, netmask, network, broadcast, hosts, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        getattr(segment, "name", ""),
                        getattr(segment, "cidr", ""),
                        getattr(segment, "interface", None),
                        getattr(segment, "netmask", None),
                        getattr(segment, "network", None),
                        getattr(segment, "broadcast", None),
                        getattr(segment, "hosts", None),
                        datetime.now().isoformat(),
                    ),
                )
                conn.commit()
                return cursor.lastrowid

    def get_segments(self) -> List[Dict[str, Any]]:
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT * FROM segments ORDER BY created_at DESC")
                return [dict(row) for row in cursor.fetchall()]

    def _safe_int(self, value, default=0):
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
