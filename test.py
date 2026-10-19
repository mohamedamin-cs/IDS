import unittest

from scapy.all import IP, TCP

from TrafficAnalyzer import TrafficAnalyzer
from DetectionEngine import DetectionEngine


class TestIDS(unittest.TestCase):
    def setUp(self):
        self.analyzer = TrafficAnalyzer()
        self.engine = DetectionEngine()

        # Fit a synthetic baseline so anomaly detection can run.
        # This is test data, not a real network baseline.
        baseline = [
            [400, 8.0, 3200.0],
            [450, 9.0, 4050.0],
            [500, 10.0, 5000.0],
            [550, 11.0, 6050.0],
            [600, 12.0, 7200.0],
            [650, 13.0, 8450.0],
            [700, 14.0, 9800.0],
            [750, 15.0, 11250.0],
        ]

        self.engine.train_anomaly_detector(baseline)

    def make_features(
        self,
        packet_size=500,
        packet_rate=10.0,
        byte_rate=5000.0,
        tcp_flags=0x10,
        window_size=8192,
    ):
        return {
            "packet_size": packet_size,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "tcp_flags": tcp_flags,
            "window_size": window_size,
        }

    def signature_rules(self, features):
        threats = self.engine.detect_threats(features)
        return {
            threat.get("rule")
            for threat in threats
            if threat.get("type") == "signature"
        }

    def test_normal_traffic(self):
        features = self.make_features()

        detected = self.signature_rules(features)

        self.assertEqual(detected, set())

    def test_syn_flood_heuristic(self):
        features = self.make_features(
            packet_size=60,
            packet_rate=150.0,
            byte_rate=9000.0,
            tcp_flags=0x02,
        )

        detected = self.signature_rules(features)

        self.assertIn("syn_flood", detected)

    def test_port_scan_heuristic(self):
        features = self.make_features(
            packet_size=60,
            packet_rate=80.0,
            byte_rate=4800.0,
            tcp_flags=0x10,
        )

        detected = self.signature_rules(features)

        self.assertIn("port_scan", detected)

    def test_slow_syn_is_not_syn_flood(self):
        features = self.make_features(
            packet_size=60,
            packet_rate=5.0,
            byte_rate=300.0,
            tcp_flags=0x02,
        )

        detected = self.signature_rules(features)

        self.assertNotIn("syn_flood", detected)

    def test_large_packet_is_not_port_scan_heuristic(self):
        features = self.make_features(
            packet_size=500,
            packet_rate=80.0,
            byte_rate=40000.0,
            tcp_flags=0x10,
        )

        detected = self.signature_rules(features)

        self.assertNotIn("port_scan", detected)

    def test_scapy_packet_analysis(self):
        packet = (
            IP(src="192.0.2.10", dst="192.0.2.20")
            / TCP(sport=12345, dport=80, flags="S")
        )

        features = self.analyzer.analyze_packet(packet)

        self.assertIsNotNone(features)
        self.assertEqual(features["packet_size"], len(packet))
        self.assertEqual(features["tcp_flags"], 0x02)

    def test_non_tcp_packet_is_ignored(self):
        from scapy.all import UDP

        packet = (
            IP(src="192.0.2.10", dst="192.0.2.20")
            / UDP(sport=12345, dport=53)
        )

        features = self.analyzer.analyze_packet(packet)

        self.assertIsNone(features)


if __name__ == "__main__":
    unittest.main(verbosity=2)
