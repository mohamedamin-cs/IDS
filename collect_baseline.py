
import csv
import math
from scapy.all import sniff, IP, TCP
from TrafficAnalyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer()
output_file = "normal_traffic.csv"


def collect_packet(packet):
    if IP not in packet or TCP not in packet:
        return

    features = analyzer.analyze_packet(packet)
    if not features:
        return

    row = [
        features["packet_size"],
        features["packet_rate"],
        features["byte_rate"],
    ]

    # Skip invalid values such as NaN or infinity.
    if not all(math.isfinite(float(value)) for value in row):
        return

    with open(output_file, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(row)

    print("Collected:", row)


print("Collecting baseline traffic for 120 seconds...")
print("Use your computer normally; avoid deliberately generating attacks.")

sniff(
    iface="wlan0",
    filter="tcp",
    prn=collect_packet,
    store=False,
    timeout=120,
)

print(f"Finished. Features saved to {output_file}")
