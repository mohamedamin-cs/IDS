from collections import defaultdict
from scapy.all import TCP, IP

class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda : {
            'packet_count' : 0,
            'byte_count' : 0,
            'start_time' : None,
            'last_time' : None
        })
    def analyze_packet(self, packet):
        if TCP in packet and IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time
            if stats['start_time'] == None:
                stats['start_time'] = current_time
            stats['last_time'] = current_time
            return self.extract_features(packet, stats)


    def extract_features(self, packet, stats):
        duration = stats['last_time'] - stats['start_time']

    # Avoid division by zero for new flows
        if duration > 0:
            packet_rate = stats['packet_count'] / duration
            byte_rate = stats['byte_count'] / duration
        else:
            packet_rate = 0.0
            byte_rate = 0.0

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }
