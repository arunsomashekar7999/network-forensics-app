import random
import pandas as pd
from datetime import datetime, timedelta
import time

class TrafficAnalyzer:
    def __init__(self):
        self.capture_duration = 10  # seconds to capture
        self.packets = []
        self.protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
        self.common_ports = {
            'HTTP': 80,
            'HTTPS': 443,
            'DNS': 53,
            'SSH': 22,
            'FTP': 21
        }
        
    def generate_mock_traffic(self):
        current_time = datetime.now()
        num_packets = random.randint(50, 100)
        
        packets = []
        for _ in range(num_packets):
            protocol = random.choice(self.protocols)
            src_port = random.choice(list(self.common_ports.values()))
            dst_port = random.choice(list(self.common_ports.values()))
            
            packet_data = {
                'timestamp': (current_time - timedelta(seconds=random.randint(0, 60))).strftime('%Y-%m-%d %H:%M:%S'),
                'src': f'192.168.1.{random.randint(2, 254)}',
                'dst': f'10.0.0.{random.randint(2, 254)}',
                'protocol': protocol,
                'length': random.randint(64, 1500),
                'src_port': src_port,
                'dst_port': dst_port
            }
            packets.append(packet_data)
            
        return sorted(packets, key=lambda x: x['timestamp'])
    
    def analyze_traffic(self):
        # Generate mock traffic data
        traffic_data = self.generate_mock_traffic()
        
        # Convert to pandas DataFrame for analysis
        df = pd.DataFrame(traffic_data)
        
        # Basic statistics
        stats = {
            'total_packets': len(df),
            'unique_sources': len(df['src'].unique()),
            'unique_destinations': len(df['dst'].unique()),
            'protocols': df['protocol'].value_counts().to_dict(),
            'avg_packet_size': df['length'].mean(),
            'max_packet_size': df['length'].max(),
            'traffic_by_src': df.groupby('src')['length'].sum().to_dict()
        }
        
        # Add statistics to each packet
        for packet in traffic_data:
            packet['stats'] = stats
            
        return traffic_data