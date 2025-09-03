import pandas as pd
from datetime import datetime

class IncidentDetector:
    def __init__(self):
        self.thresholds = {
            'large_packet': 9000,  # bytes
            'burst_rate': 1000,    # packets per second
            'suspicious_ports': [22, 23, 3389]  # SSH, Telnet, RDP
        }
        self.incidents = []
        
    def detect_incidents(self, traffic_data):
        if not traffic_data:
            return []
            
        df = pd.DataFrame(traffic_data)
        incidents = []
        
        # 1. Large packet detection
        large_packets = df[df['length'] > self.thresholds['large_packet']]
        for _, pkt in large_packets.iterrows():
            incidents.append({
                'type': 'LARGE_PACKET',
                'severity': 'MEDIUM',
                'details': f"Large packet detected: {pkt['length']} bytes",
                'src': pkt['src'],
                'dst': pkt['dst'],
                'timestamp': pkt['timestamp']
            })
        
        # 2. Suspicious port detection
        suspicious_ports = df[
            df['dst_port'].isin(self.thresholds['suspicious_ports']) |
            df['src_port'].isin(self.thresholds['suspicious_ports'])
        ]
        for _, pkt in suspicious_ports.iterrows():
            incidents.append({
                'type': 'SUSPICIOUS_PORT',
                'severity': 'HIGH',
                'details': f"Suspicious port detected: {pkt['dst_port']}",
                'src': pkt['src'],
                'dst': pkt['dst'],
                'timestamp': pkt['timestamp']
            })
        
        # 3. Traffic burst detection
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        packets_per_second = df.groupby(df['timestamp'].dt.second).size()
        bursts = packets_per_second[packets_per_second > self.thresholds['burst_rate']]
        
        for second, count in bursts.items():
            incidents.append({
                'type': 'TRAFFIC_BURST',
                'severity': 'LOW',
                'details': f"Traffic burst detected: {count} packets/second",
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            
        return incidents
    
    def log_incident(self, incident):
        # Log to file with timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open('security_incidents.log', 'a') as f:
            f.write(f"[{timestamp}] {incident['severity']} - {incident['type']}: {incident['details']}\n")
        
        # Also print to console
        print(f"🚨 INCIDENT DETECTED: {incident['severity']} - {incident['type']}: {incident['details']}")
    def detect_incident(self, traffic_data):
        # Logic to analyze traffic data and detect incidents
        pass

    def log_incident(self, incident_details):
        # Logic to log detected incidents
        pass