import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

class DataVisualizer:
    def __init__(self):
        self.traffic_data = None
        self.incidents = None
        self.df = None
        
    def create_visualization(self, traffic_data, incidents):
        self.traffic_data = traffic_data
        self.incidents = incidents
        self.df = pd.DataFrame(traffic_data)
        
    def generate_report(self):
        if not self.traffic_data:
            return "No data to generate report"
            
        # Basic statistics
        stats = self.traffic_data[0]['stats']
        
        report = f"""
Network Traffic Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
=====================================

Traffic Summary:
---------------
Total Packets: {stats['total_packets']}
Unique Sources: {stats['unique_sources']}
Unique Destinations: {stats['unique_destinations']}
Average Packet Size: {stats['avg_packet_size']:.2f} bytes
Maximum Packet Size: {stats['max_packet_size']} bytes

Protocol Distribution:
--------------------
"""
        for protocol, count in stats['protocols'].items():
            report += f"{protocol}: {count} packets\n"
            
        report += "\nSecurity Incidents:\n------------------\n"
        if self.incidents:
            for incident in self.incidents:
                report += f"- {incident['severity']} - {incident['type']}: {incident['details']}\n"
        else:
            report += "No security incidents detected.\n"
            
        return report
    
    def create_graphs(self):
        if not self.df.empty:
            # 1. Traffic Volume Over Time
            plt.figure(figsize=(12, 6))
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
            traffic_over_time = self.df.groupby(self.df['timestamp'].dt.minute)['length'].sum()
            plt.plot(traffic_over_time.index, traffic_over_time.values)
            plt.title('Network Traffic Volume Over Time')
            plt.xlabel('Time (minutes)')
            plt.ylabel('Bytes')
            plt.savefig('traffic_volume.png')
            plt.close()
            
            # 2. Protocol Distribution Pie Chart
            fig = px.pie(self.df, names='protocol', title='Protocol Distribution')
            fig.write_html('protocol_distribution.html')
            
            # 3. Source IP Distribution
            top_sources = self.df['src'].value_counts().head(10)
            fig = px.bar(x=top_sources.index, y=top_sources.values,
                        title='Top 10 Source IPs',
                        labels={'x': 'Source IP', 'y': 'Packet Count'})
            fig.write_html('top_sources.html')
            
    def display_results(self):
        # Generate and save graphs
        self.create_graphs()
        
        # Generate and print report
        report = self.generate_report()
        print(report)
        
        # Save report to file
        with open('network_analysis_report.txt', 'w') as f:
            f.write(report)
            
        print("\nFiles generated:")
        print("- traffic_volume.png (Traffic volume over time)")
        print("- protocol_distribution.html (Interactive protocol distribution chart)")
        print("- top_sources.html (Interactive top sources chart)")
        print("- network_analysis_report.txt (Detailed analysis report)")
        
        if self.incidents:
            print("\n🚨 Security Incidents Detected! Check security_incidents.log for details.")
