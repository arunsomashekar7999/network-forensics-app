
from analyzer import TrafficAnalyzer
from detector import IncidentDetector
from visualizer import DataVisualizer
from web_interface import WebInterface

def main():
    # Initialize components
    traffic_analyzer = TrafficAnalyzer()
    incident_detector = IncidentDetector()
    data_visualizer = DataVisualizer()
    
    print("Starting Network Forensics Web Application...")
    print("Initializing components...")
    
    # Initialize web interface
    web_interface = WebInterface(traffic_analyzer, incident_detector, data_visualizer)
    
    print("\nWeb application is running!")
    print("Open your web browser and navigate to: http://127.0.0.1:8050")
    print("Press Ctrl+C to stop the application")
    
    # Run the web application
    web_interface.run(debug=True)

if __name__ == "__main__":
    main()