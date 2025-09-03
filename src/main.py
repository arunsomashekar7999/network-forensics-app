
from analyzer import TrafficAnalyzer
from detector import IncidentDetector
from visualizer import DataVisualizer
from web_interface import WebInterface

def create_app():
    # Initialize components
    traffic_analyzer = TrafficAnalyzer()
    incident_detector = IncidentDetector()
    data_visualizer = DataVisualizer()
    
    # Initialize web interface
    web_interface = WebInterface(traffic_analyzer, incident_detector, data_visualizer)
    
    return web_interface.app

def main():
    print("Starting Network Forensics Web Application...")
    print("Initializing components...")
    
    app = create_app()
    
    print("\nWeb application is running!")
    print("Open your web browser and navigate to: http://127.0.0.1:8050")
    print("Press Ctrl+C to stop the application")
    
    # Run the web application
    app.run(debug=True, host='0.0.0.0', port=8050)

# Create the app instance for WSGI servers
app = create_app()

if __name__ == "__main__":
    main()