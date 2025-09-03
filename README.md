# Network Forensics Dashboard

A real-time network traffic analysis and security monitoring dashboard built with Python and Dash. This application provides live network traffic monitoring, security incident detection, and interactive visualizations.

![Network Forensics Dashboard](dashboard-screenshot.png)

## Live Demo
Access the live demo at: https://network-forensics-app.onrender.com

## Features

- 🌐 **Real-time Network Monitoring**
  - Live packet capture and analysis
  - Protocol distribution visualization
  - Traffic volume tracking

- 🔍 **Security Incident Detection**
  - Automated threat detection
  - Configurable alert thresholds
  - Incident logging and tracking

- 📊 **Interactive Dashboards**
  - Real-time traffic graphs
  - Protocol distribution charts
  - HTTP/HTTPS analysis

- 📁 **File Analysis**
  - PCAP file upload and analysis
  - Log file processing
  - Historical data review

- 🛡️ **Security Features**
  - Traffic anomaly detection
  - Suspicious port monitoring
  - Large packet detection

This project is a network forensics application designed to analyze network traffic, detect security incidents, and visualize insights using powerful forensic tools. 

## Features

- **Traffic Analysis**: Analyze network traffic to identify patterns and anomalies.
- **Incident Detection**: Detect potential security incidents and log them for further investigation.
- **Data Visualization**: Create visual representations of network data and incident reports for easier interpretation.

## Project Structure

```
network-forensics-app
├── src
│   ├── analyzer          # Contains classes and functions for analyzing network traffic
│   ├── detector          # Includes classes for detecting security incidents
│   ├── visualizer        # Handles visualization of insights
│   ├── tools             # Utility functions and classes
│   ├── main.py           # Entry point for the application
│   └── types             # Custom types and data structures
├── requirements.txt      # Lists project dependencies
├── README.md             # Documentation for the project
└── setup.py              # Packaging information
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd network-forensics-app
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

To run the application, execute the following command:
```
python src/main.py
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.