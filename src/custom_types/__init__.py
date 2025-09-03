class TrafficData:
    def __init__(self, source_ip, destination_ip, protocol, size):
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol
        self.size = size

class IncidentReport:
    def __init__(self, incident_type, description, timestamp):
        self.incident_type = incident_type
        self.description = description
        self.timestamp = timestamp