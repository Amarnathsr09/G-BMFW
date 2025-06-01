import time
from logger import log_event

sample_packets = [
    {"source_ip": "192.168.0.10", "destination_ip": "8.8.8.8", "port": 80, "protocol": "TCP"},
    {"source_ip": "192.168.0.11", "destination_ip": "10.0.0.5", "port": 22, "protocol": "SSH"},
    {"source_ip": "10.0.0.2", "destination_ip": "192.168.0.12", "port": 443, "protocol": "HTTPS"},
    {"source_ip": "172.16.0.3", "destination_ip": "8.8.4.4", "port": 53, "protocol": "UDP"},
]

def start_packet_filtering():
    print("Packet Filtering Module Started...\n")
    log_event("Packet Filtering Started")
    for packet in sample_packets:
        action = filter_packet(packet)
        status = f"Packet from {packet['source_ip']} -> {packet['destination_ip']} [{packet['protocol']}:{packet['port']}] -> {action}"
        print(status)
        log_event(status)
        time.sleep(1)
    log_event("Packet Filtering Completed")
    print("\nPacket Filtering Completed.")

def filter_packet(packet):
    if packet["port"] == 22:
        return "Denied"
    return "Approved"
