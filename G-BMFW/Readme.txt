G-BMFW: GUI-Based Modular Firewall System

G-BMFW is a customizable, GUI-based modular firewall developed during an internship at CYFOTOK. 
This Python-powered system combines packet filtering, proxy services, and real-time monitoring into a user-friendly interface. 
The goal is to help administrators efficiently inspect, control, and secure network traffic.

Features :

Packet Filtering:

Inspects data packets in real time
GUI to allow/deny traffic based on:
Source IP
Destination IP
Port
Displays packet logs live on screen

Proxy Services:

Forward Proxy (Port 8888)
Routes outbound HTTP/HTTPS traffic to the internet

Reverse Proxy (Port 8080)
Manages and forwards incoming traffic to internal servers

HTTPS/SSL Proxy (Port 8443)
Intercepts and decrypts encrypted traffic securely

Logging & Alerts:

Centralized logging of all activities (packet, proxy, etc.)
Filter logs by module or severity
Live log viewer for monitoring activity
Alerts for suspicious or abnormal behavior

Real-Time GUI Dashboard:

Developed using Tkinter
Displays active modules
Live packet activity and control
Status updates and system descriptions




Installation & Usage :

Prerequisites
Python 3.10 or higher

Required packages:

pip install pillow

Run the App :

python main.py

Use the sidebar to enable packet filtering, proxies, and view logs.
Live updates and statuses appear in the main window.

Project Structure:

G-BMFW/
├── main.py                  # Main GUI Launcher
├── packet_filter.py         # Packet filtering logic
├── proxy_services.py        # Forward, Reverse, and SSL proxy
├── logger.py                # Centralized logging and alerts
├── data/
│   └── logs.txt             # Log file storage
└── quit_icon.jpg            # GUI icon (optional)

License:

This project is for educational and research purposes.

