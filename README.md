# DHCP Packet Analyzer & Visualizer

A lightweight networking tool that captures and analyzes DHCP traffic in real time using **C++ (libpcap)** and visualizes events via a **Python Flask UI**.

## Features
- Live capture of DHCP packets (DISCOVER / OFFER / REQUEST / ACK / RELEASE)
- Extraction of transaction ID, client MAC, IP addresses
- JSON-lines logging for easy processing
- Web-based UI for live event visualization
- macOS-friendly implementation

## Architecture
C++ (libpcap capture)
↓
events.log (JSON)
↓
Python Flask UI

## Build & Run (macOS)
clang++ -std=c++17 -O2 -o dhcp_capture src/dhcp_capture.cpp -lpcap
sudo ./dhcp_capture en0 events.log

## Run UI
python3 -m venv venv
source venv/bin/activate
pip install flask
python ui/app.py

## Future Enhancement
- DHCP hostname parsing
- Passive ARP-based device discovery
- Real-time WebSocket updates
- Offline PCAP analysis
- Vendor (OUI) identification

## Author
Subasish Bhatta
