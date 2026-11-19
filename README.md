# CodeAlpha_NetworkSniffer

A lightweight Python-based network packet sniffer developed using the `Scapy` library as part of the **CodeAlpha Cyber Security Internship**.

## Features
- **Real-time Packet Capture:** Monitors live network traffic across active interfaces.
- **Protocol Identification:** Distinguishes between `TCP`, `UDP`, and `ICMP` packets.
- **IP & Port Tracking:** Extracts and displays source/destination IP addresses and port numbers.
- **Payload Inspection:** Decodes and filters printable payload data from captured packets.

## Prerequisites
- Python 3.x
- Scapy (`pip install scapy` or `sudo apt install python3-scapy`)
- Root / Administrator privileges (required for raw socket access)

## Usage
```bash
git clone [https://github.com/merONE1/CodeAlpha_NetworkSniffer.git](https://github.com/merONE1/CodeAlpha_NetworkSniffer.git)
cd CodeAlpha_NetworkSniffer
sudo python3 sniffer.py
