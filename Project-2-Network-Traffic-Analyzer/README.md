# Network Traffic Analyzer / Packet Analysis

## Overview
A Python-based network traffic analyzer that reads saved packet capture files and extracts useful information for basic network security analysis.

## Features
- Reads `.pcapng` packet capture files using Scapy.
- Extracts source and destination IP addresses.
- Identifies TCP, UDP, ICMP, and other IP traffic.
- Displays source and destination ports when available.
- Counts packets by protocol.
- Counts TCP SYN packets by source IP address.
- Generates a text report containing analysis results.

## Technologies Used
- Python 3
- Scapy
- Basic networking and TCP/IP concepts

## Project Structure
- `analyzer.py` — Main analysis script.
- `sample.pcapng` — Sample packet capture used for testing.
- `analysis_report.txt` — Generated analysis report.

## How to Run
1. Install Python 3.
2. Install Scapy:
   `py -m pip install scapy`
3. Place a packet capture file named `sample.pcapng` in the project folder.
4. Run the script from the portfolio's root directory:
   `py Project-2-Network-Traffic-Analyzer/analyzer.py`

## Learning Outcomes
- Understanding packet captures and network protocols.
- Extracting IP addresses and transport-layer ports.
- Analyzing TCP flags.
- Summarizing network traffic and generating reports.

## Limitations
- Analyzes saved packet captures; it does not perform live packet capture.
- TCP SYN counts alone cannot establish whether traffic is malicious.
- Results depend on the contents of the supplied capture file.

## Disclaimer
This project is intended for educational purposes and offline analysis of packet captures.

### Wireshark Investigation

- **Tool:** Wireshark
- **Capture file:** `sample.pcapng`
- **Display filter:** `tcp.port == 2000`
- **Finding:** Followed a TCP stream and identified the readable message `hello`.
- **Learning outcome:** Learned how to filter TCP traffic, examine TCP flags, and follow a TCP stream to inspect application data.

**Note:** This was an educational analysis of a sample packet capture.