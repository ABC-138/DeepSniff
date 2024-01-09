# DeepSniff - Packet Sniffer with ASCII Interface

## Overview

DeepSniff is a packet sniffer tool that allows users to capture network packets and save them to a .pcap file. The tool provides an ASCII interface for interaction and supports both time-based and packet-based sniffing.

## Features

- **User-Friendly Interface:** DeepSniff offers a simple ASCII interface with interactive prompts for ease of use.

- **Time-Based and Packet-Based Sniffing:** Users can choose between time-based and packet-based sniffing modes, making it flexible for various use cases.

- **Save Captured Packets:** DeepSniff prompts users to save the captured packets, providing options to confirm overwriting existing files or choose a different filename.

- **Error Logging:** The tool logs errors and events to a 'sniffer_log.txt' file for debugging and tracking purposes.

## Requirements

- Python 3
- Scapy library

## Installation

1. **Install Scapy:**
   ```bash
   pip install scapy

2. **Run DeepSniff:**
   ```bash
   sudo python3 deepsniff.py

   

1. Launch DeepSniff.
2. Follow the on-screen prompts to start a packet capture.
3. Choose the sniffing type (time-based or packet-based).
4. Save captured packets when prompted.
5. View the summary and press any key to exit.
6. You can then open the .pcap file to analyze

## Notes

- Press Ctrl-C to stop the packet capture at any time.
- Ensure proper permissions for capturing network packets.

## Author

Bort

