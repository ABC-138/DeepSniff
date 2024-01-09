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
