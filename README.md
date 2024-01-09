# DeepSniff - Packet Sniffer with ASCII Interface

## Overview

DeepSniff is a packet sniffer tool that allows users to capture network packets and save them to a .pcap file. The tool provides an ASCII interface for interaction and supports both time-based and packet-based sniffing.


1. **Dependency on Scapy:**
   - DeepSniff relies on the Scapy library. Ensure that Scapy is installed before running the script by using the following command:
     ```bash
     pip install scapy
     ```

2. **Console Interface Limitations:**
   - The current implementation uses a console-based interface with curses, which might be less familiar to some users.

3. **Limited Configuration Options:**
   - DeepSniff has limited configuration options at this time. All .pcap files will be saved to home folder. 

4. **Limited Error Handling:**
   - While basic error handling is implemented, more comprehensive handling will be added in the future for improved user experience and troubleshooting. Pay attention to potential exceptions related to file operations and input validation.

5. **Logging Level:**
   - The script's logging level is set to `logging.ERROR`. Users interested in modifying the logging behavior should refer to the logging comments within deepsniff.py.

6. **Single-Threaded Execution:**
   - DeepSniff currently uses a single-threaded approach for packet sniffing. Potential users may want to explore asynchronous or multi-threaded alternatives for more efficient packet processing in specific use cases.

7. **Security Considerations:**
   - DeepSniff captures network packets, and users should exercise caution to ensure ethical use. Always obtain proper authorization before using packet sniffers, be aware of potential legal implications, and respect privacy concerns.
   - DO NOT USE THIS TOOL FOR MALICIOUS PURPOSES

## Disclaimer:
DeepSniff is provided as-is and does not guarantee the security or privacy of network communications. Users are responsible for using this tool in compliance with applicable laws and ethical standards. The authors disclaim any liability for unauthorized or inappropriate use of DeepSniff.
DeepSniff has only been tested on Linux systems


## Features

- **User-Friendly Interface:** DeepSniff offers a simple ASCII interface with interactive prompts for ease of use.

- **Time-Based and Packet-Based Sniffing:** Users can choose between time-based and packet-based sniffing modes, making it flexible for various use cases.

- **Save Captured Packets:** DeepSniff prompts users to save the captured packets, providing options to confirm overwriting existing files or choose a different filename.

- **Error Logging:** The tool logs errors and events to a 'sniffer_log.txt' file for debugging and tracking purposes.

## Requirements

- Python 3
- Scapy library
  

## Installation

1. **Git Clone:**
   ```bash
   git clone https://github.com/ABC-138/DeepSniff.git
2. **Install Scapy:**
   ```bash
   pip install scapy
3. **Run DeepSniff:**
   ```bash
   sudo python3 deepsniff.py

   
4. Follow the on-screen prompts to start a packet capture.
5. Choose the sniffing type (time-based or packet-based).
6. Save captured packets when prompted.
7. View the summary and press any key to exit.
8. You can then open the .pcap file to analyze

## Notes

- Press Ctrl-C to stop the packet capture at any time.
- Ensure proper permissions for capturing network packets.

## Author

Bort

