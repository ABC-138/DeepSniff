import os
import importlib
import curses
from scapy.all import sniff, wrpcap
import threading
import time
import logging

## Set up logging- By setting the level to logging.DEBUG, you allow messages of all severity levels 
#(DEBUG, INFO, WARNING, ERROR, and CRITICAL) to be logged. Keep in mind that logging everything, 
#Especially at the DEBUG level, can generate a large amount of log data.
logging.basicConfig(filename='sniffer_log.txt', level=logging.ERROR,
                    format='%(asctime)s [%(levelname)s]: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

def check_scapy_installation():
    try:
        importlib.import_module('scapy')
    except ImportError:
        print("Scapy is not installed. Please install it using the following command:")
        print("pip install scapy")
        exit()

def create_ascii_banner(text):
    banner = ""
    for char in text.upper():
        if char.isalpha():
            banner += f" {char} "
        else:
            banner += char
    return banner

def display_ascii_banner(stdscr, text):
    stdscr.clear()
    ascii_banner = create_ascii_banner(text)
    stdscr.addstr(0, 0, ascii_banner)
    stdscr.addstr(10, 0, "Press any key to start the packet sniffer.")
    stdscr.refresh()
    stdscr.getch()

def save_packets(stdscr, packets):
    stdscr.clear()
    stdscr.addstr(0, 0, "Packet Sniffer - Save Captured Packets")
    stdscr.addstr(2, 0, "Enter the name for the output report (.pcap): ")
    stdscr.refresh()

    curses.echo()

    output_filename = stdscr.getstr(3, 0).decode('utf-8').strip()

    if not output_filename.endswith(".pcap"):
        output_filename += ".pcap"

    while os.path.exists(output_filename):
        stdscr.clear()
        stdscr.addstr(0, 0, f"The file '{output_filename}' already exists.")
        stdscr.addstr(1, 0, "Do you want to overwrite it, choose a different filename, or cancel? (O/D/C): ")
        stdscr.refresh()

        choice = stdscr.getch()

        if choice in [ord('O'), ord('o')]:
            break
        elif choice in [ord('D'), ord('d')]:
            stdscr.clear()
            stdscr.addstr(0, 0, "Enter a different name for the output report (.pcap): ")
            stdscr.refresh()
            output_filename = stdscr.getstr(1, 0).decode('utf-8').strip()
            if not output_filename.endswith(".pcap"):
                output_filename += ".pcap"
        elif choice in [ord('C'), ord('c')]:
            curses.noecho()
            return

    wrpcap(output_filename, packets)

    stdscr.clear()
    stdscr.addstr(0, 0, f"Captured {len(packets)} packets.")
    stdscr.addstr(2, 0, f"Captured packets saved to {output_filename}")
    stdscr.addstr(4, 0, "Press any key to exit.")
    stdscr.refresh()
    stdscr.getch()

def save_on_interrupt(stdscr, packets, scan_duration):
    try:
        stdscr.clear()
        stdscr.addstr(0, 0, "Sniff interrupted. Do you want to save captured packets? (Enter 'Y' or 'N'): ")
        stdscr.refresh()

        choice = stdscr.getch()

        if choice in [ord('Y'), ord('y')]:
            save_packets(stdscr, packets)

    except KeyboardInterrupt:
        pass

def packet_callback(packet, packets):
    packets.append(packet)

def packet_sniffer(stdscr, scan_duration, packet_count):
    packets = []

    try:
        stdscr.clear()
        stdscr.addstr(0, 0, "Do you want to start a packet capture? (Enter 'Y' or 'N'): ")
        stdscr.refresh()

        choice = stdscr.getch()

        if not (choice in [ord('Y'), ord('y')]):
            stdscr.clear()
            stdscr.addstr(0, 0, "Sniff aborted. Press any key to exit.")
            stdscr.refresh()
            stdscr.getch()
            return

        stdscr.clear()
        stdscr.addstr(0, 0, "Choose sniff type:")
        stdscr.addstr(2, 0, "1. Time-based")
        stdscr.addstr(3, 0, "2. Packet-based")
        stdscr.refresh()

        choice = stdscr.getch()

        if choice in [ord('1')]:
            stdscr.clear()
            stdscr.addstr(0, 0, "Do you want to sniff for the default 60 seconds? (Enter 'Y' or 'N'): ")
            stdscr.refresh()

            choice = stdscr.getch()

            if not (choice in [ord('Y'), ord('y')]):
                scan_duration = get_valid_scan_duration(stdscr)
            else:
                scan_duration = 60

        elif choice in [ord('2')]:
            packet_count = get_valid_packet_count(stdscr)
            if packet_count is None:
                return  # Abort the sniff

        else:
            stdscr.clear()
            stdscr.addstr(0, 0, "Invalid choice. Sniff aborted. Press any key to exit.")
            stdscr.refresh()
            stdscr.getch()
            return

        stdscr.clear()
        stdscr.addstr(0, 0, f"Sniffing Deeply. Press Ctrl-C to stop the scan.")
        stdscr.refresh()

        if scan_duration:
            sniff(prn=lambda x: packet_callback(x, packets), store=0, timeout=scan_duration)
        elif packet_count:
            sniff(prn=lambda x: packet_callback(x, packets), store=0, count=packet_count)

        save_on_interrupt(stdscr, packets, scan_duration)

    except KeyboardInterrupt:
        save_on_interrupt(stdscr, packets, scan_duration)

def get_valid_packet_count(stdscr):
    for _ in range(3):
        stdscr.clear()
        stdscr.addstr(0, 0, "Enter the desired number of packets to capture (up to 1,000,000): ")
        stdscr.refresh()

        curses.echo()

        try:
            packet_count_input = stdscr.getstr(1, 0).decode('utf-8').strip()
            packet_count = int(packet_count_input) if packet_count_input.isdigit() else None

            if packet_count is not None and 0 < packet_count <= 1000000:
                return packet_count
            else:
                stdscr.clear()
                stdscr.addstr(0, 0, "Invalid input. Please enter a number between 1 and 1,000,000.")
                stdscr.refresh()
                stdscr.getch()
        except ValueError:
            pass

    stdscr.clear()
    stdscr.addstr(0, 0, "Please Enter Valid Input and Try Again")
    stdscr.refresh()
    stdscr.getch()
    return None

def get_valid_scan_duration(stdscr):
    for _ in range(3):
        stdscr.clear()
        stdscr.addstr(0, 0, "Enter the desired sniff duration in minutes (up to 85 minutes - No decimals): ")
        stdscr.refresh()

        curses.echo()

        try:
            scan_duration_input = stdscr.getstr(1, 0).decode('utf-8').strip()
            scan_duration = int(scan_duration_input) * 60 if scan_duration_input.isdigit() else None

            if scan_duration is not None and 0 < scan_duration <= 85 * 60:
                return scan_duration
            else:
                stdscr.clear()
                stdscr.addstr(0, 0, "Invalid input. Please enter a number between 1 and 85- No Decimals.")
                stdscr.refresh()
                stdscr.getch()
        except ValueError:
            pass

    return 60

if __name__ == "__main__":
    check_scapy_installation()

    stdscr = curses.initscr()
    curses.noecho()
    curses.cbreak()

    try:
        display_ascii_banner(stdscr, "DeepSniff_1.0 - ABC")
        packet_sniffer(stdscr, 0, 0)

    finally:
        curses.nocbreak()
        curses.echo()
        curses.endwin()
