# -------------------------------------------------
# CodeAlpha Task 1 - Basic Network Sniffer
# Author: [Zwivhuya Tshutshu]
# Internship: CodeAlpha Cyber Security Internship

# Features:
#   ✅ Capture live packets
#   ✅ Display in a PrettyTable
#   ✅ Save logs to CSV file
#   ✅ Show live graph of protocol usage
# -------------------------------------------------


# Importing libraries
from scapy.all import sniff, IP, TCP, UDP, ICMP   # Scapy is used to capture/analyze packets (packet capture)
from prettytable import PrettyTable              # For clean table-like/console output
import datetime                                    # To add timestamps
import csv                                         # To save logs to CSV                                 
import matplotlib.pyplot as plt                     # For live graphing   
from collections import Counter                   # To count protocol occurrences



# Open a CSV file in write mode (setup csv)
csv_file = open("packet_logs.csv", "w", newline="")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["Time", "Source IP", "Destination IP", "Protocol", "Payload Size"])


# Create a table structure for output (setup prettytable)
table = PrettyTable()
table.field_names = ["Time", "Source IP", "Destination IP", "Protocol", "Payload Size"]


# Setup for live graphing
protocol_counter = Counter()
plt.ion()  # Turn on interactive mode so the graph updates live


# Function to analyze each packet (packet analyzer function)
def packet_analyzer(packet):
    """
    Extracts useful information from each captured packet.
    """
    try:
        if IP in packet:  # Only analyze packets that contain an IP layer
            src = packet[IP].src        # Source IP address
            dst = packet[IP].dst        # Destination IP address
            proto = "OTHER"             # Default protocol label
            size = len(packet)          # Total size of the packet (packet/payload size)

            # Check which protocol is being used (TCP/UDP/ICMP) Identify protocol
            if packet.haslayer(TCP):
                proto = "TCP"
            elif packet.haslayer(UDP):
                proto = "UDP"
            elif packet.haslayer(ICMP):
                proto = "ICMP"
                


            # Add row to table with extracted info
            table.add_row([
                datetime.datetime.now().strftime("%H:%M:%S"),  # Current time
                src, dst, proto, size
            ])
            
            
            # Save packet details into CSV file
            csv_writer.writerow([datetime.datetime.now().strftime("%H:%M:%S"), src, dst, proto, size])


            # Count protocols for graph
            protocol_counter[proto] += 1

            # Update live graph every 5 packets
            if sum(protocol_counter.values()) % 5 == 0:
                plt.clf()
                plt.bar(protocol_counter.keys(), protocol_counter.values(), color='skyblue')
                plt.title("Live Protocol Traffic Count")
                plt.xlabel("Protocol")
                plt.ylabel("Packet Count")
                plt.pause(0.1)



            # Print the table row immediately
            print(table)
            table.clear_rows()  # Clear rows so we only print one at a time
    except Exception as e:
        print(f"Error: {e}")

# Function to start sniffer
def start_sniffer(interface=None, packet_count=0):
    """
    Starts the network sniffer.
    :param interface: Network interface (e.g., 'eth0', 'wlan0', 'Wi-Fi')
    :param packet_count: Number of packets to capture (0 = unlimited)
    """
    print("🚀 Starting Network Sniffer...")
    sniff(iface=interface, prn=packet_analyzer, count=packet_count, store=False)

# Run program (main function)
if __name__ == "__main__":
    # Change interface depending on your OS (Wi-Fi/eth0/wlan0)
    start_sniffer(interface=None, packet_count=10)  # Capture 10 packets


# Close CSV file after sniffer stops
csv_file.close()

