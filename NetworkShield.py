#Network Shield - tool to monitor and protect your network
# requires: scapy, netifaces

import netifaces
from scapy.all import *
import winreg as wr
import os
import hashlib
from collections import defaultdict
import time

# Dictionaries to track requests
syn_count = defaultdict(int)
rst_response_count = defaultdict(int)
unusual_flag_count = defaultdict(int)
icmp_request_count = defaultdict(int)
arp_request_count = defaultdict(int)
TIME_WINDOW = 10  # seconds
MAX_ICMP_REQUESTS = 50  # arbitrary threshold
MAX_ARP_REQUESTS = 100  # arbitrary threshold

def get_connection_name_from_guid(iface_guids):
    iface_names = ['(unknown)' for i in range(len(iface_guids))]
    reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
    reg_key = wr.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
    for i in range(len(iface_guids)):
        try:
            reg_subkey = wr.OpenKey(reg_key, iface_guids[i] + r'\Connection')
            iface_names[i] = wr.QueryValueEx(reg_subkey, 'Name')[0]
        except FileNotFoundError:
            pass
    return iface_names

def list_interfaces():
    interfaces = netifaces.interfaces()
    print("Available network interfaces:")
    for idx, iface in enumerate(get_connection_name_from_guid(interfaces)):
        print(f"{idx}: {iface}")
    return interfaces

def select_interface(interfaces):
    while True:
        try:
            choice = int(input("Select interface number: "))
            if 0 <= choice < len(interfaces):
                if os.name != 'nt':     # Non-Windows systems
                    return interfaces[choice]   
                return get_connection_name_from_guid(interfaces)[choice]
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

def packet_callback(packet):
    # print(packet.summary())
    if packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        if tcp_flags == 2:  # SYN scan
            print("Possible SYN scan detected.")
        elif tcp_flags == 18:  # SYN-ACK
            print("SYN-ACK packet observed.")
        elif tcp_flags == 1:  # FIN scan
            print("Possible FIN scan detected.")
        elif tcp_flags == 4:  # RST scan
            print("Possible RST scan detected.")
        elif tcp_flags == 0:  # NULL scan
            print("Possible NULL scan detected.")
        elif tcp_flags & 32:  # URG scan
            print("Possible Xmas scan detected.")
    elif packet.haslayer(ICMP):
        src_ip = packet[IP].src
        icmp_request_count[src_ip] += 1
        
        # Check if this source has exceeded the threshold
        if icmp_request_count[src_ip] > MAX_ICMP_REQUESTS:
            print(f"[!] ICMP Ping Sweep detected from {src_ip}")
            # Reset count after alerting to avoid spamming
            icmp_request_count[src_ip] = 0 
    elif packet.haslayer(ARP):
        src_mac = packet[ARP].hwsrc
        arp_request_count[src_mac] += 1
        
        if arp_request_count[src_mac] > MAX_ARP_REQUESTS:
            print(f"[!] ARP Scan detected from MAC: {src_mac}")
            arp_request_count[src_mac] = 0
    elif packet.haslayer(Raw):
        payload = packet[Raw].load
        # Check for common file upload signatures in HTTP POST requests
        if packet.haslayer(TCP) and packet.haslayer(IP):
            if b"POST" in payload and (b"Content-Type: multipart/form-data" in payload or b"Content-Disposition: form-data" in payload):
                print("Possible file upload detected in HTTP POST request.")
                # Attempt to extract and hash file content (basic approach)
                # Find start of file content (after double CRLF)
                split_marker = b"\r\n\r\n"
                if split_marker in payload:
                    file_data = payload.split(split_marker, 1)[1]
                    file_hash = hashlib.sha256(file_data).hexdigest()
                    print(f"SHA256 hash of uploaded file content: {file_hash}")
    # Check for HTTP or HTTPS requests
    elif packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        if b"HTTP/" in payload:
            print("HTTP request detected.")
        elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
            print("Possible HTTPS traffic detected.")
        

def main():
    interfaces = list_interfaces()
    iface = select_interface(interfaces)
    print(f"Sniffing on interface: {iface}")
    sniff(iface=iface, prn=packet_callback, store=False)

if __name__ == "__main__":
    main()