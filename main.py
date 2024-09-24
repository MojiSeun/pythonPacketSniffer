import sys
import psutil
import base64
import switch as switch
import threading
import keyboard
from scapy.all import *
from scapy.all import get_if_list
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.inet import ICMP, UDP, TCP, IP


print(f"#####################################################################################\n"
      f"#####################################################################################\n"
      f"#####################################################################################\n"
      f"                      WELCOME TO SEUN PACKET SNIFFER APPLICATION\n"
      f"######################################################################################\n"
      f"######################################################################################\n"
      f"######################################################################################\n")
# Ask the user for input
userInput = input("Input desired type of traffic (HTTP, TCP, UDP,ICMP, DNS, TLS): ").upper()

# The Output File that stores captured traffic
filename = f"{userInput}_packet_capture_{time.strftime('%Y%m%d_%H%M%S')}.txt"


# Function to handle TCP, UDP and HTTP packets
def handle_packet(packet) :
    if packet.haslayer(IP) and packet.haslayer(TCP) :
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        raw_packets = bytes(packet)
        with open(filename, 'a') as log :
            log.write(
                f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n Raw packets: {raw_packets.hex()}\n")
    elif packet.haslayer(IP) and packet.haslayer(UDP) :
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        raw_packets = bytes(packet)
        with open(filename, 'a') as log :
            log.write(
                f"UDP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n\tRaw packets: {raw_packets.hex()}\n")
    elif packet.haslayer(IP) and packet.haslayer(HTTP) :
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[HTTP].sport
        dst_port = packet[HTTP].dport
        raw_packets = bytes(packet)
        with open(filename, 'a') as log :
            log.write(
                f"HTTP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n\tRaw packets: {raw_packets.hex()}\n")


# Function to handle the capture of DNS service packets
def handle_service_packets(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
            raw_packets = bytes(packet)
            with open(filename, 'a') as log:
                log.write(
                    f"{src_ip}: -> {dst_ip}:{packet.getlayer(DNS).qd.qname}\n\tRaw packets: {raw_packets.hex()}\n")


# Function to handle the capture of ICMP Echo requests
def handle_icmp_packets(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if packet.haslayer(ICMP) and packet.getlayer(ICMP) :
            raw_packets = bytes(packet)
            with open(filename, 'a') as log :
                log.write(f"{src_ip}: -> {dst_ip}:{packet.getlayer(ICMP)}\n\tRaw packets: {raw_packets.hex()}\n")

# Function to handle the capture of HTTP to through TLS traffic (HTTPS)
def handle_tls_packet(packet):
    if packet.haslayer(Raw):
        b = bytes(packet[Raw].load)

        if b[0] == 0x16 :
            version = int.from_bytes(b[1 :3], 'big')
            message_len = int.from_bytes(b[3 :5], 'big')
            handshake_type = b[5]
            handshake_length = int.from_bytes(b[6 :9], 'big')
            with open(filename, 'a') as log :
                log.write(
                    f"TLS_TRAFFIC: v={version}, len={message_len}, htype={handshake_type}, hlen={handshake_length}")

            if handshake_type == 11 :
                # never happens - Why?
                certs_len = int.from_bytes(b[7 :11], 'big')


# Function to start sniffing based on user input
def start_sniffing(user_input):
    protocol_filter = ""
    fuction = ""

    if user_input == "TCP":
        protocol_filter = "tcp"
        function = handle_packet
    elif user_input == "UDP":
        protocol_filter = "udp"
        function = handle_packet
    elif user_input == "HTTP":
        # HTTP doesn't have a direct filter, so we filter by TCP port 80 (HTTP standard port)
        protocol_filter = "port 80"
        function = handle_packet
        # DNS doesn't have a direct filter, so we filter by TCP port 53 (DNS standard port)
    elif user_input == "DNS":
        function = handle_service_packets
        protocol_filter = "port 53"
    elif user_input == "ICMP":
        protocol_filter = "icmp"
        function = handle_icmp_packets
        # HTTPS doesn't have a direct filter, so we filter by TCP port 443 (HTTPS through TLS standard port 443)
    elif user_input == "TLS":
        protocol_filter = "port 443"
        function = handle_tls_packet
    else:
        print(f"Unsupported protocol: {user_input}")
        return

    # Start sniffing with the protocol filter and the handle_packet function
    print(f"Sniffing {user_input} traffic...\n"
          f"To stop monitoring, press 'q'")
    sniff(filter=protocol_filter, prn=function)

    # function to halt the code during monitoring process or after the user is done monitoring


def stop_sniffing():
    global sniffing
    keyboard.wait('q')  # Wait for 'q' key press to stop sniffing
    sniffing = False
    print("\nSniffing stopped.")


# Start sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing, args=(userInput,))
sniff_thread.start()

# Start the stop monitoring in the main thread
stop_sniffing()
