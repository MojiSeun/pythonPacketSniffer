OVERVIEW 
Seun Packet Sniffer Application is a Python-based tool that captures and logs network traffic based on different protocols, including HTTP, TCP, UDP, ICMP, DNS, and TLS. The tool uses Scapy to perform packet sniffing and allows users to monitor specific network traffic while logging the packet details for later analysis.

This packet sniffer offers easy-to-use filtering based on the user’s choice of protocol and supports dynamic control of sniffing operations.

FEATURES
Protocol-Specific Packet Capture: Capture traffic based on protocols such as:

HTTP (Port 80) TCP UDP ICMP DNS (Port 53) TLS (HTTPS over Port 443) Detailed Logging: Logs source and destination IPs, ports, and raw packet data to a timestamped file for future analysis.

User Input-Driven: The application prompts the user to specify the desired protocol for packet capture.

Real-Time Stop Mechanism: Allows the user to stop the packet sniffing operation by pressing the q key.

INSTALLATION
Prerequisites Python 3.x

Scapy: A powerful Python library used for packet manipulation and sniffing. Install using:

pip install scapy Keyboard Module: This module is used for detecting keypress events to stop sniffing. Install using:

pip install keyboard psutil: (Optional) for extended system monitoring. Install using:

pip install psutil Clone the Repository To get started with the Seun Packet Sniffer, clone this repository:

git clone https://github.com/username/seun-packet-sniffer.git

USAGE 
Run the Application: After installation, navigate to the project folder and run the main.py script:

python main.py Choose a Protocol: The application will prompt you to input the desired type of traffic to capture (e.g., HTTP, TCP, UDP, ICMP, DNS, or TLS):

Input desired type of traffic (HTTP, TCP, UDP, ICMP, DNS, TLS): Start Sniffing: Once you input the desired protocol, the application will start capturing and logging traffic for that protocol. The captured traffic is saved in a timestamped log file in the current directory.

Stop Sniffing: To stop the packet sniffing, simply press the q key. The program will halt and stop capturing traffic.

EXAMPLE To capture TCP traffic, run the following steps:

python main.py Then input TCP when prompted:

Input desired type of traffic (HTTP, TCP, UDP, ICMP, DNS, TLS): TCP The application will begin capturing TCP packets and log them to a file named something like TCP_packet_capture_YYYYMMDD_HHMMSS.txt.

SUPPORTED PROTOCOLS
Protocol Port Description HTTP 80 Standard web traffic TCP N/A Transmission Control Protocol UDP N/A User Datagram Protocol ICMP N/A Internet Control Message Protocol (used for ping, etc.) DNS 53 Domain Name System queries TLS 443 Encrypted web traffic (HTTPS)

CONTRIBUTING 
Feel free to open issues or submit pull requests to improve the functionality or add new features to the Seun Packet Sniffer.
