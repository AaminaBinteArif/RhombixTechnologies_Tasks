import socket
import struct
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind(("192.168.1.5", 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
try:
    while True:
        raw_packet = sniffer.recvfrom(65565)[0]
        ip_header = raw_packet[0:20]
        print("Packet captured:")

        ip_header = raw_packet[0:20]
        unpacked_data = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = unpacked_data[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        tos = unpacked_data[1]
        total_length = unpacked_data[2]
        protocol = unpacked_data[6]
        src_ip = socket.inet_ntoa(unpacked_data[8])
        dst_ip = socket.inet_ntoa(unpacked_data[9])

        print(f"Version: {version}")
        print(f"Header Length: {ihl * 4} bytes")
        print(f"Type of Service: {tos}")
        print(f"Total Length: {total_length}")
        print(f"Protocol: {protocol} ({'TCP' if protocol==6 else 'UDP' if protocol==17 else 'ICMP' if protocol==1 else 'Other'})")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print("-" * 60)

        
        
except KeyboardInterrupt:
    print("\nStopping sniffer...")
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)