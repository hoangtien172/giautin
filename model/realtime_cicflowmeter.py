# import socket
# import json
# from scapy.all import sniff
# from cicflowmeter import CICFlowMeter

# # Khởi tạo CICFlowMeter
# flow_meter = CICFlowMeter()

# # Kết nối đến máy chủ socket
# client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# client_socket.connect(('127.0.0.1', 5000))

# def process_packet(packet):
#     # Thêm gói tin vào CICFlowMeter và tính toán thông tin về luồng
#     flow = flow_meter.process_packet(packet)

#     if flow is not None:
#         flow_data = flow.get_feature_vector()
#         client_socket.send(json.dumps(flow_data).encode())

# # Sử dụng Scapy để thu thập gói tin trong thời gian thực
# sniff(prn=process_packet, store=0)

# client_socket.close()


# import json
# from scapy.all import sniff
# from cicflowmeter.CICFlowMeter import CICFlowMeter
# from socketIO_client import SocketIO, LoggingNamespace

# # Khởi tạo CICFlowMeter
# flow_meter = CICFlowMeter()

# # Kết nối đến máy chủ socket
# socketIO = SocketIO('127.0.0.1', 5000, LoggingNamespace)

# def process_packet(packet):
#     # Thêm gói tin vào CICFlowMeter và tính toán thông tin về luồng
#     flow = flow_meter.process_packet(packet)

#     if flow is not None:
#         flow_data = flow.get_feature_vector()
#         socketIO.emit('cicflowmeter_data', json.dumps(flow_data))

# # Sử dụng Scapy để thu thập gói tin trong thời gian thực
# sniff(prn=process_packet, store=0)

# socketIO.disconnect()


import os
import time
from scapy.all import *

capture_duration = 10  # Duration in seconds to capture packets
output_folder = "output_test"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

if not os.path.exists(output_folder):
    os.makedirs(output_folder)

def capture_packets():
    pcap_filename = f"{output_folder}/packets_{int(time.time())}.pcap"

    print(f"Capturing packets for {capture_duration} seconds...")
    captured_packets = sniff(timeout=capture_duration, filter="ip", store=True)
    wrpcap(pcap_filename, captured_packets)

    print(f"Finished capturing packets. Saved to {pcap_filename}")

    return pcap_filename

def convert_pcap_to_csv(pcap_filename):
    csv_filename = pcap_filename.replace(".pcap", ".csv")
    os.system(f"cicflowmeter -i {pcap_filename} -c {csv_filename}")
    print(f"Converted {pcap_filename} to {csv_filename}")

    return csv_filename

while True:
    pcap_filename = capture_packets()
    csv_filename = convert_pcap_to_csv(pcap_filename)
    print (pcap_filename)
    print (csv_filename)
    # Do something with the csv file, e.g., send data to your Flask app


