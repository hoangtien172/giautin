import socket
import json
from cicflowmeter import CICFlowMeter

# Khởi tạo CICFlowMeter
flow_meter = CICFlowMeter()

# Kết nối đến máy chủ socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 5000))

# Thay đổi địa chỉ này thành địa chỉ pcap của bạn
pcap_file = "path/to/your/pcap/file.pcap"

# Xử lý các gói tin trong tệp pcap và tính toán thông tin về luồng
flows = flow_meter.process_pcap(pcap_file)

# Gửi thông tin về luồng qua socket
for flow in flows:
    flow_data = flow.get_feature_vector()
    client_socket.send(json.dumps(flow_data).encode())

client_socket.close()
