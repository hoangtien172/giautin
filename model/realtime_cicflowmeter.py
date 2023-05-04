


import os
import time
from scapy.all import *

from threading import Thread

capture_duration = 10  # Duration in seconds to capture packets
output_folder = "output_test"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

if not os.path.exists(output_folder):
    os.makedirs(output_folder)

def capture_packets():
    pcap_filename = f"{output_folder}/packets_{int(time.time())}.pcap"

    print(f"Capturing packets for {capture_duration} seconds...")
    # captured_packets = sniff(timeout=capture_duration, iface="wlp0s20f3", filter="ip", promisc=True, store=True)
    captured_packets = sniff(timeout=capture_duration, iface=None, store=True)


    # captured_packets = sniff(timeout=capture_duration, iface ="wlp0s20f3" ,filter="ip", store=True)
    wrpcap(pcap_filename, captured_packets)

    print(f"Finished capturing packets. Saved to {pcap_filename}")

    return pcap_filename

def convert_pcap_to_csv(pcap_filename):
    csv_filename = pcap_filename.replace(".pcap", ".csv")
    os.system(f"cicflowmeter -f {pcap_filename} -c {csv_filename}")
    print(f"Converted {pcap_filename} to {csv_filename}")

    return csv_filename

from threading import Thread

def capture_packets_threaded():
    results = []

    def target():
        results.append(capture_packets())

    t = Thread(target=target)
    t.start()
    t.join()
    
    return results[0]

while True:
    pcap_filename = capture_packets_threaded()
    csv_filename = convert_pcap_to_csv(pcap_filename)
    print(pcap_filename)
    print(csv_filename)

# while True:
#     pcap_filename = capture_packets()
#     #dung 5s de capture
#     time.sleep(15)
#     csv_filename = convert_pcap_to_csv(pcap_filename)
#     print (pcap_filename)
#     print (csv_filename)
    # Do something with the csv file, e.g., send data to your Flask app


