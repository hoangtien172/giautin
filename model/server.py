#!/usr/bin/env python
# import socket
from model import model
import requests
import json
from io import StringIO
import csv 

import os
import time
import pandas as pd
# from scapy.all import sniff
from scapy.all import *

capture_duration = 10  # Duration in seconds to capture packets
output_folder = "output"
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

if not os.path.exists(output_folder):
    os.makedirs(output_folder)


def capture_packets(capture_duration=10, pcap_filename="captured_packets.pcap"):
    # Bắt các gói tin trong khoảng thời gian capture_duration (giây)
    pcap_filename = f"{output_folder}/packets_{int(time.time())}.pcap"
    print(f"Capturing packets for {capture_duration} seconds...")

    captured_packets = sniff(timeout=capture_duration, filter="ip", store=True)

    # Ghi các gói tin đã bắt vào tập tin pcap_filename
    wrpcap(pcap_filename, captured_packets)

    return pcap_filename


def convert_pcap_to_csv(pcap_filename):
    csv_filename = pcap_filename.replace(".pcap", ".csv")
    os.system(f"cicflowmeter -i {pcap_filename} -c {csv_filename}")
    print(f"Converted {pcap_filename} to {csv_filename}")

    return csv_filename

def json_to_csv_string(json_data):
    # Convert JSON to a list of dictionaries
    data_list = json.loads(json_data)

    # Create a StringIO object to hold the CSV data
    csv_buffer = StringIO()

    # Check if data_list is not empty
    if data_list:
        # Get the header (keys of the first dictionary)
        header = data_list[0].keys()

        # Create a CSV writer object
        writer = csv.DictWriter(csv_buffer, fieldnames=header)

        # Write the header
        writer.writeheader()

        # Write the data rows
        for row in data_list:
            writer.writerow(row)

    # Get the CSV string
    csv_string = csv_buffer.getvalue()

    # Close the StringIO object
    csv_buffer.close()

    return csv_string

def convert_data(path_csv):

    flows_df = pd.read_csv(path_csv)
    if flows_df.empty:
        print("Empty dataframe")
        return None
    else:
        name = flows_df.columns
        new_name = []
        for n in name:
            n = n.replace('_', ' ')
            new_name.append(n)
        print(new_name)
        flows_df.columns = new_name

        example_columns = ['Flow IAT Mean', 'Tot Bwd Pkts', 'Fwd Header Len', 'Fwd IAT Std',
                        'Init Bwd Win Byts', 'Subflow Fwd Pkts', 'Bwd Header Len',
                        'ECE Flag Cnt', 'Flow Duration', 'Subflow Fwd Byts', 'Fwd Pkt Len Max',
                        'Bwd IAT Std', 'Subflow Bwd Byts', 'CWE Flag Count', 'SYN Flag Cnt',
                        'Pkt Len Var', 'Pkt Len Std', 'Flow IAT Std', 'Bwd Pkts/s',
                        'Pkt Len Max', 'Pkt Size Avg', 'Active Mean', 'Flow IAT Max',
                        'RST Flag Cnt', 'Idle Std', 'Bwd Pkt Len Max', 'Fwd IAT Mean',
                        'Bwd IAT Min', 'Fwd Pkt Len Std', 'Active Std', 'Fwd IAT Min',
                        'Bwd IAT Mean', 'Idle Max', 'Idle Min', 'Pkt Len Mean', 'Pkt Len Min',
                        'Bwd Pkt Len Std', 'Tot Fwd Pkts', 'TotLen Fwd Pkts', 'Fwd Pkts/s',
                        'Bwd Seg Size Avg', 'Fwd Seg Size Avg', 'Dst Port', 'Fwd IAT Max',
                        'Down/Up Ratio', 'Fwd Seg Size Min', 'Init Fwd Win Byts',
                        'Fwd Pkt Len Min', 'Bwd IAT Max', 'Fwd Act Data Pkts', 'PSH Flag Cnt',
                        'Protocol', 'ACK Flag Cnt', 'Flow IAT Min', 'Subflow Bwd Pkts',
                        'Active Min', 'Fwd Pkt Len Mean', 'Fwd PSH Flags', 'FIN Flag Cnt',
                        'Fwd URG Flags', 'URG Flag Cnt', 'Active Max', 'Bwd Pkt Len Min',
                        'Bwd Pkt Len Mean', 'Bwd IAT Tot', 'Idle Mean', 'Fwd IAT Tot',
                        'TotLen Bwd Pkts']
        name_example_columns = []
        for name in example_columns:
            name = name.lower()
            if "/" in name:
                name = name.replace("/", " ")
            name_example_columns.append(name)

        converted_df = flows_df[name_example_columns]
        converted_df.columns = example_columns
        return converted_df



predicted_results = {
    "Bot":0,
    "DoS attack":0,
    "Brute Force":0,
    "DDoS attacks":0,
    "0":0
    }
m = model()

#check for unwanted bytes and remove them
def check_flow_return_string(recv):
    allowed_chars = ["0","1","2","3","4","5","6","7","8","9",'.',',','-','N','e','d','M','a','n','u','l','L','b','E','p','o','i','t']
    data =  ""
    for i in recv:
        char = chr(i)
        if char in allowed_chars:                
            data += chr(i)
    return data

def data_processing(data,results):
    #data = Subtract_Unless_0(data)
    if results[-1] == "exit":
        quit()
    else:
        for label in data:
            for res in results:
                if label in str(res):
                    data[label] = data[label] + 1
                    
    return data

def server_program():
    global predicted_results
    host = "0.0.0.0"
    port = 5000 

    # server_socket = socket.socket() 
    # server_socket.bind((host, port)) 

    # server_socket.listen(2)
    # conn, address = server_socket.accept() 
    data = '' 
    # count = 0
    while True:
        pcap_filename = capture_packets()
        csv_filename = convert_pcap_to_csv(pcap_filename)
        print("------------", csv_filename)
        csv_filename = 'model/data_examples/flows1.csv'
        data = convert_data(csv_filename)
        if data is None:
            continue
        else:
        


        # recv = conn.recv(2048)
        
        # data_temp = check_flow_return_string(recv)
        # if not data_temp:
           
        #     continue
        # data += str(data_temp) 
        # count += 1
        
        # if (count == 10):
            # try:
            # m.load_data(data) 
            m.load_data_csv(csv_filename)
            results = m.predict()
            print(results)
            predicted_results = data_processing(predicted_results,results)
            print(predicted_results)
            req = requests.get('http://0.0.0.0:7777/reset_status')
            reset_details = req.json()
            print(reset_details)
            print(reset_details['reset_boolean'],type(reset_details['reset_boolean']))
            if reset_details['reset_boolean'] == 'True':
                print('Resetttttttt!')
                predicted_results = {
                    "Bot":0,
                    "DoS attack":0,
                    "Brute Force":0,
                    "DDoS attacks":0,
                    "0":0
                    }
                requests.post('http://0.0.0.0:7777/reset_status')
            requests.post('http://0.0.0.0:7777/post-predict',json=predicted_results)
            data = '' 
            count = 0
            # except Exception as e:cd 
            #     print(e)
            #     print("------------")
            #     print(data)
            #     print("------------")
            #     pass
            


if __name__ == '__main__':
    server_program()


