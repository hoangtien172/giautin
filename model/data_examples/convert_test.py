import csv
import pandas as pd

#chuyển tên của flows1.csv về dạng của example.csv

flows_df = pd.read_csv('data_examples/flows1.csv')
name = flows_df.columns
# print(name)
new_name = []
for n in name:
    n = n.replace('_', ' ')
    #viet hoa ki tu dau tien sau dau " "
    # n = n.title()
    new_name.append(n)
#thay name bang new_name
print(new_name)
flows_df.columns = new_name

import pandas as pd

# Danh sách các cột trong example.csv
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
    #check name include "/"
    if "/" in name:
        name = name.replace("/", " ")
    name_example_columns.append(name)

# Đọc flows1.csv

# Chỉ giữ lại các cột có trong example_columns
converted_df = flows_df[name_example_columns]
converted_df.columns = example_columns
# Lưu DataFrame đã chuyển đổi thành output.csv
converted_df.to_csv('data_examples/output.csv', index=False)



def convert_data(path_csv):
    flows_df = pd.read_csv(path_csv)
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
    # # Lưu DataFrame đã chuyển đổi thành output.csv
    # converted_df.to_csv('data_examples/output.csv', index=False)
