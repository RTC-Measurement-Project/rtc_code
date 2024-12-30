import pandas as pd
from utils import *

folder = "test_metrics"

table_app_protocol_volume_distribution = {}
table_app_protocol_type_compliance = {}
table_app_protocol_volume_compliance = {}
table_protocol_criteria_type_distribution = {}
table_app_criteria_volume_distribution = {}
table_app_dataset_summary = {}

def main(app_name, test_name, test_round, client_type, part, protocol_tables):

    main_folder = f"{folder}" + "/" + app_name + "/" + test_name

    json_file = f"./{main_folder}/{app_name}_{test_name}_{test_round}_{client_type}_part_{part}.json"
    csv_file = f"./{main_folder}/{app_name}_{test_name}_{test_round}_{client_type}_part_{part}.csv"
    # json_file = f"./{main_folder}//{app_name}_{test_name}_{test_round}_{client_type}_part_{part}.json"

    # modify_titles(csv_file)

    df = read_from_csv(csv_file)
    js = read_from_json(json_file)
    # js = read_from_json(json_file)

    test_title = f"{app_name}_{test_name}_{test_round}_{client_type}_part_{part}"
    protocol_names = df[df["Protocol"] != "Unknown"]["Protocol"].unique()
    for protocol_name in protocol_names:
        if protocol_name not in protocol_tables:
            protocol_tables[protocol_name] = pd.DataFrame()

        protocol_row = df[df["Protocol"] == protocol_name]
        empty_columns = protocol_row.isnull() | (protocol_row == "")
        empty_column_names = empty_columns.columns[empty_columns.iloc[0]].tolist()
        if not protocol_row.empty and empty_column_names:
            # start_index = df.columns.get_loc(empty_column_names[0])
            # protocol_row.columns = [
            #     "Test" if "Unnamed" in col else col for col in protocol_row.columns
            # ]
            # extracted_row = protocol_row.iloc[:, start_index:]
            # extracted_row["Test"] = test_title
            
            protocol_row.columns = [
                "Traffic Packets" if "Unnamed" in col else col for col in protocol_row.columns
            ]
            extracted_row = protocol_row.iloc[:, 2:]
            extracted_row["Traffic Packets"] = js["Packet Count (Total)"]
            extracted_row.insert(0, "Test", test_title)
            
            protocol_tables[protocol_name] = pd.concat(
                [protocol_tables[protocol_name], extracted_row]
            )

if __name__ == "__main__":
    # app_name = "Zoom"  # or "Zoom", "FaceTime", "Discord", "Messenger", "WhatsApp"
    # test_name = "multicall_2mac_av_p2pwifi_w"
    # test_round = "t1"
    # client_type = "caller"
    # part = 1
    # main(app_name, test_name, test_round, client_type, part, {})

    apps = ["Zoom", "FaceTime", "WhatsApp", "Messenger", "Discord"]
    tests = [
        "multicall_2mac_av_p2pwifi_w",
        "multicall_2mac_av_wifi_w",
        "multicall_2ip_av_p2pcellular_c",
        "multicall_2ip_av_p2pwifi_wc",
        "multicall_2ip_av_p2pwifi_w",
        "multicall_2ip_av_wifi_wc",
        "multicall_2ip_av_wifi_w",
    ]
    rounds = ["t1"]
    client_types = ["caller"]
    parts = [1, 2, 3]

    app_protocol_compliance_dict = {}

    for app_name in apps:
        protocol_tables = {}
        if app_name not in app_protocol_compliance_dict:
            app_protocol_compliance_dict[app_name] = {}
        for test_name in tests:
            for test_round in rounds:
                for client_type in client_types:
                    for part in parts:
                        main(app_name, test_name, test_round, client_type, part, protocol_tables)

        output_folder = f"{folder}" + "/" + app_name
        for protocol_name, protocol_table in protocol_tables.items():

            sum_proto_packets = protocol_table["Packets"].sum()
            sum_proprietary_header = protocol_table["Proprietary Header"].sum()
            sum_undefined_msg = protocol_table["Undefined Message"].sum()
            sum_invalid_header = protocol_table["Invalid Header"].sum()
            sum_undefined_attr = protocol_table["Undefined Attributes"].sum()
            sum_invalid_attr = protocol_table["Invalid Attributes"].sum()
            sum_invalid_semantics = protocol_table["Invalid Semantics"].sum()
            sum_non_compliant_pkts = protocol_table["Non-Compliant Packets"].sum()
            sum_compliant_pkts = protocol_table["Compliant Packets"].sum()
            sum_total_packets = protocol_table["Traffic Packets"].sum()
            assert sum_proto_packets == sum_undefined_msg + sum_invalid_header + sum_undefined_attr + sum_invalid_attr + sum_invalid_semantics + sum_compliant_pkts, "Sum of packets does not match the sum of errors and compliant packets."

            avg_row = protocol_table.mean(numeric_only=True).to_frame().T
            avg_row["Test"] = "summary"

            avg_row["Packets"] = sum_proto_packets
            avg_row["Proprietary Header"] = sum_proprietary_header
            avg_row["Undefined Message"] = sum_undefined_msg
            avg_row["Invalid Header"] = sum_invalid_header
            avg_row["Undefined Attributes"] = sum_undefined_attr
            avg_row["Invalid Attributes"] = sum_invalid_attr
            avg_row["Invalid Semantics"] = sum_invalid_semantics
            avg_row["Non-Compliant Packets"] = sum_non_compliant_pkts
            avg_row["Compliant Packets"] = sum_compliant_pkts
            avg_row["Compliance Ratio"] = sum_compliant_pkts / sum_proto_packets
            avg_row["Traffic Packets"] = sum_total_packets

            avg_msg_types = avg_row["Num of Message Types"].values[0]
            avg_compliant_types = avg_row["Num of Compliant Types"].values[0]
            avg_compliance_ratio = avg_compliant_types / avg_msg_types
            avg_row["Compliance Ratio.1"] = avg_compliance_ratio
            if not pd.isna(avg_compliance_ratio):
                percent_compliance = avg_compliance_ratio * 100
                app_protocol_compliance_dict[app_name][protocol_name] = f"{avg_compliant_types:.1f}/{avg_msg_types:.1f} ({percent_compliance:.1f}%)"
            else:
                app_protocol_compliance_dict[app_name][protocol_name] = "N/A"

            protocol_table = pd.concat([protocol_table, avg_row], ignore_index=True)
            protocol_table.to_csv(f"{output_folder}/{app_name}_{protocol_name}.csv", index=False)

    # Convert app_protocol_compliance_dict to DataFrame and save as CSV
    compliance_df = pd.DataFrame.from_dict(app_protocol_compliance_dict, orient='index').reset_index().rename(columns={'index': 'App Name'})
    compliance_df = compliance_df.fillna("N/A")
    compliance_df.to_csv(f"{folder}/app_protocol_compliance.csv", index=False)
    print(compliance_df)
