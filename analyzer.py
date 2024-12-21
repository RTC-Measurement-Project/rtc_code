import pandas as pd
from utils import *

def modify_titles(csv_file):
    old_title = "Transport Protocol,Protocol,Packets,Undefined Message Type,Invalid Header,Undefined Attributes,Invalid Attributes,Invalid Semantics,Non-Compliant Packets,Compliant Packets,Compliance Ratio,,Num of Message Types,Undefined Message Type.1,Invalid Header.1,Undefined Attributes.1,Invalid Attributes.1,Invalid Semantics.1,Num of Non-Compliant Types,Num of Compliant Types,Compliance Ratio.1\n"
    new_title = old_title.replace(".1", "")
    with open(csv_file, "r") as file:
        lines = file.readlines()
        lines[0] = new_title
    # print(lines[0])
    with open(csv_file, "w") as file:
        file.writelines(lines)


def main(app_name, test_name, test_round, client_type, part, protocol_tables):

    main_folder = "metrics" + "/" + app_name + "/" + test_name

    csv_file = f"./{main_folder}/{app_name}_{test_name}_{test_round}_{client_type}_part_{part}.csv"
    # json_file = f"./{main_folder}//{app_name}_{test_name}_{test_round}_{client_type}_part_{part}.json"
    
    # modify_titles(csv_file)

    df = read_from_csv(csv_file)
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
            start_index = df.columns.get_loc(empty_column_names[0])
            protocol_row.columns = [
                "Test" if "Unnamed" in col else col for col in protocol_row.columns
            ]
            extracted_row = protocol_row.iloc[:, start_index:]
            extracted_row["Test"] = test_title
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
        output_folder = "metrics" + "/" + app_name
        protocol_tables = {}
        if app_name not in app_protocol_compliance_dict:
            app_protocol_compliance_dict[app_name] = {}
        for test_name in tests:
            for test_round in rounds:
                for client_type in client_types:
                    for part in parts:
                        main(app_name, test_name, test_round, client_type, part, protocol_tables)

        for protocol_name, protocol_table in protocol_tables.items():
            # Calculate the average of each column and add it as a new row
            avg_row = protocol_table.mean(numeric_only=True).to_frame().T
            avg_row["Test"] = "average"
            protocol_table = pd.concat([protocol_table, avg_row], ignore_index=True)
            avg_compliance_ratio = avg_row["Compliance Ratio.1"].values[0]
            app_protocol_compliance_dict[app_name][protocol_name] = avg_compliance_ratio
            protocol_table.to_csv(f"{output_folder}/{app_name}_{protocol_name}.csv", index=False)

    # Convert app_protocol_compliance_dict to DataFrame and save as CSV
    compliance_df = pd.DataFrame.from_dict(app_protocol_compliance_dict, orient='index').reset_index().rename(columns={'index': 'App Name'})
    compliance_df.to_csv("metrics/app_protocol_compliance.csv", index=False)
    print(compliance_df)
