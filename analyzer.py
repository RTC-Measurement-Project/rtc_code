import pandas as pd
from collections import defaultdict
from utils import *

table_app_protocol_packet_distribution = {}
temp_app_protocol_packet_distribution = {}


def update_app_protocol_packet_distribution(app_name, js):
    if app_name not in temp_app_protocol_packet_distribution:
        temp_app_protocol_packet_distribution[app_name] = defaultdict(int)
    temp_app_protocol_packet_distribution[app_name]["Proprietary Header"] += js["Packet Count (Proprietary Header)"]
    temp_app_protocol_packet_distribution[app_name]["Total"] += js["Packet Count (Total)"]
    for protocol in js["Packet Count (Protocol)"]:
        temp_app_protocol_packet_distribution[app_name][protocol] += js["Packet Count (Protocol)"][protocol]["Total Packets"]

    if app_name not in table_app_protocol_packet_distribution:
        table_app_protocol_packet_distribution[app_name] = {}
    percent_pty_hd = temp_app_protocol_packet_distribution[app_name]["Proprietary Header"] / temp_app_protocol_packet_distribution[app_name]["Total"] * 100
    table_app_protocol_packet_distribution[app_name]["Proprietary Header"] = f"{percent_pty_hd:.2f}%"
    for protocol in js["Packet Count (Protocol)"]:
        percent = temp_app_protocol_packet_distribution[app_name][protocol] / temp_app_protocol_packet_distribution[app_name]["Total"] * 100
        if protocol == "STUN":
            protocol = "STUN/TURN"
        table_app_protocol_packet_distribution[app_name][protocol] = f"{percent:.2f}%"


table_app_protocol_type_compliance = {}
temp_app_protocol_type_compliance = {}


def update_app_protocol_type_compliance(app_name, js):
    if app_name not in temp_app_protocol_type_compliance:
        temp_app_protocol_type_compliance[app_name] = defaultdict(set)
    for protocol in js["Message Types"]:
        all_type_set = set(js["Message Types"][protocol].keys())
        temp_app_protocol_type_compliance[app_name][protocol + " total"].update(all_type_set)
        compliant_set = set([msg_type for msg_type in js["Message Types"][protocol] if len(js["Message Types"][protocol][msg_type]) == 0])
        non_compliant_set = set([msg_type for msg_type in js["Message Types"][protocol] if len(js["Message Types"][protocol][msg_type]) != 0])
        temp_app_protocol_type_compliance[app_name][protocol + " compliant"].update(compliant_set)

    if app_name not in table_app_protocol_type_compliance:
        table_app_protocol_type_compliance[app_name] = {}
    for protocol in js["Message Types"]:
        compliant_count = len(temp_app_protocol_type_compliance[app_name][protocol + " compliant"])
        total_count = len(temp_app_protocol_type_compliance[app_name][protocol + " total"])
        if protocol == "STUN":
            protocol = "STUN/TURN"
        table_app_protocol_type_compliance[app_name][protocol] = f"{compliant_count}/{total_count} ({compliant_count/total_count*100:.2f}%)"


table_app_protocol_message_compliance = {}
temp_app_protocol_message_compliance = {}


def update_app_protocol_message_compliance(app_name, js):
    if app_name not in temp_app_protocol_message_compliance:
        temp_app_protocol_message_compliance[app_name] = defaultdict(int)
    for protocol in js["Message Count (Protocol)"]:
        if protocol == "Unknown":
            continue
        temp_app_protocol_message_compliance[app_name][protocol + " total"] += js["Message Count (Protocol)"][protocol]["Total Messages"]
        temp_app_protocol_message_compliance[app_name][protocol + " compliant"] += js["Message Count (Protocol)"][protocol]["Compliant Messages"]

    if app_name not in table_app_protocol_message_compliance:
        table_app_protocol_message_compliance[app_name] = {}
    for protocol in js["Message Count (Protocol)"]:
        if protocol == "Unknown":
            continue
        percent = temp_app_protocol_message_compliance[app_name][protocol + " compliant"] / temp_app_protocol_message_compliance[app_name][protocol + " total"] * 100
        if protocol == "STUN":
            protocol = "STUN/TURN"
        table_app_protocol_message_compliance[app_name][protocol] = f"{percent:.2f}%"


table_protocol_criteria_type_distribution = {}
temp_protocol_criteria_type_distribution = {}


def update_protocol_criteria_type_distribution(js):
    for protocol in js["Message Types"]:
        if protocol not in temp_protocol_criteria_type_distribution:
            temp_protocol_criteria_type_distribution[protocol] = defaultdict(set)
        # temp_protocol_criteria_type_distribution[protocol]["Total"].update(set(js["Message Types"][protocol].keys()))
        temp_protocol_criteria_type_distribution[protocol]["Total"].update(set([msg_type for msg_type in js["Message Types"][protocol] if len(js["Message Types"][protocol][msg_type]) != 0]))
        for msg_type in js["Message Types"][protocol]:
            for criteria in js["Message Types"][protocol][msg_type]:
                temp_protocol_criteria_type_distribution[protocol][criteria].add(msg_type)

        if protocol not in table_protocol_criteria_type_distribution:
            table_protocol_criteria_type_distribution[protocol] = {}
        for criteria in ["Undefined Message", "Invalid Header", "Undefined Attributes", "Invalid Attributes", "Invalid Semantics"]:
            if criteria in temp_protocol_criteria_type_distribution[protocol]:
                criteria_count = len(temp_protocol_criteria_type_distribution[protocol][criteria])
            else:
                criteria_count = 0
            total_count = len(temp_protocol_criteria_type_distribution[protocol]["Total"])
            if total_count != 0:
                table_protocol_criteria_type_distribution[protocol][criteria] = f"{criteria_count}/{total_count} ({criteria_count/total_count*100:.2f}%)"
            else:
                table_protocol_criteria_type_distribution[protocol][criteria] = f"N/A"

        if protocol == "STUN":
            table_protocol_criteria_type_distribution["STUN/TURN"] = table_protocol_criteria_type_distribution.pop("STUN")


table_app_criteria_message_distribution = {}
temp_app_criteria_message_distribution = {}


def update_app_criteria_message_distribution(app_name, js):
    if app_name not in temp_app_criteria_message_distribution:
        temp_app_criteria_message_distribution[app_name] = defaultdict(int)
    for protocol in js["Message Count (Protocol)"]:
        # temp_app_criteria_message_distribution[app_name]["Total"] += js["Message Count (Protocol)"][protocol]["Total Messages"]
        if protocol == "Unknown":
            continue
        temp_app_criteria_message_distribution[app_name]["Total"] += js["Message Count (Protocol)"][protocol]["Total Messages"] - js["Message Count (Protocol)"][protocol]["Compliant Messages"]
        for criteria in ["Undefined Message", "Invalid Header", "Undefined Attributes", "Invalid Attributes", "Invalid Semantics"]:
            temp_app_criteria_message_distribution[app_name][criteria] += js["Message Count (Protocol)"][protocol][criteria]

    if app_name not in table_app_criteria_message_distribution:
        table_app_criteria_message_distribution[app_name] = {}
    for criteria in ["Undefined Message", "Invalid Header", "Undefined Attributes", "Invalid Attributes", "Invalid Semantics"]:
        if temp_app_criteria_message_distribution[app_name]["Total"] != 0:
            percent = temp_app_criteria_message_distribution[app_name][criteria] / temp_app_criteria_message_distribution[app_name]["Total"] * 100
            table_app_criteria_message_distribution[app_name][criteria] = f"{percent:.2f}%"
        else:
            table_app_criteria_message_distribution[app_name][criteria] = f"N/A"


table_app_dataset_summary = {}
temp_app_dataset_summary = {}


def update_app_dataset_summary(app_name, js):
    if app_name not in temp_app_dataset_summary:
        temp_app_dataset_summary[app_name] = defaultdict(int)
    temp_app_dataset_summary[app_name]["Traffic Count"] += 1
    temp_app_dataset_summary[app_name]["Total Duration"] += js["Call Duration"]
    temp_app_dataset_summary[app_name]["Total Packets"] += js["Packet Count (Total)"]
    temp_app_dataset_summary[app_name]["Total Volume"] += js["Traffic Volume"]
    temp_app_dataset_summary[app_name]["Total UDP Packets"] += js["Packet Count (UDP)"]
    temp_app_dataset_summary[app_name]["Total TCP Packets"] += js["Packet Count (TCP)"]
    temp_app_dataset_summary[app_name]["Total UDP Streams"] += js["Stream Count (UDP)"]
    temp_app_dataset_summary[app_name]["Total TCP Streams"] += js["Stream Count (TCP)"]

    if app_name not in table_app_dataset_summary:
        table_app_dataset_summary[app_name] = {}
    total_duration_min = temp_app_dataset_summary[app_name]["Total Duration"] / 60
    total_volume_mb = temp_app_dataset_summary[app_name]["Total Volume"] / 1024 / 1024
    avg_udp_streams = temp_app_dataset_summary[app_name]["Total UDP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    avg_tcp_streams = temp_app_dataset_summary[app_name]["Total TCP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    table_app_dataset_summary[app_name]["Total Duration (min)"] = f"{total_duration_min:.2f}"
    table_app_dataset_summary[app_name]["Total Datagrams"] = temp_app_dataset_summary[app_name]["Total Packets"]
    table_app_dataset_summary[app_name]["Total Volume (MB)"] = f"{total_volume_mb:.2f}"
    table_app_dataset_summary[app_name]["Total UDP Datagrams"] = temp_app_dataset_summary[app_name]["Total UDP Packets"]
    table_app_dataset_summary[app_name]["Total TCP Datagrams"] = temp_app_dataset_summary[app_name]["Total TCP Packets"]
    table_app_dataset_summary[app_name]["Avg UDP Streams"] = f"{avg_udp_streams:.2f}"
    table_app_dataset_summary[app_name]["Avg TCP Streams"] = f"{avg_tcp_streams:.2f}"


def main(app_name, csv_file, json_file):
    df = read_from_csv(csv_file)
    js = read_from_json(json_file)

    update_app_protocol_packet_distribution(app_name, js)
    update_app_protocol_type_compliance(app_name, js)
    update_app_protocol_message_compliance(app_name, js)
    update_protocol_criteria_type_distribution(js)
    update_app_criteria_message_distribution(app_name, js)
    update_app_dataset_summary(app_name, js)


if __name__ == "__main__":
    folder = "test_metrics"

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

    for app_name in apps:
        for test_name in tests:
            for test_round in rounds:
                for client_type in client_types:
                    for part in parts:
                        main_folder = f"{folder}" + "/" + app_name + "/" + test_name
                        csv_file = f"./{main_folder}/{app_name}_{test_name}_{test_round}_{client_type}_part_{part}.csv"
                        json_file = f"./{main_folder}/{app_name}_{test_name}_{test_round}_{client_type}_part_{part}.json"
                        main(app_name, csv_file, json_file)

    df_app_protocol_packet_distribution = pd.DataFrame.from_dict(table_app_protocol_packet_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_protocol_packet_distribution = df_app_protocol_packet_distribution.fillna("N/A")
    print(df_app_protocol_packet_distribution)

    df_app_protocol_type_compliance = pd.DataFrame.from_dict(table_app_protocol_type_compliance, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_protocol_type_compliance = df_app_protocol_type_compliance.fillna("N/A")
    print(df_app_protocol_type_compliance)

    df_app_protocol_message_compliance = pd.DataFrame.from_dict(table_app_protocol_message_compliance, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_protocol_message_compliance = df_app_protocol_message_compliance.fillna("N/A")
    print(df_app_protocol_message_compliance)

    df_protocol_criteria_type_distribution = pd.DataFrame.from_dict(table_protocol_criteria_type_distribution, orient="index").reset_index().rename(columns={"index": "Protocols"})
    print(df_protocol_criteria_type_distribution)

    df_app_criteria_message_distribution = pd.DataFrame.from_dict(table_app_criteria_message_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    print(df_app_criteria_message_distribution)

    df_app_dataset_summary = pd.DataFrame.from_dict(table_app_dataset_summary, orient="index").reset_index().rename(columns={"index": "Applications"})
    print(df_app_dataset_summary)
    
    df_app_protocol_packet_distribution.to_csv(f"./{folder}/app_protocol_datagram_distribution.csv", index=False)
    df_app_protocol_type_compliance.to_csv(f"./{folder}/app_protocol_type_compliance.csv", index=False)
    df_app_protocol_message_compliance.to_csv(f"./{folder}/app_protocol_message_compliance.csv", index=False)
    df_protocol_criteria_type_distribution.to_csv(f"./{folder}/protocol_criteria_type_distribution.csv", index=False)
    df_app_criteria_message_distribution.to_csv(f"./{folder}/app_criteria_message_distribution.csv", index=False)
    df_app_dataset_summary.to_csv(f"./{folder}/app_dataset_summary.csv", index=False)
