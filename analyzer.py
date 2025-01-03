import pandas as pd
from collections import defaultdict
from utils import *

table_proprietary_app_message_distribution = {
    "Total UDP Datagrams": {},
    "Total Proprietary Header": {},
}
temp_proprietary_app_message_distribution = {
    "Total UDP Datagrams": defaultdict(int),
    "Total Proprietary Header": defaultdict(int),
}


def update_app_proprietary_message_distribution(app_name, js):
    temp_proprietary_app_message_distribution["Total UDP Datagrams"][app_name] += js["Packet Count (Transport)"]["UDP"]["Total"]
    temp_proprietary_app_message_distribution["Total Proprietary Header"][app_name] += js["Packet Count (Proprietary Header)"]

    count = temp_proprietary_app_message_distribution["Total Proprietary Header"][app_name]
    count_k = round(count / 1000)
    total = temp_proprietary_app_message_distribution["Total UDP Datagrams"][app_name]
    total_k = round(total / 1000)
    table_proprietary_app_message_distribution["Total UDP Datagrams"][app_name] = f"{total_k}k"
    table_proprietary_app_message_distribution["Total Proprietary Header"][app_name] = f"{count_k}k ({count/total*100:.2f}%)"


table_app_protocol_message_distribution = {}
temp_app_protocol_message_distribution = {}


def update_app_protocol_message_distribution(app_name, js):
    if app_name not in temp_app_protocol_message_distribution:
        temp_app_protocol_message_distribution[app_name] = defaultdict(int)
    temp_app_protocol_message_distribution[app_name]["Total"] += js["Message Count (Total)"]
    for protocol in js["Message Count (Protocol)"]:
        temp_app_protocol_message_distribution[app_name][protocol] += js["Message Count (Protocol)"][protocol]["Total Messages"]

    if app_name not in table_app_protocol_message_distribution:
        table_app_protocol_message_distribution[app_name] = {}
    for protocol in js["Message Count (Protocol)"]:
        percent = temp_app_protocol_message_distribution[app_name][protocol] / temp_app_protocol_message_distribution[app_name]["Total"] * 100
        if protocol == "STUN":
            protocol = "STUN/TURN"
        table_app_protocol_message_distribution[app_name][protocol] = f"{percent:.2f}%"


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
        # compliant_set = set([msg_type for msg_type in js["Message Types"][protocol] if len(js["Message Types"][protocol][msg_type]) == 0])
        # temp_app_protocol_type_compliance[app_name][protocol + " compliant"].update(compliant_set)
        non_compliant_set = set([msg_type for msg_type in js["Message Types"][protocol] if len(js["Message Types"][protocol][msg_type]) != 0])
        temp_app_protocol_type_compliance[app_name][protocol + " non-compliant"].update(non_compliant_set)

    if app_name not in table_app_protocol_type_compliance:
        table_app_protocol_type_compliance[app_name] = {}
    for protocol in js["Message Types"]:
        total_count = len(temp_app_protocol_type_compliance[app_name][protocol + " total"])
        # compliant_count = len(temp_app_protocol_type_compliance[app_name][protocol + " compliant"])
        non_compliant_count = len(temp_app_protocol_type_compliance[app_name][protocol + " non-compliant"])
        compliant_count = total_count - non_compliant_count
        percent = compliant_count / total_count * 100
        if protocol == "STUN":
            protocol = "STUN/TURN"
        table_app_protocol_type_compliance[app_name][protocol] = f"{compliant_count}/{total_count} ({percent:.2f}%)"


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
            table_protocol_criteria_type_distribution[protocol]["Total Non-Compliance"] = total_count
            if total_count != 0:
                percent = criteria_count / total_count * 100
                table_protocol_criteria_type_distribution[protocol][criteria] = f"{criteria_count}/{total_count}"
            else:
                table_protocol_criteria_type_distribution[protocol][criteria] = f"N/A"

        if protocol == "STUN":
            table_protocol_criteria_type_distribution["STUN/TURN"] = table_protocol_criteria_type_distribution.pop("STUN")


table_app_criteria_type_distribution = {}
temp_app_criteria_type_distribution = {}


def update_app_criteria_type_distribution(app_name, js):
    if app_name not in temp_app_criteria_type_distribution:
        temp_app_criteria_type_distribution[app_name] = defaultdict(set)
    for protocol in js["Message Types"]:
        for msg_type in js["Message Types"][protocol]:
            if len(js["Message Types"][protocol][msg_type]) != 0:
                temp_app_criteria_type_distribution[app_name]["Total"].add(msg_type)
            for criteria in js["Message Types"][protocol][msg_type]:
                temp_app_criteria_type_distribution[app_name][criteria].add(msg_type)

    if app_name not in table_app_criteria_type_distribution:
        table_app_criteria_type_distribution[app_name] = {}
    for criteria in ["Undefined Message", "Invalid Header", "Undefined Attributes", "Invalid Attributes", "Invalid Semantics"]:
        if criteria in temp_app_criteria_type_distribution[app_name]:
            criteria_count = len(temp_app_criteria_type_distribution[app_name][criteria])
        else:
            criteria_count = 0
        total_count = len(temp_app_criteria_type_distribution[app_name]["Total"])
        table_app_criteria_type_distribution[app_name]["Total Non-Compliance"] = total_count
        if total_count != 0:
            percent = criteria_count / total_count * 100
            table_app_criteria_type_distribution[app_name][criteria] = f"{criteria_count}/{total_count}"
        else:
            table_app_criteria_type_distribution[app_name][criteria] = f"N/A"


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
    temp_app_dataset_summary[app_name]["Total Volume"] += js["Traffic Volume"]

    temp_app_dataset_summary[app_name]["Raw Packets"] += js["Packet Count (Raw)"]
    temp_app_dataset_summary[app_name]["Filtered Packets"] += js["Packet Count (Filtered)"]
    temp_app_dataset_summary[app_name]["Total Packets"] += js["Packet Count (Total)"]

    temp_app_dataset_summary[app_name]["Raw UDP Packets"] += js["Packet Count (Transport)"]["UDP"]["Raw"]
    temp_app_dataset_summary[app_name]["Filtered UDP Packets"] += js["Packet Count (Transport)"]["UDP"]["Filtered"]
    temp_app_dataset_summary[app_name]["Total UDP Packets"] += js["Packet Count (Transport)"]["UDP"]["Total"]

    temp_app_dataset_summary[app_name]["Raw TCP Packets"] += js["Packet Count (Transport)"]["TCP"]["Raw"]
    temp_app_dataset_summary[app_name]["Filtered TCP Packets"] += js["Packet Count (Transport)"]["TCP"]["Filtered"]
    temp_app_dataset_summary[app_name]["Total TCP Packets"] += js["Packet Count (Transport)"]["TCP"]["Total"]

    temp_app_dataset_summary[app_name]["Raw UDP Streams"] += js["Stream Count (Transport)"]["UDP"]["Raw"]
    temp_app_dataset_summary[app_name]["Filtered UDP Streams"] += js["Stream Count (Transport)"]["UDP"]["Filtered"]
    temp_app_dataset_summary[app_name]["Total UDP Streams"] += js["Stream Count (Transport)"]["UDP"]["Total"]

    temp_app_dataset_summary[app_name]["Raw TCP Streams"] += js["Stream Count (Transport)"]["TCP"]["Raw"]
    temp_app_dataset_summary[app_name]["Filtered TCP Streams"] += js["Stream Count (Transport)"]["TCP"]["Filtered"]
    temp_app_dataset_summary[app_name]["Total TCP Streams"] += js["Stream Count (Transport)"]["TCP"]["Total"]

    if app_name not in table_app_dataset_summary:
        table_app_dataset_summary[app_name] = {}

    total_duration_min = temp_app_dataset_summary[app_name]["Total Duration"] / 60
    total_volume_mb = temp_app_dataset_summary[app_name]["Total Volume"] / 1024 / 1024

    avg_udp_streams_raw = temp_app_dataset_summary[app_name]["Raw UDP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    avg_udp_streams_filtered = temp_app_dataset_summary[app_name]["Filtered UDP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    avg_udp_streams = temp_app_dataset_summary[app_name]["Total UDP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]

    avg_tcp_streams_raw = temp_app_dataset_summary[app_name]["Raw TCP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    avg_tcp_streams_filtered = temp_app_dataset_summary[app_name]["Filtered TCP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    avg_tcp_streams = temp_app_dataset_summary[app_name]["Total TCP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]

    total_packets_k = round(temp_app_dataset_summary[app_name]["Total Packets"] / 1000)

    raw_udp_datagrams_k = round(temp_app_dataset_summary[app_name]["Raw UDP Packets"] / 1000)
    filtered_udp_datagrams_k = round(temp_app_dataset_summary[app_name]["Filtered UDP Packets"] / 1000)
    total_udp_datagrams_k = round(temp_app_dataset_summary[app_name]["Total UDP Packets"] / 1000)

    total_tcp_segments_k = round(temp_app_dataset_summary[app_name]["Total TCP Packets"] / 1000)

    table_app_dataset_summary[app_name]["Total Duration (min)"] = f"{total_duration_min:.2f}"
    table_app_dataset_summary[app_name]["Total Volume (MB)"] = f"{total_volume_mb:.2f}"
    # table_app_dataset_summary[app_name]["Total Packets"] = f"{total_packets_k}k"
    table_app_dataset_summary[app_name]["UDP Datagrams (Raw)"] = f"{raw_udp_datagrams_k}k"
    table_app_dataset_summary[app_name]["UDP Datagrams (Filter 1)"] = f"{filtered_udp_datagrams_k}k"
    table_app_dataset_summary[app_name]["UDP Datagrams (Filter 2)"] = f"{total_udp_datagrams_k}k"
    # table_app_dataset_summary[app_name]["Total TCP Segments"] = f"{total_tcp_segments_k}k"
    table_app_dataset_summary[app_name]["Avg UDP Streams (Raw)"] = f"{avg_udp_streams_raw:.2f}"
    table_app_dataset_summary[app_name]["Avg UDP Streams (Filter 1)"] = f"{avg_udp_streams_filtered:.2f}"
    table_app_dataset_summary[app_name]["Avg UDP Streams (Filter 2)"] = f"{avg_udp_streams:.2f}"
    # table_app_dataset_summary[app_name]["Avg TCP Streams"] = f"{avg_tcp_streams:.2f}"

table_test_summary = {}

def update_test_summary(test_name, js):
    if test_name not in table_test_summary:
        table_test_summary[test_name] = {}
    table_test_summary[test_name]["Error Count"] = js["Error Count"]
    for protocol in js["Packet Count (Protocol)"]:
        if protocol == "Unknown":
            table_test_summary[test_name]["Unknown"] = js["Packet Count (Protocol)"][protocol]["Total Packets"]
            continue
        compliant_count = js["Packet Count (Protocol)"][protocol]["Compliant Packets"]
        total = js["Packet Count (Protocol)"][protocol]["Total Packets"]
        percent = (1 - compliant_count / total) * 100
        table_test_summary[test_name][protocol] = percent

def main(app_name, csv_file, json_file):
    df = read_from_csv(csv_file)
    js = read_from_json(json_file)
    file_name = csv_file.split("/")[-1].split(".")[0]

    update_app_proprietary_message_distribution(app_name, js)
    update_app_protocol_message_distribution(app_name, js)
    update_app_protocol_packet_distribution(app_name, js)
    update_app_protocol_type_compliance(app_name, js)
    update_app_protocol_message_compliance(app_name, js)
    update_protocol_criteria_type_distribution(js)
    update_app_criteria_type_distribution(app_name, js)
    update_app_criteria_message_distribution(app_name, js)
    update_app_dataset_summary(app_name, js)
    update_test_summary(file_name, js)


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

    df_proprietary_app_message_distribution = pd.DataFrame.from_dict(table_proprietary_app_message_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_proprietary_app_message_distribution = df_proprietary_app_message_distribution.fillna("N/A")
    df_proprietary_app_message_distribution.to_csv(f"./{folder}/proprietary_app_message_distribution.csv", index=False)
    print(df_proprietary_app_message_distribution)

    df_app_protocol_message_distribution = pd.DataFrame.from_dict(table_app_protocol_message_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_protocol_message_distribution = df_app_protocol_message_distribution.fillna("N/A")
    df_app_protocol_message_distribution.to_csv(f"./{folder}/app_protocol_message_distribution.csv", index=False)
    print(df_app_protocol_message_distribution)

    # df_app_protocol_packet_distribution = pd.DataFrame.from_dict(table_app_protocol_packet_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    # df_app_protocol_packet_distribution = df_app_protocol_packet_distribution.fillna("N/A")
    # df_app_protocol_packet_distribution.to_csv(f"./{folder}/app_protocol_datagram_distribution.csv", index=False)
    # print(df_app_protocol_packet_distribution)

    df_app_protocol_type_compliance = pd.DataFrame.from_dict(table_app_protocol_type_compliance, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_protocol_type_compliance = df_app_protocol_type_compliance.fillna("N/A")
    df_app_protocol_type_compliance.to_csv(f"./{folder}/app_protocol_type_compliance.csv", index=False)
    print(df_app_protocol_type_compliance)

    df_app_protocol_message_compliance = pd.DataFrame.from_dict(table_app_protocol_message_compliance, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_protocol_message_compliance = df_app_protocol_message_compliance.fillna("N/A")
    df_app_protocol_message_compliance.to_csv(f"./{folder}/app_protocol_message_compliance.csv", index=False)
    print(df_app_protocol_message_compliance)

    df_protocol_criteria_type_distribution = pd.DataFrame.from_dict(table_protocol_criteria_type_distribution, orient="index").reset_index().rename(columns={"index": "Protocols"})
    df_protocol_criteria_type_distribution.to_csv(f"./{folder}/protocol_criteria_type_distribution.csv", index=False)
    print(df_protocol_criteria_type_distribution)

    df_app_criteria_type_distribution = pd.DataFrame.from_dict(table_app_criteria_type_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_criteria_type_distribution.to_csv(f"./{folder}/app_criteria_type_distribution.csv", index=False)
    print(df_app_criteria_type_distribution)

    # df_app_criteria_message_distribution = pd.DataFrame.from_dict(table_app_criteria_message_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    # df_app_criteria_message_distribution.to_csv(f"./{folder}/app_criteria_message_distribution.csv", index=False)
    # print(df_app_criteria_message_distribution)

    df_app_dataset_summary = pd.DataFrame.from_dict(table_app_dataset_summary, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_dataset_summary.to_csv(f"./{folder}/app_dataset_summary.csv", index=False)
    print(df_app_dataset_summary)
    
    df_test_summary = pd.DataFrame.from_dict(table_test_summary, orient="index").reset_index().rename(columns={"index": "Tests"})
    df_test_summary = df_test_summary.fillna("N/A")
    df_test_summary.to_csv(f"./{folder}/test_summary.csv", index=False)
    print(df_test_summary)
