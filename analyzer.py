import pandas as pd
from collections import defaultdict
from statistics import median
import matplotlib.pyplot as plt
import numpy as np
import argparse

from utils import *

json_app_protocol_modifications = {}
temp_app_message_type_count = {}


def update_app_protocol_modifications(app_name, js):
    if app_name not in json_app_protocol_modifications:
        json_app_protocol_modifications[app_name] = {}
    if app_name not in temp_app_message_type_count:
        temp_app_message_type_count[app_name] = defaultdict(int)
    deep_dict_merge(json_app_protocol_modifications[app_name], js["Message Types"], copy_dict=False)
    deep_dict_merge(temp_app_message_type_count[app_name], js["Message Count (Message Type)"], copy_dict=False)


table_app_protocol_pty_pkt_distribution = {}
temp_app_protocol_pty_pkt_distribution = {}


def update_app_protocol_pty_pkt_distribution(app_name, js):
    if app_name not in temp_app_protocol_pty_pkt_distribution:
        temp_app_protocol_pty_pkt_distribution[app_name] = defaultdict(int)
    temp_app_protocol_pty_pkt_distribution[app_name]["Total Proprietary Header"] += js["Packet Count (Proprietary Header)"]
    temp_app_protocol_pty_pkt_distribution[app_name]["Total Packets"] += js["Packet Count (Total)"]
    for protocol in js["Packet Count (Protocol)"]:
        if protocol == "Unknown":
            continue
        temp_app_protocol_pty_pkt_distribution[app_name][protocol] += js["Packet Count (Protocol)"][protocol]["Proprietary Header"]

    if app_name not in table_app_protocol_pty_pkt_distribution:
        table_app_protocol_pty_pkt_distribution[app_name] = {}
    total = temp_app_protocol_pty_pkt_distribution[app_name]["Total Packets"]
    total_k = round(total / 1000)
    pty_pkt = temp_app_protocol_pty_pkt_distribution[app_name]["Total Proprietary Header"]
    pty_pkt_k = round(pty_pkt / 1000)

    for protocol in js["Packet Count (Protocol)"]:
        if protocol == "Unknown":
            continue
        if protocol == "STUN":
            protocol = "STUN/TURN"
        pty_count = temp_app_protocol_pty_pkt_distribution[app_name][protocol]
        pty_count_k = round(pty_count / 1000)
        table_app_protocol_pty_pkt_distribution[app_name][protocol] = f"{pty_count_k}k"
        if pty_pkt != 0:
            # if pty_count != 0:
            percent = pty_count / pty_pkt * 100
            # table_app_protocol_pty_pkt_distribution[app_name][protocol] = f"{pty_count_k}k ({percent:.1f}%)"
            table_app_protocol_pty_pkt_distribution[app_name][protocol + " [Percent]"] = f"{percent:.1f}%"
    if total != 0:
        # if pty_pkt != 0:
        pty_percent = pty_pkt / total * 100
        # table_app_protocol_pty_pkt_distribution[app_name]["Total"] = f"{pty_pkt_k}k ({pty_percent:.1f}%)"
        table_app_protocol_pty_pkt_distribution[app_name]["Total Proprietary Header"] = f"{pty_pkt_k}k"
        table_app_protocol_pty_pkt_distribution[app_name]["Total Proprietary Header [Percent]"] = f"{pty_percent:.1f}%"
    # table_app_protocol_pty_pkt_distribution[app_name]["All Traffic"] = f"{total_k}k"


# table_proprietary_app_message_distribution = {
#     "Total UDP Datagrams": {},
#     "Total Proprietary Header": {},
# }
# temp_proprietary_app_message_distribution = {
#     "Total UDP Datagrams": defaultdict(int),
#     "Total Proprietary Header": defaultdict(int),
# }


# def update_app_proprietary_message_distribution(app_name, js):
#     temp_proprietary_app_message_distribution["Total UDP Datagrams"][app_name] += js["Packet Count (Transport)"]["UDP"]["Total"]
#     temp_proprietary_app_message_distribution["Total Proprietary Header"][app_name] += js["Packet Count (Proprietary Header)"]

#     count = temp_proprietary_app_message_distribution["Total Proprietary Header"][app_name]
#     count_k = round(count / 1000)
#     total = temp_proprietary_app_message_distribution["Total UDP Datagrams"][app_name]
#     total_k = round(total / 1000)
#     table_proprietary_app_message_distribution["Total UDP Datagrams"][app_name] = f"{total_k}k"
#     table_proprietary_app_message_distribution["Total Proprietary Header"][app_name] = f"{count_k}k ({count/total*100:.1f}%)"


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
    total = temp_app_protocol_message_distribution[app_name]["Total"]
    total_k = round(total / 1000)
    for protocol in js["Message Count (Protocol)"]:
        protocol_count = temp_app_protocol_message_distribution[app_name][protocol]
        protocol_count_k = round(protocol_count / 1000)
        percent = protocol_count / total * 100
        if protocol == "STUN":
            protocol = "STUN/TURN"
        if protocol == "Unknown":
            protocol = "Proprietary"
        table_app_protocol_message_distribution[app_name][protocol] = f"{percent:.1f}%"
    #     table_app_protocol_message_distribution[app_name][protocol] = protocol_count_k
    #     table_app_protocol_message_distribution[app_name][protocol + " [Percent]"] = f"{percent:.1f}%"
    # table_app_protocol_message_distribution[app_name]["Total"] = total_k


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
    table_app_protocol_packet_distribution[app_name]["Proprietary Header"] = f"{percent_pty_hd:.1f}%"
    for protocol in js["Packet Count (Protocol)"]:
        percent = temp_app_protocol_packet_distribution[app_name][protocol] / temp_app_protocol_packet_distribution[app_name]["Total"] * 100
        if protocol == "STUN":
            protocol = "STUN/TURN"
        table_app_protocol_packet_distribution[app_name][protocol] = f"{percent:.1f}%"


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
        non_compliant_set = set([msg_type for msg_type in js["Message Types"][protocol] if len(js["Message Types"][protocol][msg_type]) > 0])
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
        # table_app_protocol_type_compliance[app_name][protocol] = f"{compliant_count}/{total_count} ({percent:.1f}%)"
        table_app_protocol_type_compliance[app_name][protocol] = f"{compliant_count}/{total_count}"
        # table_app_protocol_type_compliance[app_name][protocol + " [Percent]"] = f"{percent:.1f}%"


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
        temp_app_protocol_message_compliance[app_name]["Compliant Messages"] += js["Message Count (Protocol)"][protocol]["Compliant Messages"]
        temp_app_protocol_message_compliance[app_name]["Standard Messages"] += js["Message Count (Protocol)"][protocol]["Total Messages"]
    temp_app_protocol_message_compliance[app_name]["Total Messages"] += js["Message Count (Total)"]

    if app_name not in table_app_protocol_message_compliance:
        table_app_protocol_message_compliance[app_name] = {}
    for protocol in js["Message Count (Protocol)"]:
        if protocol == "Unknown":
            continue
        percent = temp_app_protocol_message_compliance[app_name][protocol + " compliant"] / temp_app_protocol_message_compliance[app_name][protocol + " total"] * 100
        if protocol == "STUN":
            protocol = "STUN/TURN"
        table_app_protocol_message_compliance[app_name][protocol] = f"{percent:.1f}%"


table_protocol_criteria_type_distribution = {}
temp_protocol_criteria_type_distribution = {}


def update_protocol_criteria_type_distribution(js):
    for protocol in js["Message Types"]:
        if protocol not in temp_protocol_criteria_type_distribution:
            temp_protocol_criteria_type_distribution[protocol] = defaultdict(set)
        # temp_protocol_criteria_type_distribution[protocol]["Total"].update(set(js["Message Types"][protocol].keys()))
        temp_protocol_criteria_type_distribution[protocol]["Total"].update(set(js["Message Types"][protocol].keys()))
        temp_protocol_criteria_type_distribution[protocol]["Total Non-Compliance"].update(
            set([msg_type for msg_type in js["Message Types"][protocol] if len(js["Message Types"][protocol][msg_type]) > 0])
        )
        for msg_type in js["Message Types"][protocol]:
            for criteria in js["Message Types"][protocol][msg_type]:
                temp_protocol_criteria_type_distribution[protocol][criteria].add(msg_type)

        if protocol not in table_protocol_criteria_type_distribution:
            table_protocol_criteria_type_distribution[protocol] = {}
        total_non_compliance_count = len(temp_protocol_criteria_type_distribution[protocol]["Total Non-Compliance"])
        for criteria in ["Undefined Message", "Invalid Header", "Undefined Attributes", "Invalid Attributes", "Invalid Semantics"]:
            if criteria in temp_protocol_criteria_type_distribution[protocol]:
                criteria_count = len(temp_protocol_criteria_type_distribution[protocol][criteria])
            else:
                criteria_count = 0
            if total_non_compliance_count != 0:
                percent = criteria_count / total_non_compliance_count * 100
                # table_protocol_criteria_type_distribution[protocol][criteria] = f"{criteria_count}/{total_non_compliance_count}"
                table_protocol_criteria_type_distribution[protocol][criteria] = f"{criteria_count}"
            else:
                table_protocol_criteria_type_distribution[protocol][criteria] = f"N/A"
        table_protocol_criteria_type_distribution[protocol]["Non-Compliant Types"] = total_non_compliance_count
        total_count = len(temp_protocol_criteria_type_distribution[protocol]["Total"])
        table_protocol_criteria_type_distribution[protocol]["All Types"] = total_count

        if protocol == "STUN":
            table_protocol_criteria_type_distribution["STUN/TURN"] = table_protocol_criteria_type_distribution.pop("STUN")


table_app_criteria_type_distribution = {}
temp_app_criteria_type_distribution = {}


def update_app_criteria_type_distribution(app_name, js):
    if app_name not in temp_app_criteria_type_distribution:
        temp_app_criteria_type_distribution[app_name] = defaultdict(set)
    for protocol in js["Message Types"]:
        for msg_type in js["Message Types"][protocol]:
            temp_app_criteria_type_distribution[app_name]["Total"].add(msg_type)
            if len(js["Message Types"][protocol][msg_type]) != 0:
                temp_app_criteria_type_distribution[app_name]["Total Non-Compliance"].add(msg_type)
            for criteria in js["Message Types"][protocol][msg_type]:
                temp_app_criteria_type_distribution[app_name][criteria].add(msg_type)

    if app_name not in table_app_criteria_type_distribution:
        table_app_criteria_type_distribution[app_name] = {}
    total_non_compliance_count = len(temp_app_criteria_type_distribution[app_name]["Total Non-Compliance"])
    for criteria in ["Undefined Message", "Invalid Header", "Undefined Attributes", "Invalid Attributes", "Invalid Semantics"]:
        if criteria in temp_app_criteria_type_distribution[app_name]:
            criteria_count = len(temp_app_criteria_type_distribution[app_name][criteria])
        else:
            criteria_count = 0
        if total_non_compliance_count != 0:
            percent = criteria_count / total_non_compliance_count * 100
            # table_app_criteria_type_distribution[app_name][criteria] = f"{criteria_count}/{total_non_compliance_count}"
            table_app_criteria_type_distribution[app_name][criteria] = f"{criteria_count}"
        else:
            table_app_criteria_type_distribution[app_name][criteria] = f"N/A"
    table_app_criteria_type_distribution[app_name]["Non-Compliant Types"] = total_non_compliance_count
    total_count = len(temp_app_criteria_type_distribution[app_name]["Total"])
    table_app_criteria_type_distribution[app_name]["All Types"] = total_count


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
            table_app_criteria_message_distribution[app_name][criteria] = f"{percent:.1f}%"
        else:
            table_app_criteria_message_distribution[app_name][criteria] = f"N/A"


table_app_standard_packet_distribution = {}
temp_app_standard_packet_distribution = {}


def update_app_standard_packet_distribution(app_name, js):
    if app_name not in temp_app_standard_packet_distribution:
        temp_app_standard_packet_distribution[app_name] = defaultdict(int)
    temp_app_standard_packet_distribution[app_name]["Proprietary Header"] += js["Packet Count (Proprietary Header)"]
    temp_app_standard_packet_distribution[app_name]["Unknown"] += js["Packet Count (Protocol)"]["Unknown"]["Total Packets"]
    temp_app_standard_packet_distribution[app_name]["Pure Standard"] += js["Packet Count (Pure Standard)"]
    temp_app_standard_packet_distribution[app_name]["Compliant Pure Standard"] += js["Packet Count (Compliant Pure Standard)"]
    temp_app_standard_packet_distribution[app_name]["Total"] += js["Packet Count (Total)"]

    if app_name not in table_app_standard_packet_distribution:
        table_app_standard_packet_distribution[app_name] = {}
    total = temp_app_standard_packet_distribution[app_name]["Total"]
    total_k = round(total / 1000)
    pure_standard = temp_app_standard_packet_distribution[app_name]["Pure Standard"]
    pure_standard_k = round(pure_standard / 1000)
    compliant_pure_standard = temp_app_standard_packet_distribution[app_name]["Compliant Pure Standard"]
    compliant_pure_standard_k = round(compliant_pure_standard / 1000)
    pty_hd = temp_app_standard_packet_distribution[app_name]["Proprietary Header"]
    pty_hd_k = round(pty_hd / 1000)
    unknown = temp_app_standard_packet_distribution[app_name]["Unknown"]
    unknown_k = round(unknown / 1000)
    table_app_standard_packet_distribution[app_name]["Compliant Standard"] = f"{compliant_pure_standard_k}k"
    table_app_standard_packet_distribution[app_name]["Compliant Standard [Percent]"] = f"{compliant_pure_standard/total*100:.1f}%"
    table_app_standard_packet_distribution[app_name]["Non-Compliant Standard"] = f"{pure_standard_k - compliant_pure_standard_k}k"
    table_app_standard_packet_distribution[app_name]["Non-Compliant Standard [Percent]"] = f"{(pure_standard - compliant_pure_standard)/total*100:.1f}%"
    table_app_standard_packet_distribution[app_name]["Standard with Proprietary Header"] = f"{pty_hd_k}k"
    table_app_standard_packet_distribution[app_name]["Standard with Proprietary Header [Percent]"] = f"{pty_hd/total*100:.1f}%"
    table_app_standard_packet_distribution[app_name]["Proprietary"] = f"{unknown_k}k"
    table_app_standard_packet_distribution[app_name]["Proprietary [Percent]"] = f"{unknown/total*100:.1f}%"
    table_app_standard_packet_distribution[app_name]["Total Datagrams"] = f"{total_k}k"


table_app_raw_summary = {}
table_app_filtered_summary = {}
table_app_twofilter_summary = {"Total": {}}
table_app_twostage_summary = {}
table_app_percall_summary = {}
temp_app_dataset_summary = {}


def update_app_dataset_summary(app_name, js):
    if app_name not in temp_app_dataset_summary:
        temp_app_dataset_summary[app_name] = defaultdict(int)
        temp_app_dataset_summary[app_name]["UDP Streams Raw List"] = []
        temp_app_dataset_summary[app_name]["UDP Streams Filtered List"] = []
        temp_app_dataset_summary[app_name]["UDP Streams Total List"] = []
        temp_app_dataset_summary[app_name]["TCP Streams Raw List"] = []
        temp_app_dataset_summary[app_name]["TCP Streams Filtered List"] = []
        temp_app_dataset_summary[app_name]["TCP Streams Total List"] = []

    temp_app_dataset_summary[app_name]["Traffic Count"] += 1
    temp_app_dataset_summary[app_name]["Total Duration"] += js["Call Duration"]

    temp_app_dataset_summary[app_name]["Raw Volume"] += js["Traffic Volume (Raw)"]
    temp_app_dataset_summary[app_name]["Filtered Volume"] += js["Traffic Volume (Filtered)"]
    temp_app_dataset_summary[app_name]["Total Volume"] += js["Traffic Volume (Total)"]

    temp_app_dataset_summary[app_name]["Raw Packets"] += js["Packet Count (Raw)"]
    temp_app_dataset_summary[app_name]["Filtered Packets"] += js["Packet Count (Filtered)"]
    temp_app_dataset_summary[app_name]["Total Packets"] += js["Packet Count (Total)"]

    temp_app_dataset_summary[app_name]["Compliant Packets"] += js["Packet Count (Compliant Proprietary Header)"] + js["Packet Count (Compliant Pure Standard)"]
    temp_app_dataset_summary[app_name]["Compliant Customized Packets"] += js["Packet Count (Compliant Proprietary Header)"]
    temp_app_dataset_summary[app_name]["Compliant Standard Packets"] += js["Packet Count (Compliant Pure Standard)"]
    temp_app_dataset_summary[app_name]["Non-Compliant Customized Packets"] += js["Packet Count (Proprietary Header)"] - js["Packet Count (Compliant Proprietary Header)"]
    temp_app_dataset_summary[app_name]["Non-Compliant Standard Packets"] += js["Packet Count (Pure Standard)"] - js["Packet Count (Compliant Pure Standard)"]
    temp_app_dataset_summary[app_name]["Proprietary Header Packets"] += js["Packet Count (Proprietary Header)"]
    temp_app_dataset_summary[app_name]["Standard Packets"] += js["Packet Count (Pure Standard)"]
    temp_app_dataset_summary[app_name]["Unknown Packets"] += js["Packet Count (Protocol)"]["Unknown"]["Total Packets"]

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

    temp_app_dataset_summary[app_name]["UDP Streams Raw List"].append(js["Stream Count (Transport)"]["UDP"]["Raw"])
    temp_app_dataset_summary[app_name]["UDP Streams Filtered List"].append(js["Stream Count (Transport)"]["UDP"]["Filtered"])
    temp_app_dataset_summary[app_name]["UDP Streams Total List"].append(js["Stream Count (Transport)"]["UDP"]["Total"])

    temp_app_dataset_summary[app_name]["TCP Streams Raw List"].append(js["Stream Count (Transport)"]["TCP"]["Raw"])
    temp_app_dataset_summary[app_name]["TCP Streams Filtered List"].append(js["Stream Count (Transport)"]["TCP"]["Filtered"])
    temp_app_dataset_summary[app_name]["TCP Streams Total List"].append(js["Stream Count (Transport)"]["TCP"]["Total"])

    if app_name not in table_app_raw_summary:
        table_app_raw_summary[app_name] = {}
    if app_name not in table_app_filtered_summary:
        table_app_filtered_summary[app_name] = {}
    if app_name not in table_app_percall_summary:
        table_app_percall_summary[app_name] = {}
    if app_name not in table_app_twofilter_summary:
        table_app_twofilter_summary[app_name] = {}
    if app_name not in table_app_twostage_summary:
        table_app_twostage_summary[app_name] = {
            "Stage1 Filtered UDP Streams": 0,
            "Stage1 Filtered UDP Packets": 0,
            "Stage2 Filtered UDP Streams": 0,
            "Stage2 Filtered UDP Packets": 0,
            "Stage1 Filtered TCP Streams": 0,
            "Stage1 Filtered TCP Packets": 0,
            "Stage2 Filtered TCP Streams": 0,
            "Stage2 Filtered TCP Packets": 0,
        }

    total_duration_min = temp_app_dataset_summary[app_name]["Total Duration"] / 60

    # avg_udp_streams_raw = temp_app_dataset_summary[app_name]["Raw UDP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    # avg_udp_streams_filtered = temp_app_dataset_summary[app_name]["Filtered UDP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    # avg_udp_streams = temp_app_dataset_summary[app_name]["Total UDP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]

    # avg_tcp_streams_raw = temp_app_dataset_summary[app_name]["Raw TCP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    # avg_tcp_streams_filtered = temp_app_dataset_summary[app_name]["Filtered TCP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]
    # avg_tcp_streams = temp_app_dataset_summary[app_name]["Total TCP Streams"] / temp_app_dataset_summary[app_name]["Traffic Count"]

    raw_volume_mb = temp_app_dataset_summary[app_name]["Raw Volume"] / 1024 / 1024
    filtered_volume_mb = temp_app_dataset_summary[app_name]["Filtered Volume"] / 1024 / 1024
    total_volume_mb = temp_app_dataset_summary[app_name]["Total Volume"] / 1024 / 1024

    raw_packets_k = round(temp_app_dataset_summary[app_name]["Raw Packets"] / 1000)
    filtered_packets_k = round(temp_app_dataset_summary[app_name]["Filtered Packets"] / 1000)
    total_packets_k = round(temp_app_dataset_summary[app_name]["Total Packets"] / 1000)

    raw_udp_datagrams_k = round(temp_app_dataset_summary[app_name]["Raw UDP Packets"] / 1000)
    filtered_udp_datagrams_k = round(temp_app_dataset_summary[app_name]["Filtered UDP Packets"] / 1000)
    total_udp_datagrams_k = round(temp_app_dataset_summary[app_name]["Total UDP Packets"] / 1000)

    raw_tcp_segments_k = round(temp_app_dataset_summary[app_name]["Raw TCP Packets"] / 1000)
    filtered_tcp_segments_k = round(temp_app_dataset_summary[app_name]["Filtered TCP Packets"] / 1000)
    total_tcp_segments_k = round(temp_app_dataset_summary[app_name]["Total TCP Packets"] / 1000)

    median_udp_streams_raw = median(temp_app_dataset_summary[app_name]["UDP Streams Raw List"])
    median_udp_streams_filtered = median(temp_app_dataset_summary[app_name]["UDP Streams Filtered List"])
    median_udp_streams_total = median(temp_app_dataset_summary[app_name]["UDP Streams Total List"])

    median_tcp_streams_raw = median(temp_app_dataset_summary[app_name]["TCP Streams Raw List"])
    median_tcp_streams_filtered = median(temp_app_dataset_summary[app_name]["TCP Streams Filtered List"])
    median_tcp_streams_total = median(temp_app_dataset_summary[app_name]["TCP Streams Total List"])

    table_app_raw_summary[app_name]["Total Duration (min)"] = f"{total_duration_min:.1f}"
    table_app_raw_summary[app_name]["Total Volume (MB)"] = f"{raw_volume_mb:.1f}"
    table_app_raw_summary[app_name]["Calls"] = temp_app_dataset_summary[app_name]["Traffic Count"]
    table_app_raw_summary[app_name]["UDP Datagrams"] = f"{raw_udp_datagrams_k}k"
    # table_app_raw_summary[app_name]["Median UDP Streams"] = f"{median_udp_streams_raw}"
    table_app_raw_summary[app_name]["UDP Streams"] = temp_app_dataset_summary[app_name]["Raw UDP Streams"]
    table_app_raw_summary[app_name]["TCP Segments"] = f"{raw_tcp_segments_k}k"
    # table_app_raw_summary[app_name]["TCP Segments"] = temp_app_dataset_summary[app_name]["Raw TCP Packets"]
    # table_app_raw_summary[app_name]["Median TCP Streams"] = f"{median_tcp_streams_raw}"
    table_app_raw_summary[app_name]["TCP Streams"] = temp_app_dataset_summary[app_name]["Raw TCP Streams"]

    # table_app_raw_summary[app_name]["raw"] = raw_packets_k
    # table_app_raw_summary[app_name]["filter1"] = filtered_packets_k
    # table_app_raw_summary[app_name]["filter1 [Percent]"] = f"{100 - (filtered_packets_k/raw_packets_k)*100:.1f}%"
    # table_app_raw_summary[app_name]["filter1 stream"] = median_udp_streams_raw
    # table_app_raw_summary[app_name]["filter2"] = total_packets_k
    # table_app_raw_summary[app_name]["filter2 [Percent]"] = f"{100 - (total_packets_k/raw_packets_k)*100:.1f}%"
    # table_app_raw_summary[app_name]["filter2 stream"] = median_udp_streams_total

    # table_app_filtered_summary[app_name]["Traffic Volume (MB) [Ratio]"] = f"{total_volume_mb:.1f}/{raw_volume_mb:.1f}"
    table_app_filtered_summary[app_name]["Volume (MB)"] = f"{total_volume_mb:.1f}"
    table_app_filtered_summary[app_name]["Volume (MB) [Percent]"] = f"{(total_volume_mb/raw_volume_mb)*100:.1f}%"
    # table_app_filtered_summary[app_name]["UDP Datagrams [Ratio]"] = f"{total_udp_datagrams_k}k/{raw_udp_datagrams_k}k"
    table_app_filtered_summary[app_name]["UDP Datagrams"] = f"{total_udp_datagrams_k}k"
    table_app_filtered_summary[app_name]["UDP Datagrams [Percent]"] = f"{(total_udp_datagrams_k/raw_udp_datagrams_k)*100:.1f}%"
    # table_app_filtered_summary[app_name]["Median UDP Streams [Ratio]"] = f"{median_udp_streams_total}/{median_udp_streams_raw}"
    # table_app_filtered_summary[app_name]["Median UDP Streams"] = f"{median_udp_streams_total}"
    # table_app_filtered_summary[app_name]["Median UDP Streams [Percent]"] = f"{(median_udp_streams_total/median_udp_streams_raw)*100:.1f}%"
    table_app_filtered_summary[app_name]["UDP Streams"] = temp_app_dataset_summary[app_name]["Total UDP Streams"]
    table_app_filtered_summary[app_name]["UDP Streams [Percent]"] = f"{(temp_app_dataset_summary[app_name]['Total UDP Streams']/temp_app_dataset_summary[app_name]['Raw UDP Streams'])*100:.1f}%"
    # table_app_filtered_summary[app_name]["TCP Segments [Ratio]"] = f"{total_tcp_segments_k}k/{raw_tcp_segments_k}k"
    table_app_filtered_summary[app_name]["TCP Segments"] = temp_app_dataset_summary[app_name]["Total TCP Packets"]
    table_app_filtered_summary[app_name]["TCP Segments [Percent]"] = f"{(total_tcp_segments_k/raw_tcp_segments_k)*100:.1f}%"
    # table_app_filtered_summary[app_name]["Median TCP Streams [Ratio]"] = f"{median_tcp_streams_total}/{median_tcp_streams_raw}"
    # table_app_filtered_summary[app_name]["Median TCP Streams"] = f"{median_tcp_streams_total}"
    # table_app_filtered_summary[app_name]["Median TCP Streams [Percent]"] = f"{(median_tcp_streams_total/median_tcp_streams_raw)*100:.1f}%"
    table_app_filtered_summary[app_name]["TCP Streams"] = temp_app_dataset_summary[app_name]["Total TCP Streams"]
    table_app_filtered_summary[app_name]["TCP Streams [Percent]"] = f"{(temp_app_dataset_summary[app_name]['Total TCP Streams']/temp_app_dataset_summary[app_name]['Raw TCP Streams'])*100:.1f}%"

    toatl_udp_datagrams = temp_app_dataset_summary[app_name]["Total UDP Packets"]
    total_tcp_segments = temp_app_dataset_summary[app_name]["Total TCP Packets"]
    total_volume_kb = temp_app_dataset_summary[app_name]["Total Volume"] / 1024

    table_app_percall_summary[app_name]["Average Volume Rate (KB/s)"] = f"{total_volume_kb/temp_app_dataset_summary[app_name]['Total Duration']:.1f}"
    table_app_percall_summary[app_name]["Median UDP Streams"] = f"{median_udp_streams_total}"
    # table_app_percall_summary[app_name]["Average UDP Datagrams"] = f"{total_udp_datagrams_k/temp_app_dataset_summary[app_name]['Traffic Count']:.1f}k"
    table_app_percall_summary[app_name]["Average UDP Datagrams Rate"] = f"{toatl_udp_datagrams/temp_app_dataset_summary[app_name]['Total Duration']:.1f}"
    # table_app_percall_summary[app_name]["Median TCP Streams"] = f"{median_tcp_streams_total}"
    # table_app_percall_summary[app_name]["Average TCP Segments"] = f"{total_tcp_segments_k/temp_app_dataset_summary[app_name]['Traffic Count']:.1f}k"
    # table_app_percall_summary[app_name]["Average TCP Segments Rate"] = f"{total_tcp_segments/temp_app_dataset_summary[app_name]['Total Duration']:.1f}"

    table_app_twofilter_summary[app_name]["Raw"] = temp_app_dataset_summary[app_name]["Raw Packets"]
    table_app_twofilter_summary[app_name]["Filter1"] = temp_app_dataset_summary[app_name]["Filtered Packets"]
    table_app_twofilter_summary[app_name]["Filter1 Diff"] = temp_app_dataset_summary[app_name]["Raw Packets"] - temp_app_dataset_summary[app_name]["Filtered Packets"]
    table_app_twofilter_summary[app_name]["Filter1 Diff [Percent]"] = (table_app_twofilter_summary[app_name]["Filter1 Diff"] / temp_app_dataset_summary[app_name]["Raw Packets"]) * 100
    table_app_twofilter_summary[app_name]["Filter2"] = temp_app_dataset_summary[app_name]["Total Packets"]
    table_app_twofilter_summary[app_name]["Filter2 Diff"] = temp_app_dataset_summary[app_name]["Filtered Packets"] - temp_app_dataset_summary[app_name]["Total Packets"]
    table_app_twofilter_summary[app_name]["Filter2 Diff [Percent]"] = (table_app_twofilter_summary[app_name]["Filter2 Diff"] / temp_app_dataset_summary[app_name]["Raw Packets"]) * 100
    table_app_twofilter_summary["Total"]["Raw"] = sum([table_app_twofilter_summary[a_name]["Raw"] for a_name in table_app_twofilter_summary if a_name != "Total"])
    table_app_twofilter_summary["Total"]["Filter1"] = sum([table_app_twofilter_summary[a_name]["Filter1"] for a_name in table_app_twofilter_summary if a_name != "Total"])
    table_app_twofilter_summary["Total"]["Filter1 Diff"] = table_app_twofilter_summary["Total"]["Raw"] - table_app_twofilter_summary["Total"]["Filter1"]
    table_app_twofilter_summary["Total"]["Filter1 Diff [Percent]"] = (table_app_twofilter_summary["Total"]["Filter1 Diff"] / table_app_twofilter_summary["Total"]["Raw"]) * 100
    table_app_twofilter_summary["Total"]["Filter2"] = sum([table_app_twofilter_summary[a_name]["Filter2"] for a_name in table_app_twofilter_summary if a_name != "Total"])
    table_app_twofilter_summary["Total"]["Filter2 Diff"] = table_app_twofilter_summary["Total"]["Filter1"] - table_app_twofilter_summary["Total"]["Filter2"]
    table_app_twofilter_summary["Total"]["Filter2 Diff [Percent]"] = (table_app_twofilter_summary["Total"]["Filter2 Diff"] / table_app_twofilter_summary["Total"]["Raw"]) * 100

    table_app_twostage_summary[app_name]["Stage1 Filtered UDP Streams"] += js["Stage 1 Filtered Streams Count"]["UDP"]
    table_app_twostage_summary[app_name]["Stage1 Filtered UDP Packets"] += js["Stage 1 Filtered Packets Count"]["UDP"]
    table_app_twostage_summary[app_name]["Stage2 Filtered UDP Streams"] += js["Stage 2 Filtered Streams Count"]["UDP"]
    table_app_twostage_summary[app_name]["Stage2 Filtered UDP Packets"] += js["Stage 2 Filtered Packets Count"]["UDP"]
    table_app_twostage_summary[app_name]["Stage1 Filtered TCP Streams"] += js["Stage 1 Filtered Streams Count"]["TCP"]
    table_app_twostage_summary[app_name]["Stage1 Filtered TCP Packets"] += js["Stage 1 Filtered Packets Count"]["TCP"]
    table_app_twostage_summary[app_name]["Stage2 Filtered TCP Streams"] += js["Stage 2 Filtered Streams Count"]["TCP"]
    table_app_twostage_summary[app_name]["Stage2 Filtered TCP Packets"] += js["Stage 2 Filtered Packets Count"]["TCP"]

table_test_summary = {}


def update_test_summary(test_name, js):
    if test_name not in table_test_summary:
        table_test_summary[test_name] = {}
    table_test_summary[test_name]["Error Count"] = js["Error Count"]
    table_test_summary[test_name]["P2P"] = js["P2P Found?"]
    total_total = js["Packet Count (Total)"]
    for protocol in js["Packet Count (Protocol)"]:
        if protocol == "Unknown":
            unknown_percent = js["Packet Count (Protocol)"][protocol]["Total Packets"] / total_total * 100
            table_test_summary[test_name]["Proprietary (Packet)"] = unknown_percent
            continue
        compliant_count = js["Packet Count (Protocol)"][protocol]["Compliant Packets"]
        packet_count = js["Packet Count (Protocol)"][protocol]["Total Packets"]
        total = js["Packet Count (Protocol)"][protocol]["Total Packets"]
        compliance_percent = (1 - compliant_count / total) * 100
        table_test_summary[test_name][protocol + "(Compliance)"] = compliance_percent
        packet_percent = packet_count / total_total * 100
        table_test_summary[test_name][protocol + "(Packet)"] = packet_percent


def main(app_name, csv_file, json_file):
    df = read_from_csv(csv_file)
    js = read_from_json(json_file)
    file_name = csv_file.split("/")[-1].split(".")[0]

    update_app_protocol_modifications(app_name, js)
    update_app_protocol_pty_pkt_distribution(app_name, js)
    # update_app_proprietary_message_distribution(app_name, js)
    update_app_protocol_message_distribution(app_name, js)
    update_app_protocol_packet_distribution(app_name, js)
    update_app_protocol_type_compliance(app_name, js)
    update_app_protocol_message_compliance(app_name, js)
    update_protocol_criteria_type_distribution(js)
    update_app_criteria_type_distribution(app_name, js)
    update_app_criteria_message_distribution(app_name, js)
    update_app_standard_packet_distribution(app_name, js)
    update_app_dataset_summary(app_name, js)
    update_test_summary(file_name, js)


def compliance_plot():
    # fig, ax = plt.subplots()
    # ax.axvline(x=0, linewidth=2, color="black")
    # ax.axhline(y=0, linewidth=2, color="black")
    # marker_list = ["o", "s", "D", "^", "v"]
    # for idx, app_name in enumerate(temp_app_protocol_message_compliance):
    #     total_compliant = temp_app_protocol_message_compliance[app_name]["Compliant Messages"]
    #     total_standard = temp_app_protocol_message_compliance[app_name]["Standard Messages"]
    #     total_msgs = temp_app_protocol_message_compliance[app_name]["Total Messages"]
    #     compliant_ratio = (total_compliant / total_standard * 100) if total_msgs else 0
    #     standard_ratio = (total_standard / total_msgs * 100) if total_msgs else 0
    #     ax.scatter(compliant_ratio, standard_ratio, label=app_name, marker=marker_list[idx % len(marker_list)], s=100)

    # for spine in ax.spines.values():
    #     spine.set_visible(False)

    # ax.set_xlim(-5, 105)
    # ax.set_ylim(-5, 105)

    # ax.set_xlabel("Ratio of Compliant Messages (%)")
    # ax.set_ylabel("Ratio of Standard Messages (%)")
    # # ax.set_title("Protocol Compliance vs Application Compliance")
    # ax.grid(True)
    # ax.legend(loc="lower left")
    # plt.show()

    catalogs = list(temp_app_dataset_summary.keys())

    pty_packets = [temp_app_dataset_summary[c]["Unknown Packets"] for c in catalogs]
    pty_hdr_packets = [temp_app_dataset_summary[c]["Proprietary Header Packets"] for c in catalogs]
    std_packets = [temp_app_dataset_summary[c]["Standard Packets"] for c in catalogs]
    total_packets = [temp_app_dataset_summary[c]["Total Packets"] for c in catalogs]
    assert all(np.array(total_packets) == np.array(pty_packets) + np.array(pty_hdr_packets) + np.array(std_packets)), "Total Packets != Sum of All Types"

    pty_pkt_ratio = np.array(pty_packets) / np.array(total_packets) * 100
    pty_hdr_pkt_ratio = np.array(pty_hdr_packets) / np.array(total_packets) * 100
    std_pkt_ratio = np.array(std_packets) / np.array(total_packets) * 100

    compliant_std_messages = [temp_app_protocol_message_compliance[c]["Compliant Messages"] for c in catalogs]
    total_std_messages = [temp_app_protocol_message_compliance[c]["Standard Messages"] for c in catalogs]
    non_compliant_std_messages = np.array(total_std_messages) - np.array(compliant_std_messages)

    compliant_std_msg_ratio = np.array(compliant_std_messages) / np.array(total_std_messages) * 100
    non_compliant_std_msg_ratio = np.array(non_compliant_std_messages) / np.array(total_std_messages) * 100

    x = np.arange(len(catalogs))

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.bar(x, pty_pkt_ratio, bottom=std_pkt_ratio + pty_hdr_pkt_ratio, label="Proprietary Datagrams", color="gray")
    ax.bar(x, pty_hdr_pkt_ratio, bottom=std_pkt_ratio, label="Proprietary Header Datagrams", color="orange")
    ax.bar(x, std_pkt_ratio, label="Standard Datagrams", color="green")
    plt.xlabel("Applications")
    plt.ylabel("Datagram Percentages (%)")
    # plt.title("Datagram Distribution across Applications")
    plt.xticks(x, catalogs)
    plt.legend(loc="lower right")

    fig2, ax2 = plt.subplots(figsize=(8, 6))
    ax2.bar(x, compliant_std_msg_ratio)
    # ax2.bar(x, compliant_std_msg_ratio, bottom=non_compliant_std_msg_ratio, label="Compliant Standard Messages")
    # ax2.bar(x, non_compliant_std_msg_ratio, label="Non-Compliant Standard Messages")
    plt.xlabel("Applications")
    plt.ylabel("Message Percentages (%)")
    # plt.title("Compliant Standard Message Percentage across Applications")
    plt.xticks(x, catalogs)

    plt.show()

    # group_labels = ["std proto (all compliant)", "std proto (has non-compliant)", "pty hdr + std proto (all compliant)", "pty hdr + std proto (has non-compliant)", "pty proto"]
    # catalogs = list(temp_app_dataset_summary.keys())

    # data = []
    # for c in catalogs:
    #     one_data = [
    #         temp_app_dataset_summary[c]["Compliant Standard Packets"] / temp_app_dataset_summary[c]["Total Packets"],
    #         temp_app_dataset_summary[c]["Non-Compliant Standard Packets"] / temp_app_dataset_summary[c]["Total Packets"],
    #         temp_app_dataset_summary[c]["Compliant Customized Packets"] / temp_app_dataset_summary[c]["Total Packets"],
    #         temp_app_dataset_summary[c]["Non-Compliant Customized Packets"] / temp_app_dataset_summary[c]["Total Packets"],
    #         temp_app_dataset_summary[c]["Unknown Packets"] / temp_app_dataset_summary[c]["Total Packets"],
    #     ]
    #     data.append(one_data)
    # data = np.array(data)
    # data = np.where(data == 0, 1e-10, data) * 100
    # data_T = data.T  # Transpose to [groups][catalogs]

    # # ========== Original Plot (Applications on x-axis) ==========
    # x = np.arange(len(catalogs))
    # width = 0.15

    # fig1, ax1 = plt.subplots(figsize=(12, 6))
    # for i, group in enumerate(group_labels):
    #     offset = width * (i - len(group_labels) / 2)
    #     ax1.bar(x + offset, data_T[i], width, label=group)

    # ax1.set_xlabel("Applications")
    # ax1.set_ylabel("Datagram Percentages (%)")
    # ax1.set_title("Datagram Percentages across Applications")
    # ax1.set_xticks(x)
    # ax1.set_xticklabels(catalogs)
    # ax1.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    # plt.tight_layout()
    # plt.show()

    # # ========== Flipped Plot (Protocols on x-axis) ==========
    # fig2, ax2 = plt.subplots(figsize=(12, 6))
    # x_new = np.arange(len(group_labels))
    # width_new = 0.15

    # # Plot applications as clustered bars under each protocol
    # for i, app in enumerate(catalogs):
    #     offset = width_new * (i - len(catalogs) / 2)
    #     ax2.bar(x_new + offset, data[i], width_new, label=app)

    # ax2.set_xlabel("Protocols")
    # ax2.set_ylabel("Datagram Percentages (%)")
    # ax2.set_title("Flipped: Datagram Percentages across Protocols")
    # ax2.set_xticks(x_new)
    # ax2.set_xticklabels(group_labels, rotation=45, ha="right")
    # ax2.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    # plt.tight_layout()
    # plt.show()


if __name__ == "__main__":
    # python analyzer.py --config config.json

    parser = argparse.ArgumentParser(description="Determine RTC protocol compliance.")
    parser.add_argument("--config", type=str, default="config.json", help="Path to the configuration file.")
    args = parser.parse_args()
    config_path = args.config
    pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, precall_noise_duration, postcall_noise_duration, plugin_target_folder, plugin_source_folder = load_config(config_path)

    for app_name in apps:
        for test_name in tests:
            if "noise" in test_name:
                continue
            for test_round in rounds:
                for client_type in client_types:
                    for part in range(1, tests[test_name] + 1):
                        main_folder = f"{save_main_folder}" + "/" + app_name + "/" + test_name
                        csv_file = f"{main_folder}/{app_name}_{test_name}_{test_round}_{client_type}_part{part}.csv"
                        json_file = f"{main_folder}/{app_name}_{test_name}_{test_round}_{client_type}_part{part}.json"
                        main(app_name, csv_file, json_file)

    json_app_protocol_modifications = {
        app: {
            protocol: {
                msg_type: {
                    criteria: {
                        field: {
                            value: json_app_protocol_modifications[app][protocol][msg_type][criteria][field][value]
                            for value in sorted(json_app_protocol_modifications[app][protocol][msg_type][criteria][field])
                        }
                        for field in sorted(json_app_protocol_modifications[app][protocol][msg_type][criteria])
                    }
                    for criteria in sorted(json_app_protocol_modifications[app][protocol][msg_type])
                }
                for msg_type in sorted(json_app_protocol_modifications[app][protocol])
            }
            for protocol in json_app_protocol_modifications[app]
        }
        for app in json_app_protocol_modifications
    }
    for app in json_app_protocol_modifications:
        for protocol in json_app_protocol_modifications[app]:
            for msg_type, msg_type_dict in json_app_protocol_modifications[app][protocol].items():
                msg_type_dict["Total Messages"] = temp_app_message_type_count[app][protocol][msg_type]["Total Messages"]
                msg_type_dict["Compliant Messages"] = temp_app_message_type_count[app][protocol][msg_type]["Compliant Messages"]
                msg_type_dict["Non-Compliant Messages"] = temp_app_message_type_count[app][protocol][msg_type]["Non-Compliant Messages"]
    save_dict_to_json(json_app_protocol_modifications, f"{save_main_folder}/app_protocol_modifications.json")

    df_app_protocol_pty_pkt_distribution = pd.DataFrame.from_dict(table_app_protocol_pty_pkt_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    columns = []
    for item in ["STUN/TURN", "RTP", "RTCP", "QUIC", "Total Proprietary Header"]:
        columns += [item, item + " [Percent]"]
    df_app_protocol_pty_pkt_distribution = df_app_protocol_pty_pkt_distribution.set_index("Applications").reindex(index=apps, columns=columns).reset_index()
    df_app_protocol_pty_pkt_distribution = df_app_protocol_pty_pkt_distribution.fillna("N/A")
    df_app_protocol_pty_pkt_distribution.to_csv(f"{save_main_folder}/app_protocol_pty_pkt_distribution.csv", index=False)

    # df_proprietary_app_message_distribution = pd.DataFrame.from_dict(table_proprietary_app_message_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    # df_proprietary_app_message_distribution.to_csv(f"{save_main_folder}/proprietary_app_message_distribution.csv", index=False)
    # df_proprietary_app_message_distribution = df_proprietary_app_message_distribution.fillna("N/A")
    # print(df_proprietary_app_message_distribution)

    df_app_protocol_message_distribution = pd.DataFrame.from_dict(table_app_protocol_message_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_protocol_message_distribution = df_app_protocol_message_distribution.set_index("Applications").reindex(index=apps, columns=["STUN/TURN", "RTP", "RTCP", "QUIC", "Proprietary"]).reset_index()
    df_app_protocol_message_distribution = df_app_protocol_message_distribution.fillna("N/A")
    df_app_protocol_message_distribution.to_csv(f"{save_main_folder}/app_protocol_message_distribution.csv", index=False)
    print(df_app_protocol_message_distribution)

    # df_app_protocol_packet_distribution = pd.DataFrame.from_dict(table_app_protocol_packet_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    # df_app_protocol_packet_distribution = df_app_protocol_packet_distribution.fillna("N/A")
    # df_app_protocol_packet_distribution.to_csv(f"{save_main_folder}/app_protocol_packet_distribution.csv", index=False)
    # print(df_app_protocol_packet_distribution)

    df_app_protocol_type_compliance = pd.DataFrame.from_dict(table_app_protocol_type_compliance, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_protocol_type_compliance = df_app_protocol_type_compliance.set_index("Applications").reindex(index=apps, columns=["STUN/TURN", "RTP", "RTCP", "QUIC"]).reset_index()
    df_app_protocol_type_compliance = df_app_protocol_type_compliance.fillna("N/A")
    df_app_protocol_type_compliance.to_csv(f"{save_main_folder}/app_protocol_type_compliance.csv", index=False)
    print(df_app_protocol_type_compliance)

    df_app_protocol_message_compliance = pd.DataFrame.from_dict(table_app_protocol_message_compliance, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_protocol_message_compliance = df_app_protocol_message_compliance.set_index("Applications").reindex(index=apps, columns=["STUN/TURN", "RTP", "RTCP", "QUIC"]).reset_index()
    df_app_protocol_message_compliance = df_app_protocol_message_compliance.fillna("N/A")
    df_app_protocol_message_compliance.to_csv(f"{save_main_folder}/app_protocol_message_compliance.csv", index=False)
    print(df_app_protocol_message_compliance)

    df_protocol_criteria_type_distribution = pd.DataFrame.from_dict(table_protocol_criteria_type_distribution, orient="index").reset_index().rename(columns={"index": "Protocols"})
    df_protocol_criteria_type_distribution = df_protocol_criteria_type_distribution.set_index("Protocols").reindex(index=["STUN/TURN", "RTP", "RTCP", "QUIC"]).reset_index()
    df_protocol_criteria_type_distribution.to_csv(f"{save_main_folder}/protocol_criteria_type_distribution.csv", index=False)
    print(df_protocol_criteria_type_distribution)

    df_app_criteria_type_distribution = pd.DataFrame.from_dict(table_app_criteria_type_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_criteria_type_distribution.to_csv(f"{save_main_folder}/app_criteria_type_distribution.csv", index=False)
    print(df_app_criteria_type_distribution)

    # df_app_criteria_message_distribution = pd.DataFrame.from_dict(table_app_criteria_message_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    # df_app_criteria_message_distribution.to_csv(f"{save_main_folder}/app_criteria_message_distribution.csv", index=False)
    # print(df_app_criteria_message_distribution)

    df_app_standard_packet_distribution = pd.DataFrame.from_dict(table_app_standard_packet_distribution, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_standard_packet_distribution.to_csv(f"{save_main_folder}/app_standard_packet_distribution.csv", index=False)

    df_app_raw_summary = pd.DataFrame.from_dict(table_app_raw_summary, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_raw_summary.to_csv(f"{save_main_folder}/app_raw_summary.csv", index=False)
    print(df_app_raw_summary)

    df_app_filtered_summary = pd.DataFrame.from_dict(table_app_filtered_summary, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_filtered_summary.to_csv(f"{save_main_folder}/app_filtered_summary.csv", index=False)
    print(df_app_filtered_summary)

    df_app_twofilter_summary = pd.DataFrame.from_dict(table_app_twofilter_summary, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_twofilter_summary.to_csv(f"{save_main_folder}/app_twofilter_summary.csv", index=False)
    print(df_app_twofilter_summary)
    
    df_app_twostage_summary = pd.DataFrame.from_dict(table_app_twostage_summary, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_twostage_summary.to_csv(f"{save_main_folder}/app_twostage_summary.csv", index=False)
    print(df_app_twostage_summary)

    df_app_precall_summary = pd.DataFrame.from_dict(table_app_percall_summary, orient="index").reset_index().rename(columns={"index": "Applications"})
    df_app_precall_summary.to_csv(f"{save_main_folder}/app_percall_summary.csv", index=False)
    print(df_app_precall_summary)

    df_test_summary = pd.DataFrame.from_dict(table_test_summary, orient="index").reset_index().rename(columns={"index": "Tests"})
    df_test_summary.to_csv(f"{save_main_folder}/test_summary.csv", index=False)
    df_test_summary = df_test_summary.fillna("N/A")
    print(df_test_summary)

    compliance_plot()
