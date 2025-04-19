import pyshark
from IPy import IP
import pandas as pd
import multiprocessing
import time
import sys
import argparse

from utils import *
from compliance import process_packet
from protocol_extractor import extract_protocol

this_file_location = os.path.dirname(os.path.realpath(__file__))

def count_packets(
    pcap_file,
    target_protocols,
    filter_code="",
    decode_as={},
    prev_results={},
):

    cap = pyshark.FileCapture(
        pcap_file,
        display_filter=filter_code,
        decode_as=decode_as,
        # use_json=True,
        # include_raw=True,
    )
    cap.set_debug()

    # Create a dictionary for both transport and application protocols
    protocol_dict = {"TCP": {"Unknown": 0}, "UDP": {"Unknown": 0}}
    protocol_msg_dict = {"TCP": {"Unknown": 0}, "UDP": {"Unknown": 0}}
    protocol_compliance = {"TCP": {}, "UDP": {}}
    metrics_dict = {
        "Total Messages": 0,
        "Total Packets": 0,
        "UDP Packets": 0,
        "TCP Packets": 0,
        "Proprietary Header Packets": 0,
        "Total Volume": 0,  # in bytes
    }

    log = []
    multi_proto_pkts = []
    packet_details = {}

    for key in prev_results:
        if key == "log":
            log += prev_results[key]
        elif key == "multi_proto_pkts":
            multi_proto_pkts += prev_results[key]
        elif key == "protocol_dict":
            protocol_dict = prev_results[key]
        elif key == "protocol_msg_dict":
            protocol_msg_dict = prev_results[key]
        elif key == "protocol_compliance":
            protocol_compliance = prev_results[key]
        elif key == "metrics_dict":
            metrics_dict = prev_results[key]
        elif key == "packet_details":
            packet_details = prev_results[key]

    counter = 0
    for packet in cap:
        # if packet.number == '3139': # for debugging
        #     print(packet)
        # if "RTCP" in packet:
        #     pass

        counter += 1
        packet_details[int(packet.number)] = {
            "timestamp": float(packet.sniff_timestamp),
            "transport_protocol": "TCP" if hasattr(packet, "tcp") else "UDP",
            "stream_id": int(packet.tcp.stream) if hasattr(packet, "tcp") else int(packet.udp.stream),
            "payload_size": int(packet.tcp.len) if hasattr(packet, "tcp") else (int(packet.udp.length) - 8),
        }

        metrics_dict["Total Packets"] += 1
        metrics_dict["Total Volume"] += int(packet.length)

        if counter % 1000 == 0:
            print(
                f"Packet: {packet.number} \tError Counts: {len(log)} \tMulti-Protocol Packets: {len(multi_proto_pkts)}",
                end="\r",
            )

        if "TCP" in packet:
            metrics_dict["TCP Packets"] += 1
            transport_protocol = "TCP"
        elif "UDP" in packet:
            metrics_dict["UDP Packets"] += 1
            transport_protocol = "UDP"

        protocols = []
        process_packet(packet, protocol_compliance, log, target_protocols, protocols, decode_as=decode_as)

        if len(protocols) == 0:
            protocol_dict[transport_protocol]["Unknown"] += 1
            protocol_msg_dict[transport_protocol]["Unknown"] += 1
            metrics_dict["Total Messages"] += 1
        elif len(protocols) > 1:
            multi_proto_pkts.append([transport_protocol, protocols, int(packet.number)])

        unique_protocols = set(protocols)
        for unique_actual_protocol in unique_protocols:
            if "ZOOM" in packet or "ZOOM_O" in packet or "FACETIME" in packet:
                protocol_compliance[transport_protocol][unique_actual_protocol]["Proprietary Header Packets"].add(int(packet.number))
            if protocol_dict[transport_protocol].get(unique_actual_protocol) is None:
                protocol_dict[transport_protocol][unique_actual_protocol] = 0
            protocol_dict[transport_protocol][unique_actual_protocol] += 1

        for actual_protocol in protocols:
            if protocol_msg_dict[transport_protocol].get(actual_protocol) is None:
                protocol_msg_dict[transport_protocol][actual_protocol] = 0
            if packet_details[int(packet.number)].get("rtc_protocol") is None:
                packet_details[int(packet.number)]["rtc_protocol"] = []
            protocol_msg_dict[transport_protocol][actual_protocol] += 1
            metrics_dict["Total Messages"] += 1
            packet_details[int(packet.number)]["rtc_protocol"].append(actual_protocol)

        if ("ZOOM" in packet or "ZOOM_O" in packet or "FACETIME" in packet) and len(protocols) > 0:
            metrics_dict["Proprietary Header Packets"] += 1

        assert metrics_dict["Total Packets"] == metrics_dict["UDP Packets"] + metrics_dict["TCP Packets"], "Mismatch between total packet count and sum of UDP and TCP packet count"

    print(f"Packet Results: {protocol_dict}")
    print(f"Total Packets: {metrics_dict['Total Packets']}")
    print(f"UDP Packets: {metrics_dict['UDP Packets']}")
    print(f"TCP Packets: {metrics_dict['TCP Packets']}")
    print(f"Proprietary Header Packets: {metrics_dict['Proprietary Header Packets']}")
    print(f"Multi-Protocol Packets: {len(multi_proto_pkts)}")
    print(f"Message Results: {protocol_msg_dict}")
    print(f"Total Messages: {metrics_dict['Total Messages']}")
    print(f"Error Counts: {len(log)}")

    cap.close()
    return (
        protocol_dict,
        protocol_msg_dict,
        protocol_compliance,
        metrics_dict,
        log,
        multi_proto_pkts,
        packet_details,
    )


def save_results(
    protocol_dict,
    protocol_msg_dict,
    protocol_compliance,
    metrics_dict,
    volume_list,
    packet_count_list,
    stream_count_list,
    decode_as_dict,
    stream_summary,
    packet_summary,
    file_name="protocol_analysis.xlsx",
    sheet_name="sheet1",
    filter_code="",
    log=[],
    multi_proto_pkts=[],
    p2p=False,
    raw_filter_code="",
):
    def merge_protocols(proto_dict, protocol_compliance):
        marked_protocols = set()
        for protocol in proto_dict["TCP"]:
            if protocol != "Unknown" and protocol in proto_dict["UDP"]:
                marked_protocols.add(protocol)
                if "UDP/TCP" not in proto_dict.keys():
                    proto_dict["UDP/TCP"] = {}
                tcp_count = proto_dict["TCP"][protocol]
                udp_count = proto_dict["UDP"][protocol]
                proto_dict["UDP/TCP"][protocol] = tcp_count + udp_count

        for protocol in marked_protocols:
            if "UDP/TCP" not in protocol_compliance.keys():
                protocol_compliance["UDP/TCP"] = {}
            if protocol not in protocol_compliance["UDP/TCP"]:
                tcp_compliance = protocol_compliance["TCP"].get(protocol, {})
                udp_compliance = protocol_compliance["UDP"].get(protocol, {})
                merged_compliance = deep_dict_merge(tcp_compliance, udp_compliance)
                protocol_compliance["UDP/TCP"][protocol] = merged_compliance

                protocol_compliance["TCP"].pop(protocol)
                protocol_compliance["UDP"].pop(protocol)
            proto_dict["TCP"].pop(protocol)
            proto_dict["UDP"].pop(protocol)

    def verify_json_results(data):
        stream_count = data["Stream Count (Total)"]
        packet_count = data["Packet Count (Total)"]
        message_count = data["Message Count (Total)"]
        packet_dict = data["Packet Count (Protocol)"]
        message_dict = data["Message Count (Protocol)"]

        assert (
            data["Stream Count (Total)"] == data["Stream Count (Transport)"]["UDP"]["Total"] + data["Stream Count (Transport)"]["TCP"]["Total"]
        ), "Mismatch between total stream count and sum of UDP and TCP stream count"
        assert data["Stream Count (Raw)"] >= data["Stream Count (Filtered)"] >= stream_count, "Correct Stream Count order should be Raw >= Filtered >= Total"
        assert (
            data["Packet Count (Total)"] == data["Packet Count (Transport)"]["UDP"]["Total"] + data["Packet Count (Transport)"]["TCP"]["Total"]
        ), "Mismatch between total packet count and sum of UDP and TCP packet count"
        assert data["Packet Count (Raw)"] >= data["Packet Count (Filtered)"] >= packet_count, "Correct Packet Count order should be Raw >= Filtered >= Total"
        assert data["Traffic Volume (Raw)"] >= data["Traffic Volume (Filtered)"] >= data["Traffic Volume (Total)"], "Correct Traffic Volume order should be Raw >= Filtered >= Total"
        assert message_count == sum([message_dict[protocol]["Total Messages"] for protocol in message_dict]), "Mismatch between total message count and sum of protocol message count"

        if data["Packet Count (Multi-Protocol)"] > 0:
            assert data["Packet Count (Pure Standard)"] <= sum(
                [packet_dict[protocol]["Pure Standard"] for protocol in packet_dict if protocol != "Unknown"]
            ), "Mismatch between total pure-standard packet count and sum of protocol pure-standard packet count"
        else:
            assert data["Packet Count (Pure Standard)"] == sum(
                [packet_dict[protocol]["Pure Standard"] for protocol in packet_dict if protocol != "Unknown"]
            ), "Mismatch between total pure-standard packet count and sum of protocol pure-standard packet count"

        for protocol in data["Message Count (Message Type)"]:
            compliant_sum = sum([data["Message Count (Message Type)"][protocol][type]["Compliant Messages"] for type in data["Message Count (Message Type)"][protocol]])
            assert (
                compliant_sum == data["Message Count (Protocol)"][protocol]["Compliant Messages"]
            ), f"Mismatch between total compliant message count {data['Message Count (Protocol)'][protocol]['Compliant Messages']} and sum of message type compliant message count {compliant_sum}"

        # new_packet_dict = rename_dict_key(packet_dict, "Total Packets", "Total", inplace=False)
        # rename_dict_key(new_packet_dict, "Compliant Packets", "Compliant", inplace=True)
        # new_message_dict = rename_dict_key(message_dict, "Total Messages", "Total", inplace=False)
        # rename_dict_key(new_message_dict, "Compliant Messages", "Compliant", inplace=True)
        # c = compare_shared_values(new_packet_dict, new_message_dict)
        # assert c != 1, "Message count should be greater than or equal to packet count"
        # if c == 0:  # each packet has only one message
        #     assert message_count == packet_count, "Mismatch between message count and packet count"
        #     assert packet_count == sum([packet_dict[protocol]["Total Packets"] for protocol in packet_dict]), "Mismatch between total packet count and sum of protocol packet count"

        assert message_count >= packet_count, "Mismatch between message count and packet count"
        assert packet_count <= sum([packet_dict[protocol]["Total Packets"] for protocol in packet_dict]), "Mismatch between total packet count and sum of protocol packet count"

    def save_json_results(
        log,
        multi_proto_pkts,
        protocol_compliance,
        filter_code,
        p2p,
        file_name,
        volume_list,
        packet_count_list,
        stream_count_list,
        protocol_dict,
        protocol_msg_dict,
        metrics_dict,
        decode_as_dict,
        stream_summary,
        packet_summary,
        raw_filter_code,
    ):
        log_dict = {}
        for error in log:
            if log_dict.get(error[0]) is None:
                log_dict[error[0]] = {}
            if log_dict[error[0]].get(error[1]) is None:
                log_dict[error[0]][error[1]] = []
            log_dict[error[0]][error[1]].append([error[2], error[3]])

        multi_proto_dict = {}
        for multi_proto_pkt in multi_proto_pkts:
            protocols = ", ".join(multi_proto_pkt[1])
            if multi_proto_dict.get(multi_proto_pkt[0]) is None:
                multi_proto_dict[multi_proto_pkt[0]] = {}
            if multi_proto_dict[multi_proto_pkt[0]].get(protocols) is None:
                multi_proto_dict[multi_proto_pkt[0]][protocols] = []
            multi_proto_dict[multi_proto_pkt[0]][protocols].append(multi_proto_pkt[2])

        non_compliant_pkts = {}
        message_types = {}
        message_types_count = {}
        total_nc_set = set()
        total_nc_pty_hd_set = set()
        total_nc_std_set = set()
        protocol_dict_new = {"Unknown": {"Total Packets": protocol_dict["TCP"]["Unknown"] + protocol_dict["UDP"]["Unknown"]}}
        protocol_msg_dict_new = {"Unknown": {"Total Messages": protocol_msg_dict["TCP"]["Unknown"] + protocol_msg_dict["UDP"]["Unknown"]}}
        for transport_protocol, protocols in protocol_compliance.items():
            for protocol, values in protocols.items():  # assume each protocol only under one transport protocol (UDP, TCP, or UDP/TCP), except for Unknown

                if non_compliant_pkts.get(protocol) is None:
                    non_compliant_pkts[protocol] = {}
                non_compliant_pkts[protocol]["Undefined Message"] = list(values.get("Undefined Message Packets", set()))
                non_compliant_pkts[protocol]["Invalid Header"] = list(values.get("Invalid Header Packets", set()))
                non_compliant_pkts[protocol]["Undefined Attributes"] = list(values.get("Undefined Attributes Packets", set()))
                non_compliant_pkts[protocol]["Invalid Attributes"] = list(values.get("Invalid Attributes Packets", set()))
                non_compliant_pkts[protocol]["Invalid Semantics"] = list(values.get("Invalid Semantics Packets", set()))
                # non_compliant_pkts[protocol]["Proprietary Header"] = list(values.get("Proprietary Header Packets", set()))

                if message_types.get(protocol) is None:
                    message_types[protocol] = {}
                types = values.get("Message Types", dict())
                message_types_count[protocol] = types
                for type in types:
                    # message_types[protocol][type] = list(values["Non-Compliant Types"].get(type, {}).keys())
                    # type_dict = values["Non-Compliant Types"].get(type, {})
                    # for key, value in type_dict.items():
                    #     type_dict[key] = list(value)
                    # message_types[protocol][type] = type_dict
                    error_dict = values["Non-Compliant Types"].get(type, {})
                    for criterion, field_dict in error_dict.items():
                        for field, field_values in field_dict.items():
                            # error_dict[criterion][field] = list(field_values)
                            error_dict[criterion][field] = {}
                            for field_value in field_values:
                                error_detail = f"Protocol [{protocol}], Message [{type}], Criterion [{criterion}], Field [{field}], Value [{field_value}]"
                                error_list = [pkt[1] for pkt in non_compliant_pkts[protocol][criterion]]
                                error_count = error_list.count(error_detail)
                                error_dict[criterion][field][field_value] = error_count
                    message_types[protocol][type] = error_dict

                total_packets = protocol_dict[transport_protocol][protocol]
                nc_set = set()
                for key in ["Undefined Message Packets", "Invalid Header Packets", "Undefined Attributes Packets", "Invalid Attributes Packets", "Invalid Semantics Packets"]:
                    if len(values.get(key, set())) == 0:
                        continue
                    key_set = set([item[0] for item in values[key]])
                    nc_set |= key_set
                nc_pty_hd_set = nc_set & values.get("Proprietary Header Packets", set())
                nc_std_set = nc_set - values.get("Proprietary Header Packets", set())
                total_nc_set |= nc_set
                total_nc_pty_hd_set |= nc_pty_hd_set
                total_nc_std_set |= nc_std_set
                protocol_dict_new[protocol] = {
                    "Total Packets": total_packets,
                    "Compliant Packets": total_packets - len(nc_set),
                    "Undefined Message": len(values.get("Undefined Message Packets", set())),
                    "Invalid Header": len(values.get("Invalid Header Packets", set())),
                    "Undefined Attributes": len(values.get("Undefined Attributes Packets", set())),
                    "Invalid Attributes": len(values.get("Invalid Attributes Packets", set())),
                    "Invalid Semantics": len(values.get("Invalid Semantics Packets", set())),
                    "Proprietary Header": len(values.get("Proprietary Header Packets", set())),
                    "Compliant Proprietary Header": len(values.get("Proprietary Header Packets", set())) - len(nc_pty_hd_set),
                    "Pure Standard": total_packets - len(values.get("Proprietary Header Packets", set())),
                    "Compliant Pure Standard": total_packets - len(values.get("Proprietary Header Packets", set())) - len(nc_std_set),
                }

                total_messages = protocol_msg_dict[transport_protocol][protocol]
                protocol_msg_dict_new[protocol] = {
                    "Total Messages": total_messages,
                    "Compliant Messages": total_messages
                    - values.get("Undefined Message Messages", 0)
                    - values.get("Invalid Header Messages", 0)
                    - values.get("Undefined Attributes Messages", 0)
                    - values.get("Invalid Attributes Messages", 0)
                    - values.get("Invalid Semantics Messages", 0),
                    "Undefined Message": values.get("Undefined Message Messages", 0),
                    "Invalid Header": values.get("Invalid Header Messages", 0),
                    "Undefined Attributes": values.get("Undefined Attributes Messages", 0),
                    "Invalid Attributes": values.get("Invalid Attributes Messages", 0),
                    "Invalid Semantics": values.get("Invalid Semantics Messages", 0),
                }

        data = {
            "P2P Found?": p2p,
            "Decode As": decode_as_dict,
            "Filter Code": raw_filter_code,
            "Heuristic Filter Code": filter_code,
            "Error Count": len(log),
            "Traffic Volume (Raw)": volume_list[0],
            "Traffic Volume (Filtered)": volume_list[1],
            "Traffic Volume (Total)": metrics_dict["Total Volume"],
            "Call Duration": metrics_dict["Call Duration"],
            "Stream Count (Raw)": stream_count_list[0],
            "Stream Count (Filtered)": stream_count_list[1],
            "Stream Count (Total)": metrics_dict["Total Streams"],
            "Stream Count (Transport)": stream_summary,
            "Packet Count (Multi-Protocol)": len(multi_proto_pkts),
            "Packet Count (Proprietary Header)": metrics_dict["Proprietary Header Packets"],
            "Packet Count (Compliant Proprietary Header)": metrics_dict["Proprietary Header Packets"] - len(total_nc_pty_hd_set),
            "Packet Count (Pure Standard)": metrics_dict["Total Packets"] - metrics_dict["Proprietary Header Packets"] - protocol_dict_new["Unknown"]["Total Packets"],
            "Packet Count (Compliant Pure Standard)": metrics_dict["Total Packets"]
            - metrics_dict["Proprietary Header Packets"]
            - protocol_dict_new["Unknown"]["Total Packets"]
            - len(total_nc_std_set),
            "Packet Count (Raw)": packet_count_list[0],
            "Packet Count (Filtered)": packet_count_list[1],
            "Packet Count (Total)": metrics_dict["Total Packets"],
            "Packet Count (Transport)": packet_summary,
            "Packet Count (Protocol)": protocol_dict_new,
            "Message Count (Total)": metrics_dict["Total Messages"],
            "Message Count (Protocol)": protocol_msg_dict_new,
            "Message Count (Message Type)": message_types_count,
            "Message Types": message_types,
            "Error Log": log_dict,
            "Non-Compliant Packets": non_compliant_pkts,
            "Multi-Protocol Packets": multi_proto_dict,
        }

        verify_json_results(data)

        save_dict_to_json(data, file_name + ".json")
        print(f"Results saved to '{file_name}.json'")

    # Create data structure for saving to Excel
    data1 = {
        "Transport Protocol": [],
        "Protocol": [],
        "Packets": [],
        # "Proprietary Header": [],
        "Undefined Message": [],
        "Invalid Header": [],
        "Undefined Attributes": [],
        "Invalid Attributes": [],
        "Invalid Semantics": [],
        "Non-Compliant Packets": [],
        "Compliant Packets": [],
        # "Non-Compliance Ratio": [],
        "Compliance Ratio": [],
    }

    data1_ext = {
        "Num of Message Types": [],
        "Undefined Message": [],
        "Invalid Header": [],
        "Undefined Attributes": [],
        "Invalid Attributes": [],
        "Invalid Semantics": [],
        "Num of Non-Compliant Types": [],
        "Num of Compliant Types": [],
        # "Non-Compliance Ratio": [],
        "Compliance Ratio": [],
    }

    data2 = {
        "Total Packets": [metrics_dict["Total Packets"]],
        # "Total Percentage": [],
        "Percent of Unknown Packets": [],
        "Percent of Proprietary Header": [],
        "Percent of Undefined Messenge": [],
        "Percent of Invalid Header": [],
        "Percent of Undefined Attributes": [],
        "Percent of Invalid Attributes": [],
        "Percent of Invalid Semantics": [],
        "Percent of Non-Compliant Packets": [],
        "Percent of Compliant Packets": [],
    }

    # log_str = str(log)
    # data3 = {"Log": [log], "Filter": [filter_code]}

    total_unknown_packets = 0
    # total_proprietary_header = set()

    merge_protocols(protocol_dict, protocol_compliance)
    merge_protocols(protocol_msg_dict, protocol_compliance)

    save_json_results(
        log,
        multi_proto_pkts,
        protocol_compliance,
        filter_code,
        p2p,
        file_name,
        volume_list,
        packet_count_list,
        stream_count_list,
        protocol_dict,
        protocol_msg_dict,
        metrics_dict,
        decode_as_dict,
        stream_summary,
        packet_summary,
        raw_filter_code,
    )

    # Iterate through the protocol dictionary to populate the Excel data
    for transport_protocol, protocols in protocol_dict.items():
        for protocol, values in protocols.items():
            packet_count = values

            # Get compliance data from protocol_compliance
            compliance = protocol_compliance.get(transport_protocol, {}).get(protocol, {})
            num_message_types = len(compliance.get("Message Types", dict()))
            num_non_compliant_types = len(compliance.get("Non-Compliant Types", dict()))
            num_compliant_types = num_message_types - num_non_compliant_types
            if num_message_types == 0:
                non_compliance_ratio = -1
                compliance_ratio = -1
            else:
                non_compliance_ratio = num_non_compliant_types / num_message_types
                compliance_ratio = num_compliant_types / num_message_types

            type_with_undefined_msg = 0
            type_with_invalid_header = 0
            type_with_undefined_attr = 0
            type_with_invalid_attr = 0
            type_with_invalid_semantics = 0
            for key, values in compliance.get("Non-Compliant Types", dict()).items():
                value_list = list(values.keys())
                if "Undefined Message" in value_list:
                    type_with_undefined_msg += 1
                if "Invalid Header" in value_list:
                    type_with_invalid_header += 1
                if "Undefined Attributes" in value_list:
                    type_with_undefined_attr += 1
                if "Invalid Attributes" in value_list:
                    type_with_invalid_attr += 1
                if "Invalid Semantics" in value_list:
                    type_with_invalid_semantics += 1

            # undefined_msg = compliance.get("Undefined Message Messages", 0)
            # invalid_header = compliance.get("Invalid Header Messages", 0)
            # undefined_attr = compliance.get("Undefined Attributes Messages", 0)
            # invalid_attr = compliance.get("Invalid Attributes Messages", 0)
            # invalid_semantics = compliance.get("Invalid Semantics Messages", 0)

            undefined_msg = len(compliance.get("Undefined Message Packets", set()))
            invalid_header = len(compliance.get("Invalid Header Packets", set()))
            undefined_attr = len(compliance.get("Undefined Attributes Packets", set()))
            invalid_attr = len(compliance.get("Invalid Attributes Packets", set()))
            invalid_semantics = len(compliance.get("Invalid Semantics Packets", set()))
            proprietary_header_pkts = compliance.get("Proprietary Header Packets", set())
            # proprietary_header = len(proprietary_header_pkts)
            # total_proprietary_header.update(proprietary_header_pkts)

            # Add the extracted data to the Excel data structure
            data1["Transport Protocol"].append(transport_protocol)
            data1["Protocol"].append(protocol)
            data1["Packets"].append(packet_count)
            data1["Undefined Message"].append(undefined_msg)
            data1["Invalid Header"].append(invalid_header)
            data1["Undefined Attributes"].append(undefined_attr)
            data1["Invalid Attributes"].append(invalid_attr)
            data1["Invalid Semantics"].append(invalid_semantics)
            # data1["Proprietary Header"].append(proprietary_header)

            data1_ext["Num of Message Types"].append(num_message_types)
            data1_ext["Undefined Message"].append(type_with_undefined_msg)
            data1_ext["Invalid Header"].append(type_with_invalid_header)
            data1_ext["Undefined Attributes"].append(type_with_undefined_attr)
            data1_ext["Invalid Attributes"].append(type_with_invalid_attr)
            data1_ext["Invalid Semantics"].append(type_with_invalid_semantics)
            data1_ext["Num of Non-Compliant Types"].append(num_non_compliant_types)
            data1_ext["Num of Compliant Types"].append(num_compliant_types)
            # data1_ext["Non-Compliance Ratio"].append(non_compliance_ratio)
            data1_ext["Compliance Ratio"].append(compliance_ratio)

            if protocol == "Unknown":
                total_unknown_packets += packet_count
                data1["Non-Compliant Packets"].append(packet_count)
                data1["Compliant Packets"].append(0)
                # data1["Non-Compliance Ratio"].append(-1)
                data1["Compliance Ratio"].append(-1)
            else:
                data1["Non-Compliant Packets"].append(undefined_msg + invalid_header + undefined_attr + invalid_attr + invalid_semantics)
                data1["Compliant Packets"].append(packet_count - undefined_msg - invalid_header - undefined_attr - invalid_attr - invalid_semantics)
                # data1["Non-Compliance Ratio"].append(data1["Non-Compliant Packets"][-1] / packet_count)
                data1["Compliance Ratio"].append(data1["Compliant Packets"][-1] / packet_count)

    data2["Percent of Unknown Packets"].append(total_unknown_packets / metrics_dict["Total Packets"] * 100)
    data2["Percent of Undefined Messenge"].append(sum(data1["Undefined Message"]) / metrics_dict["Total Packets"] * 100)
    data2["Percent of Invalid Header"].append(sum(data1["Invalid Header"]) / metrics_dict["Total Packets"] * 100)
    data2["Percent of Undefined Attributes"].append(sum(data1["Undefined Attributes"]) / metrics_dict["Total Packets"] * 100)
    data2["Percent of Invalid Attributes"].append(sum(data1["Invalid Attributes"]) / metrics_dict["Total Packets"] * 100)
    data2["Percent of Invalid Semantics"].append(sum(data1["Invalid Semantics"]) / metrics_dict["Total Packets"] * 100)
    data2["Percent of Proprietary Header"].append(metrics_dict["Proprietary Header Packets"] / metrics_dict["Total Packets"] * 100)
    data2["Percent of Non-Compliant Packets"].append(sum(data1["Non-Compliant Packets"]) / metrics_dict["Total Packets"] * 100)
    data2["Percent of Compliant Packets"].append(sum(data1["Compliant Packets"]) / metrics_dict["Total Packets"] * 100)
    # data2["Total Percentage"].append(
    #     data2["Percent of Non-Compliant Packets"][0]
    #     + data2["Percent of Compliant Packets"][0]
    # )

    # Convert to DataFrame
    df1 = pd.DataFrame(data1)
    df1_ext = pd.DataFrame(data1_ext)
    df2 = pd.DataFrame(data2)
    # df3 = pd.DataFrame(data3).T
    # df3.columns = ["" if col == 0 else col for col in df3.columns]

    file_name_xlsx = file_name + ".xlsx"
    with pd.ExcelWriter(file_name_xlsx, engine="openpyxl") as writer:
        df1.to_excel(writer, sheet_name=sheet_name, index=False)
        df1_ext.to_excel(writer, sheet_name=sheet_name, startcol=len(df1.columns) + 1, index=False)
        df2.to_excel(writer, sheet_name=sheet_name, startrow=len(df1) + 2, index=False)
        # df3.to_excel(
        #     writer,
        #     sheet_name=sheet_name,
        #     startrow=len(df1) + len(df2) + 1,
        # )
    # print(f"Results saved to '{file_name}' in sheet '{sheet_name}'")

    df = pd.read_excel(file_name_xlsx, sheet_name=sheet_name, index_col=None)
    df.columns = ["" if col.startswith("Unnamed:") else col for col in df.columns]
    file_name_csv = file_name_xlsx.replace(".xlsx", ".csv")
    df.to_csv(file_name_csv, index=False)
    os.remove(file_name_xlsx)
    print(f"Results saved to '{file_name_csv}'")


def update_stream_details(packet_details, filter_path, streams_path):

    filter_data = read_from_json(filter_path)
    streams_to_label = {"TCP": [], "UDP": []}
    filter_code = filter_data.get("Filter Code", "")
    udp_ids = re.findall(r"udp\.stream\s*==\s*(\d+)", filter_code)
    if udp_ids:
        streams_to_label["UDP"] = udp_ids
    tcp_ids = re.findall(r"tcp\.stream\s*==\s*(\d+)", filter_code)
    if tcp_ids:
        streams_to_label["TCP"] = tcp_ids

    streams_data = read_from_json(streams_path)
    for proto, ids in streams_data.items():
        if proto in streams_to_label:
            for stream_id in ids:
                if stream_id in streams_to_label[proto]:
                    streams_data[proto][stream_id]["label"] = True
                else:
                    streams_data[proto][stream_id]["label"] = False

    for packet_number, packet in packet_details.items():
        stream_type = packet["transport_protocol"]
        stream_id = str(packet["stream_id"])
        streams_data[stream_type][stream_id]["packet_details"][str(packet_number)] = packet

    save_dict_to_json(streams_data, streams_path)


def get_metrics(pcap_stream, stream_dict):
    p2p_ports = {"UDP": set(), "TCP": set()}
    pcap_stream_filtered = {"UDP": {}, "TCP": {}}
    for stream_type in stream_dict:
        for stream_id in stream_dict[stream_type]:
            pcap_stream_filtered[stream_type][stream_id] = pcap_stream[stream_type][stream_id]
            if pcap_stream[stream_type][stream_id]["is_p2p"]:
                p2p_ports[stream_type].add(pcap_stream[stream_type][stream_id]["src_port"])
                p2p_ports[stream_type].add(pcap_stream[stream_type][stream_id]["dst_port"])

    packet_count_udp_raw = sum([len(pcap_stream["UDP"][stream_id]["packet_details"]) for stream_id in pcap_stream["UDP"]])
    packet_count_tcp_raw = sum([len(pcap_stream["TCP"][stream_id]["packet_details"]) for stream_id in pcap_stream["TCP"]])
    packet_count_udp_filtered = sum([len(pcap_stream_filtered["UDP"][stream_id]["packet_details"]) for stream_id in pcap_stream_filtered["UDP"]])
    packet_count_tcp_filtered = sum([len(pcap_stream_filtered["TCP"][stream_id]["packet_details"]) for stream_id in pcap_stream_filtered["TCP"]])
    packet_count_raw = packet_count_udp_raw + packet_count_tcp_raw
    packet_count_filtered = packet_count_udp_filtered + packet_count_tcp_filtered

    volume_raw = sum([sum(pcap_stream["UDP"][stream_id]["packet_sizes"]) for stream_id in pcap_stream["UDP"]]) + sum([sum(pcap_stream["TCP"][stream_id]["packet_sizes"]) for stream_id in pcap_stream["TCP"]])
    volume_filter = sum([sum(pcap_stream_filtered["UDP"][stream_id]["packet_sizes"]) for stream_id in pcap_stream_filtered["UDP"]]) + sum([sum(pcap_stream_filtered["TCP"][stream_id]["packet_sizes"]) for stream_id in pcap_stream_filtered["TCP"]])

    stream_summary = {
        "UDP": {"Raw": len(pcap_stream["UDP"]), "Filtered": len(pcap_stream_filtered["UDP"])},
        "TCP": {"Raw": len(pcap_stream["TCP"]), "Filtered": len(pcap_stream_filtered["TCP"])},
    }
    packet_summary = {
        "UDP": {"Raw": packet_count_udp_raw, "Filtered": packet_count_udp_filtered},
        "TCP": {"Raw": packet_count_tcp_raw, "Filtered": packet_count_tcp_filtered},
    }

    return p2p_ports, packet_count_raw, packet_count_filtered, volume_raw, volume_filter, stream_summary, packet_summary


def main(pcap_file, save_name, app_name, call_num=1, save_protocols=False, suppress_output=False, precall_noise_duration=0, postcall_noise_duration=0):

    if suppress_output:
        sys.stdout = open(os.devnull, "w")

    text_file = pcap_file.split("_calle")[0] + ".txt"

    target_protocols = [
        "RTP",
        "RTCP",
        "STUN",
        "QUIC",
        "CLASSICSTUN",
        "WASP",
        "ZOOM",
        "ZOOM_O",
        "FACETIME",
        "DISCORD",
    ]

    standard_protocols = [
        "RTP",
        "RTCP",
        "STUN",
        "QUIC",
        "CLASSICSTUN",
        "WASP",
    ]

    extractable_protocols = {
        "RTP": "rtp",
        "RTCP": "rtcp",
        "QUIC": "quic",
        "STUN": "stun or classicstun",
        "Unknown": "!(rtp or rtcp or quic or stun or classicstun)",
    }

    no_443_quic = "!(quic and (udp.srcport == 443 or udp.dstport == 443))"  # prove to be RTC-unrelated in FaceTime and Discord
    avoid_protocols = f"(!mdns and !tls and !icmp and !icmpv6 and !dns and {no_443_quic})"

    if app_name == "Zoom":
        p2p_protocol = "zoom"
        target_protocols.remove("QUIC")
        standard_protocols.remove("QUIC")
        extractable_protocols.pop("QUIC")
    elif app_name == "FaceTime":
        p2p_protocol = "facetime"
    elif app_name == "WhatsApp" or app_name == "Messenger":
        p2p_protocol = "wasp"
        target_protocols.remove("QUIC")
        standard_protocols.remove("QUIC")
        extractable_protocols.pop("QUIC")
        extractable_protocols["STUN"] = "stun or classicstun or wasp"
        extractable_protocols["Unknown"] = "!(rtp or rtcp or quic or stun or wasp or classicstun)"
    elif app_name == "Discord":
        p2p_protocol = "discord"
        target_protocols.remove("QUIC")
        standard_protocols.remove("QUIC")
        extractable_protocols.pop("QUIC")
        target_protocols.remove("STUN")
        standard_protocols.remove("STUN")
        extractable_protocols.pop("STUN")
    else:
        raise Exception("Invalid app name.")

    print(f"\nPcap file: {pcap_file}")

    base_gap = 3
    for i in range(0, call_num):
        print(f"\nProcessing part {i+1} ...")
        part_save_name = f"{save_name}_part{i+1}"
        pcap_info_file = part_save_name + ".json"
        pcap_stream_file = part_save_name + "_streams.json"

        pcap_info = read_from_json(pcap_info_file)
        pcap_stream = read_from_json(pcap_stream_file)

        gap = base_gap
        if app_name == "Discord":
            gap = base_gap + 1
        start = i * gap
        end = (i + 1) * gap

        timestamp_dict, zone_offset = find_timestamps(text_file)
        time_filter, call_duration = get_time_filter(timestamp_dict, start=start, end=end, pre_offset=precall_noise_duration, post_offset=postcall_noise_duration)
        call_duration = call_duration - (precall_noise_duration + postcall_noise_duration)

        raw_traffic_filter = pcap_info["Filter Code"]
        traffic_filter = raw_traffic_filter + " and " + avoid_protocols + "and" + time_filter
        stream_dict = parse_stream_filter(traffic_filter)

        p2p_ports, packet_count_raw, packet_count_filter, volume_raw, volume_filter, stream_summary, packet_summary = get_metrics(pcap_stream, stream_dict)

        stream_count_raw = stream_summary["UDP"]["Raw"] + stream_summary["TCP"]["Raw"]
        stream_count_filter = stream_summary["UDP"]["Filtered"] + stream_summary["TCP"]["Filtered"]
        udp_stream_count = len(stream_dict["UDP"])
        tcp_stream_count = len(stream_dict["TCP"])
        print(f"Raw packets: {packet_count_raw}, Filtered packets: {packet_count_filter}")
        decode_as = get_decode_as(p2p_ports, p2p_protocol)

        if p2p_ports["UDP"] or p2p_ports["TCP"]:
            print("P2P streams found.")
            print(f"Decode as: {decode_as}")
        else:
            print("No P2P streams found.")

        print("\nFilter Code:")
        print(traffic_filter)

        print("\nMeasuring traffic ...")
        (
            protocol_dict,
            protocol_msg_dict,
            protocol_compliance,
            metrics_dict,
            log,
            multi_proto_pkts,
            packet_details,
        ) = count_packets(
            pcap_file,
            standard_protocols,
            filter_code=traffic_filter,
            decode_as=decode_as,
        )

        metrics_dict["UDP Streams"] = udp_stream_count
        metrics_dict["TCP Streams"] = tcp_stream_count
        metrics_dict["Total Streams"] = udp_stream_count + tcp_stream_count
        metrics_dict["Call Duration"] = call_duration

        packet_summary["UDP"]["Total"] = metrics_dict["UDP Packets"]
        packet_summary["TCP"]["Total"] = metrics_dict["TCP Packets"]
        stream_summary["UDP"]["Total"] = udp_stream_count
        stream_summary["TCP"]["Total"] = tcp_stream_count

        print("\nSaving results and pcaps ...")
        save_results(
            protocol_dict,
            protocol_msg_dict,
            protocol_compliance,
            metrics_dict,
            [volume_raw, volume_filter],
            [packet_count_raw, packet_count_filter],
            [stream_count_raw, stream_count_filter],
            decode_as,
            stream_summary,
            packet_summary,
            file_name=part_save_name,
            sheet_name=f"Part {i+1}",
            filter_code=traffic_filter,
            log=log,
            multi_proto_pkts=multi_proto_pkts,
            p2p=bool(p2p_ports["TCP"] or p2p_ports["UDP"]),
            raw_filter_code=raw_traffic_filter,
        )

        update_stream_details(packet_details, pcap_info_file, pcap_stream_file)

        if save_protocols:
            total = 0
            for name, code in extractable_protocols.items():
                total += extract_protocol(
                    pcap_file,
                    f"{part_save_name}_{name}.pcap",
                    code,
                    filter_code=traffic_filter,
                    decode_as=decode_as,
                )
            print(f"Total packets extracted: {total}")

    if suppress_output:
        sys.stdout.close()
        sys.stdout = sys.__stdout__


def check_task_success(save_name, call_num):
    success = True
    for i in range(1, call_num + 1):
        json_file = f"{save_name}_part{i}.json"
        csv_file = f"{save_name}_part{i}.csv"
        if not os.path.exists(json_file) or not os.path.exists(csv_file):
            # print(f"Missing file: {json_file if not os.path.exists(json_file) else csv_file}")
            success = False
    return success


if __name__ == "__main__":
    # python step3-4_heuristic_baseline.py --config config.json --multiprocess

    parser = argparse.ArgumentParser(description="Determine RTC protocol compliance.")
    parser.add_argument("--multiprocess", action="store_true", help="Use multiprocessing for extraction.")
    parser.add_argument("--config", type=str, default="config.json", help="Path to the configuration file.")
    args = parser.parse_args()
    config_path = args.config
    multiprocess = args.multiprocess
    pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, precall_noise_duration, postcall_noise_duration, plugin_target_folder, plugin_source_folder = load_config(config_path)

    all_tests = []

    for app_name in apps:

        pcap_files = []
        save_names = []
        call_nums = []

        if app_name == "Zoom":
            lua_file = "zoom.lua"
        elif app_name == "FaceTime":
            lua_file = "facetime.lua"
        elif app_name == "WhatsApp" or app_name == "Messenger":
            lua_file = "wasp.lua"
        elif app_name == "Discord":
            lua_file = "discord.lua"
        else:
            raise Exception("Invalid app name.")

        # move_file_to_target(plugin_enable_folder, lua_file, plugin_disable_folder)
        lua_file_names = os.listdir(plugin_source_folder)
        clean_up_folder(plugin_target_folder, files=lua_file_names)
        copy_file_to_target(plugin_target_folder, lua_file, plugin_source_folder, overwrite=True)

        for test_name in tests:
            if "noise" in test_name:
                continue
            for test_round in rounds:
                for client_type in client_types:
                    pcap_subfolder = f"{pcap_main_folder}/{app_name}"
                    save_subfolder = f"{save_main_folder}/{app_name}/{test_name}"
                    if not os.path.exists(save_subfolder):
                        os.makedirs(save_subfolder)

                    pcap_file_name = f"{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
                    text_file_name = f"{app_name}_{test_name}_{test_round}.txt"

                    pcap_file = f"{save_subfolder}/{pcap_file_name}"
                    save_name = f"{save_subfolder}/{app_name}_{test_name}_{test_round}_{client_type}"

                    pcap_files.append(pcap_file)
                    save_names.append(save_name)
                    call_nums.append(tests[test_name])

                    all_tests.append([save_name, tests[test_name]])

        processes = []
        process_start_times = []
        for pcap_file, save_name, call_num in zip(pcap_files, save_names, call_nums):
            if multiprocess:
                p = multiprocessing.Process(
                    target=main,
                    args=(pcap_file, save_name, app_name, call_num, False, True, precall_noise_duration, postcall_noise_duration),
                )
                process_start_times.append(time.time())
                processes.append(p)
                p.start()
            else:
                main(pcap_file, save_name, app_name, call_num=call_num, precall_noise_duration=precall_noise_duration, postcall_noise_duration=postcall_noise_duration)

        if multiprocess:
            if len(processes) == 0:
                print(f"Skip {app_name} tasks.")
                continue
            
            print(f"\n{app_name} tasks started.\n")

            lines = len(processes)
            elapsed_times = [0] * len(processes)
            print("\n" * lines, end="")
            while True:
                all_finished = True
                status = ""
                for i, p in enumerate(processes):
                    if p.is_alive():
                        elapsed_time = int(time.time() - process_start_times[i])
                        elapsed_times[i] = elapsed_time
                        all_finished = False
                        status += f"Running\t|{elapsed_time}s\t|{save_names[i]}\n"
                    else:
                        elapsed_time = elapsed_times[i]
                        if p.exitcode is None:
                            status += f"Unknown\t|{elapsed_time}s\t|{save_names[i]}\n"
                        elif p.exitcode == 0:
                            status += f"Done\t|{elapsed_time}s\t|{save_names[i]}\n"
                        else:
                            status += f"Code {p.exitcode}\t|{elapsed_time}s\t|{save_names[i]}\n"

                if status[-1] == "\n":
                    status = status[:-1]
                print("\033[F" * lines, end="")  # Move cursor up
                for _ in range(lines):
                    print("\033[K\n", end="")  # Clear the line
                print("\033[F" * lines, end="")  # Move cursor up
                print(status)

                if all_finished:
                    print(f"\nAll {app_name} tasks are finished. (Average Runtime: {sum(elapsed_times) / len(elapsed_times):.2f}s)")
                    break
                time.sleep(1)

            for p in processes:
                p.join()

    print("\nSummary:")
    no_success = 0
    for save_name, call_num in all_tests:
        if not check_task_success(save_name, call_num):
            no_success += 1
            print(f"Task failed: {save_name}")
    if no_success == 0:
        print("All tasks completed successfully.")
    else:
        print(f"{no_success}/{len(all_tests)} tasks failed.")
