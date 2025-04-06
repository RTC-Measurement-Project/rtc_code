import pyshark
from IPy import IP
import pandas as pd
import multiprocessing
import time
import sys

from utils import *
from compliance import process_packet
from protocol_extractor import extract_protocol
from noise_cancellation import extract_filter_para
from extract_streams import extract_streams_from_pcap

this_file_location = os.path.dirname(os.path.realpath(__file__))

asn_file = this_file_location + "/asn_description.json"
if not os.path.exists(asn_file):
    ip_asn = {}
else:
    ip_asn = read_from_json(asn_file)


def get_streams(
    pcap_file,
    target_protocols,
    zone_offset,
    noise_stream_dict,
    filter_code="",
    decode_as={},
):
    cap = pyshark.FileCapture(pcap_file, display_filter=filter_code, decode_as=decode_as)
    cap.set_debug()

    stream_dict = {"UDP": {}, "TCP": {}, "P2P_UDP": {}, "P2P_TCP": {}}
    p2p_ports = {"UDP": set(), "TCP": set()}

    packet_count_raw = 0
    packet_count_filter = 0
    volume_raw = 0
    volume_filter = 0

    packet_count_udp_raw = 0
    packet_count_udp_filter = 0
    packet_count_tcp_raw = 0
    packet_count_tcp_filter = 0

    stream_udp_raw = set()
    stream_tcp_raw = set()
    stream_udp_filter = set()
    stream_tcp_filter = set()

    counter = 0
    for packet in cap:
        counter += 1
        # if packet.number == "3139": # for debugging
        #     print(packet)

        if counter % 1000 == 0:
            print(f"Packet: {packet.number}", end="\r")

        packet_count_raw += 1
        volume_raw += int(packet.length)

        if "TCP" in packet:
            stream_id = packet.tcp.stream
            stream_tcp_raw.add(stream_id)
            packet_count_tcp_raw += 1
            if stream_id in noise_stream_dict["TCP"]:
                continue
            stream_tcp_filter.add(stream_id)
            packet_count_tcp_filter += 1
        elif "UDP" in packet:
            stream_id = packet.udp.stream
            stream_udp_raw.add(stream_id)
            packet_count_udp_raw += 1
            if stream_id in noise_stream_dict["UDP"]:
                continue
            stream_udp_filter.add(stream_id)
            packet_count_udp_filter += 1
        else:
            print(f"Invalid packet {packet.number} (No TCP or UDP layer)")
            continue

        packet_count_filter += 1
        volume_filter += int(packet.length)

        # check p2p, if yes, save them to a separate file
        if "IP" in packet:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
        elif "IPv6" in packet:
            ip_src = packet.ipv6.src
            ip_dst = packet.ipv6.dst
        else:
            print(f"Invalid packet {packet.number} (No IP or IPv6 layer)")
            continue
        # if both ip src and dst are private, save them to a separate file
        src_dot_count = max(ip_src.count("."), ip_src.count(":"))
        dst_dot_count = max(ip_dst.count("."), ip_dst.count(":"))
        for ip in [ip_src, ip_dst]:
            if ip not in ip_asn:
                ip_asn[ip] = get_asn_description(ip)
                if type(ip_asn[ip]) != str:
                    raise Exception(f"Error when getting ASN description for {ip}")
                save_dict_to_json(ip_asn, asn_file)
        ip_src_IP = IP(ip_src)
        ip_dst_IP = IP(ip_dst)
        # p2p_types = [
        #     "PRIVATE",
        #     "CARRIER_GRADE_NAT",
        #     # "ALLOCATED ARIN",
        #     # "ALLOCATED RIPE NCC",
        # ]

        p2p = False
        isp_types = ["T-MOBILE", "ATT", "UUNET", "CHINAMOBILE", "COMCAST"]  # for T-Mobile, AT&T, Verizon, China Mobile
        p2p_option1 = ip_src_IP.iptype() == ip_dst_IP.iptype() == "PRIVATE"
        p2p_option2 = ip_asn[ip_dst] == ip_asn[ip_src] and any(isp_type in ip_asn[ip_dst] for isp_type in isp_types)
        p2p_option3 = ip_dst_IP.iptype() == "PRIVATE" and any(isp_type in ip_asn[ip_src] for isp_type in isp_types)
        p2p_option4 = any(isp_type in ip_asn[ip_dst] for isp_type in isp_types) and ip_src_IP.iptype() == "PRIVATE"
        p2p_option5 = ip_asn[ip_dst] in ["Unknown", "NA"] and any(isp_type in ip_asn[ip_src] for isp_type in isp_types)
        p2p_option6 = any(isp_type in ip_asn[ip_dst] for isp_type in isp_types) and ip_asn[ip_src] in ["Unknown", "NA"]
        # assume p2p is only over UDP
        if (p2p_option1 or p2p_option2 or p2p_option3 or p2p_option4 or p2p_option5 or p2p_option6) and ("UDP" in packet and src_dot_count == dst_dot_count):
            p2p = True

        if not any(proto in packet for proto in target_protocols) and not p2p:
            continue

        if "TCP" in packet:
            stream_id = packet.tcp.stream
            if stream_dict["TCP"].get(stream_id) is None:
                packet_time = datetime.fromtimestamp(float(packet.sniff_timestamp))
                packet_time = packet_time.replace(tzinfo=zone_offset)
                if p2p:
                    p2p_ports["TCP"].add(packet.tcp.srcport)
                    p2p_ports["TCP"].add(packet.tcp.dstport)
                    stream_dict["P2P_TCP"][stream_id] = packet_time
                else:
                    stream_dict["TCP"][stream_id] = packet_time
        elif "UDP" in packet:
            stream_id = packet.udp.stream
            if stream_dict["UDP"].get(stream_id) is None:
                packet_time = datetime.fromtimestamp(float(packet.sniff_timestamp))
                packet_time = packet_time.replace(tzinfo=zone_offset)
                if p2p:
                    p2p_ports["UDP"].add(packet.udp.srcport)
                    p2p_ports["UDP"].add(packet.udp.dstport)
                    stream_dict["P2P_UDP"][stream_id] = packet_time
                else:
                    stream_dict["UDP"][stream_id] = packet_time

    cap.close()
    stream_summary = {
        "UDP": {"Raw": len(stream_udp_raw), "Filtered": len(stream_udp_filter)},
        "TCP": {"Raw": len(stream_tcp_raw), "Filtered": len(stream_tcp_filter)},
    }
    packet_summary = {
        "UDP": {"Raw": packet_count_udp_raw, "Filtered": packet_count_udp_filter},
        "TCP": {"Raw": packet_count_tcp_raw, "Filtered": packet_count_tcp_filter},
    }
    return stream_dict, p2p_ports, packet_count_raw, packet_count_filter, volume_raw, volume_filter, stream_summary, packet_summary


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
    # cap.set_debug()

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


def add_delta_time(timestamp_dict, stream_dict):
    # find the delta time between the each stream start time and its nearest timestamp
    for stream_type in stream_dict:
        for stream_id in stream_dict[stream_type]:
            new_dict = {
                "start_time": stream_dict[stream_type][stream_id],
                "timestamp": None,
                "delta_time": None,
            }
            stream_start_time = stream_dict[stream_type][stream_id]
            nearest_timestamp = min(timestamp_dict, key=lambda x: abs(x - stream_start_time))
            delta_time = stream_start_time - nearest_timestamp
            new_dict["timestamp"] = nearest_timestamp
            new_dict["delta_time"] = delta_time.total_seconds()
            stream_dict[stream_type][stream_id] = new_dict

    # pop stream that has delta time > 3s
    # for stream_type in stream_dict:
    #     for stream_id in list(stream_dict[stream_type].keys()):
    #         if stream_dict[stream_type][stream_id]["delta_time"] > 3:
    #             stream_dict[stream_type].pop(stream_id)

    return stream_dict


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
    filter_1_code="",
    filter_2_code="",
    log=[],
    multi_proto_pkts=[],
    p2p=False,
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
        filter_1_code,
        filter_2_code,
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
            "Filter 1 Code": filter_1_code,
            "Filter 2 Code": filter_2_code,
            "Filter Code": filter_code,
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
        filter_1_code,
        filter_2_code,
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


def main(pcap_file, save_name, app_name, call_num=1, noise_duration=0, save_protocols=False, suppress_output=False):

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

    noise_stream_dict = {
        "UDP": set(),
        "TCP": set(),
    }
    if noise_duration > 0:
        print("\nExtracting noise streams ...")
        discard_ips, tcp_stream_ids, udp_stream_ids = extract_filter_para(pcap_file, noise_duration)
        noise_stream_dict["UDP"] = udp_stream_ids
        noise_stream_dict["TCP"] = tcp_stream_ids
        print(f"Noise streams extracted: UDP: {len(noise_stream_dict['UDP'])}, TCP: {len(noise_stream_dict['TCP'])}")
        filter_1_code = get_stream_filter(list(noise_stream_dict["TCP"]), list(noise_stream_dict["UDP"]))
    else:
        filter_1_code = ""

    base_gap = 3
    for i in range(0, call_num):
        part_save_name = f"{save_name}_part{i+1}"
        gap = base_gap
        if app_name == "Discord":
            gap = base_gap + 1
        start = i * gap
        end = (i + 1) * gap

        timestamp_dict, zone_offset = find_timestamps(text_file)
        time_filter, call_duration = get_time_filter(timestamp_dict, start=start, end=end)
        base_filter = time_filter + " and " + avoid_protocols

        print(f"\nProcessing part {i+1} ...")

        filter_2_code = ""

        stream_dict, p2p_ports, packet_count_raw, packet_count_filter, volume_raw, volume_filter, stream_summary, packet_summary = get_streams(
            pcap_file,
            target_protocols,
            zone_offset,
            noise_stream_dict,
            filter_code=base_filter,
        )
        stream_count_raw = stream_summary["UDP"]["Raw"] + stream_summary["TCP"]["Raw"]
        stream_count_filter = stream_summary["UDP"]["Filtered"] + stream_summary["TCP"]["Filtered"]
        udp_stream_count = len(stream_dict["UDP"]) + len(stream_dict["P2P_UDP"])
        tcp_stream_count = len(stream_dict["TCP"]) + len(stream_dict["P2P_TCP"])
        print(f"Raw packets: {packet_count_raw}, Filtered packets: {packet_count_filter}")
        # stream_dict = add_delta_time(timestamp_dict, stream_dict)
        stream_filter = get_stream_filter(list(stream_dict["TCP"].keys()), list(stream_dict["UDP"].keys()))
        p2p_filter = get_stream_filter(list(stream_dict["P2P_TCP"].keys()), list(stream_dict["P2P_UDP"].keys()))
        decode_as = get_decode_as(p2p_ports, p2p_protocol)

        if p2p_filter != "()":
            print("P2P streams found.")
            print(f"P2P filer: {p2p_filter}")
            print(f"Decode as: {decode_as}")
            p2p_traffic_filter = p2p_filter + " and " + base_filter
        else:
            print("No P2P streams found.")

        # if not os.path.exists(f"{part_save_name}_streams.json"):
        # extended_time_filter, _ = get_time_filter(timestamp_dict, start=start, end=end, offset=noise_duration + 10)
        # streams = extract_streams_from_pcap(pcap_file, filter_code=extended_time_filter, decode_as=decode_as)
        # save_dict_to_json(streams, f"{part_save_name}_streams.json")

        traffic_filter = ""

        if stream_filter != "()" and p2p_filter != "()":
            traffic_filter = "(" + stream_filter + " or " + p2p_filter + ")" + " and " + base_filter
        elif stream_filter != "()" and p2p_filter == "()":
            traffic_filter = stream_filter + " and " + base_filter
        elif stream_filter == "()" and p2p_filter != "()":
            traffic_filter = p2p_filter + " and " + base_filter
        else:
            traffic_filter = base_filter

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
            # filter_code=traffic_filter_no_p2p,
            filter_code=traffic_filter,
            decode_as=decode_as,
        )

        # if p2p_filter != "()":
        #     print("\nMeasuring P2P traffic ...")
        #     prev_results = {
        #         "protocol_dict": protocol_dict,
        #         "protocol_msg_dict": protocol_msg_dict,
        #         "protocol_compliance": protocol_compliance,
        #         "metrics_dict": metrics_dict,
        #         "log": log,
        #         "multi_proto_pkts": multi_proto_pkts,
        #         "packet_details": packet_details,
        #     }
        #     protocol_dict, protocol_msg_dict, protocol_compliance, metrics_dict, log, multi_proto_pkts, packet_details = count_packets(
        #         pcap_file,
        #         standard_protocols,
        #         filter_code=p2p_traffic_filter,
        #         decode_as=decode_as,
        #         prev_results=prev_results,
        #     )

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
            filter_1_code=filter_1_code,
            filter_2_code=filter_2_code,
            log=log,
            multi_proto_pkts=multi_proto_pkts,
            p2p=len(stream_dict["P2P_TCP"]) != 0 or len(stream_dict["P2P_UDP"]) != 0,
        )

        update_stream_details(packet_details, f"{part_save_name}.json", f"{part_save_name}_streams.json")

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
    # app_name = "Zoom"
    # # pcap_file = f"/Users/sam/Desktop/rtc_code/tests/test_noise/raw/Zoom/Zoom_nc_2ip_av_wifi_ww_t1_caller.pcapng"
    # # pcap_file = f"/Users/sam/Desktop/rtc_code/tests/test_noise/raw/Messenger/Messenger_nc_2ip_av_wifi_ww_t1_caller.pcapng"
    # # pcap_file = f"/Users/sam/Desktop/rtc_code/tests/test_noise/raw/WhatsApp/WhatsApp_nc_2ip_av_wifi_ww_t1_caller.pcapng"
    # # pcap_file = f"/Users/sam/Desktop/rtc_code/tests/test_noise/raw/FaceTime/FaceTime_nc_2ip_av_wifi_ww_t1_caller.pcapng"
    # pcap_file = f"/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_5minNoise_2ip_av_wifi_ww_t1_caller.pcapng"
    # # save_name = f"/Users/sam/Desktop/rtc_code/Apps/tests/Messenger_oh_600s_av_t1_caller"
    # save_name = pcap_file.split(".pcapng")[0]
    # main(pcap_file, save_name, app_name, call_num=1, noise_duration=300)
    # exit()

    multiprocess = True
    # multiprocess = False
    apps = [
        "Zoom",
        # "FaceTime",
        # "WhatsApp",
        # "Messenger",
        # "Discord",
    ]
    tests = {  # test_name: call_num
        # "600s_2ip_av_wifi_w": 1,
        # "multicall_2ip_av_p2pcellular_c": 3,
        # "multicall_2ip_av_p2pwifi_w": 3,
        # "multicall_2ip_av_p2pwifi_wc": 3,
        # "multicall_2ip_av_wifi_w": 3,
        # "multicall_2ip_av_wifi_wc": 3,
        # "multicall_2mac_av_p2pwifi_w": 3,
        # "multicall_2mac_av_wifi_w": 3,
        # "oh_600s_av": 1,
        # "oh_600s_a": 1,
        # "oh_600s_nm": 1,
        # "nc_2ip_av_wifi_ww": 1,
        # "151call_2ip_av_wifi_ww": 1,
        # "2ip_av_cellular_cc": 1,
        # "2ip_av_p2pwifi_ww": 1,
        "2ip_av_wifi_ww": 1,
    }
    rounds = [
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
    ]
    client_types = [
        "caller",
        "callee",
    ]

    # pcap_main_folder = "./Apps"
    # save_main_folder = "./test_metrics"
    # pcap_main_folder = "/Users/sam/Downloads/noise_collection"
    # save_main_folder = "/Users/sam/Downloads/noise_metrics"
    # pcap_main_folder = "/Users/sam/Desktop/rtc_code/tests/test_noise/raw"
    # save_main_folder = "/Users/sam/Downloads/noise_metrics2"
    # pcap_main_folder = "./testbench/data"
    # save_main_folder = "/Users/sam/Downloads/noise_metrics3"
    pcap_main_folder = "/Users/sam/Downloads/data"
    save_main_folder = "/Users/sam/Downloads/metrics"

    noise_duration = 0
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

        target_folder_path = "/Users/sam/.local/lib/wireshark/plugins"
        storage_folder_path = "/Users/sam/.local/lib/wireshark/disabled"
        move_file_to_target(target_folder_path, lua_file, storage_folder_path)

        for test_name in tests:
            for test_round in rounds:
                for client_type in client_types:
                    pcap_subfolder = f"{pcap_main_folder}/{app_name}"
                    save_subfolder = f"{save_main_folder}/{app_name}/{test_name}"
                    if not os.path.exists(save_subfolder):
                        os.makedirs(save_subfolder)

                    pcap_file_name = f"{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
                    text_file_name = f"{app_name}_{test_name}_{test_round}.txt"
                    copy_file_to_target(save_subfolder, pcap_file_name, pcap_subfolder, suppress_output=True)
                    copy_file_to_target(save_subfolder, text_file_name, pcap_subfolder, suppress_output=True)

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
                    args=(pcap_file, save_name, app_name, call_num, noise_duration, False, True),
                )
                process_start_times.append(time.time())
                processes.append(p)
                p.start()
            else:
                main(pcap_file, save_name, app_name, call_num=call_num, noise_duration=noise_duration)

        if multiprocess:
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
