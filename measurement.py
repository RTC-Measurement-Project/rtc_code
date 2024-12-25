import pyshark
from IPy import IP
import pandas as pd

from compliance import check_compliance
from utils import *
from protocol_extractor import extract_protocol
from noise_cancellation import extract_filter_para

# check file exist
asn_file = "asn_description.json"
if not os.path.exists(asn_file):
    ip_asn = {}
else:
    ip_asn = read_from_json(asn_file)


def get_streams(pcap_file, target_protocols, zone_offset, noise_stream_dict, filter_code="", decode_as={}):
    cap = pyshark.FileCapture(
        pcap_file, display_filter=filter_code, decode_as=decode_as
    )
    stream_dict = {"UDP": {}, "TCP": {}, "P2P_UDP": {}, "P2P_TCP": {}}
    p2p_ports = {"UDP": set(), "TCP": set()}
    packet_count_raw = 0
    packet_count_filter = 0

    for packet in cap:
        # if packet.number == "1269": # for debugging
        #     print(packet)

        packet_count_raw += 1
        
        if "TCP" in packet:
            stream_id = packet.tcp.stream
            if stream_id in noise_stream_dict["TCP"]:
                continue
        elif "UDP" in packet:
            stream_id = packet.udp.stream
            if stream_id in noise_stream_dict["UDP"]:
                continue
            
        packet_count_filter += 1
        
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
        isp_types = ["T-MOBILE", "ATT", "UUNET"]  # for T-Mobile, AT&T, and Verizon
        p2p_option1 = ip_src_IP.iptype() == ip_dst_IP.iptype() == "PRIVATE"
        p2p_option2 = ip_asn[ip_dst] == ip_asn[ip_src] and any(
            isp_type in ip_asn[ip_dst] for isp_type in isp_types
        )
        p2p_option3 = ip_dst_IP.iptype() == "PRIVATE" and any(
            isp_type in ip_asn[ip_src] for isp_type in isp_types
        )
        p2p_option4 = (
            any(isp_type in ip_asn[ip_dst] for isp_type in isp_types)
            and ip_src_IP.iptype() == "PRIVATE"
        )
        # assume p2p is only over UDP
        if (p2p_option1 or p2p_option2 or p2p_option3 or p2p_option4) and (
            "UDP" in packet and src_dot_count == dst_dot_count
        ):
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
    return stream_dict, p2p_ports, packet_count_raw, packet_count_filter


def count_packets(
    pcap_file,
    target_protocols,
    filter_code="",
    decode_as={},
    prev_results={},
):
    cap = pyshark.FileCapture(
        pcap_file, display_filter=filter_code, decode_as=decode_as
    )

    # Create a dictionary for both transport and application protocols
    protocol_dict = {"TCP": {"Unknown": 0}, "UDP": {"Unknown": 0}}
    protocol_compliance = {"TCP": {}, "UDP": {}}

    count = 0
    udp_count = 0
    tcp_count = 0
    log = []
    multi_proto_pkts = []

    for key in prev_results:
        if key == "log":
            log += prev_results[key]
        elif key == "multi_proto_pkts":
            multi_proto_pkts += prev_results[key]
        elif key == "protocol_dict":
            protocol_dict = prev_results[key]
        elif key == "protocol_compliance":
            protocol_compliance = prev_results[key]
        elif key == "metrics_dict":
            count = prev_results[key]["Total Packets"]
            udp_count = prev_results[key]["UDP Packets"]
            tcp_count = prev_results[key]["TCP Packets"]

    # Helper function to process packet compliance and counting
    def process_packet(
        packet, transport_protocol, protocol_dict, protocol_compliance, log
    ):
        protocols = []
        for protocol in target_protocols:
            if protocol in packet:
                if protocol in ["WASP", "CLASSICSTUN"]:
                    actual_protocol = "STUN"
                else:
                    actual_protocol = protocol
                if protocol_dict[transport_protocol].get(actual_protocol) is None:
                    protocol_dict[transport_protocol][actual_protocol] = 0
                validity_checks = check_compliance(
                    protocol_compliance[transport_protocol],
                    packet,
                    protocol,
                    actual_protocol,
                    log,
                )
                if any(validity_checks):
                    if "ZOOM" in packet or "ZOOM_O" in packet or "FACETIME" in packet:
                        protocol_compliance[transport_protocol][actual_protocol]["Proprietary Header Packets"].add(packet.number)
                    protocol_dict[transport_protocol][actual_protocol] += 1
                    protocols.append(actual_protocol)
        return protocols

    for packet in cap:
        # if packet.number == '3111': # for debugging
        #     print(packet)

        count += 1

        print(
            f"Error Counts: {len(log)} \tMulti-Protocol Packets: {len(multi_proto_pkts)}",
            end="\r",
        )

        if "TCP" in packet:
            tcp_count += 1
            protocols = process_packet(
                packet, "TCP", protocol_dict, protocol_compliance, log
            )
            if len(protocols) == 0:
                protocol_dict["TCP"]["Unknown"] += 1
            elif len(protocols) > 1:
                # print(
                #     "Multiple protocols detected in a single TCP packet: ",
                #     packet.number,
                #     protocols,
                # )
                multi_proto_pkts.append(["TCP", protocols, packet.number])

        elif "UDP" in packet:
            udp_count += 1
            protocols = process_packet(
                packet, "UDP", protocol_dict, protocol_compliance, log
            )
            if len(protocols) == 0:
                protocol_dict["UDP"]["Unknown"] += 1
            elif len(protocols) > 1:
                # print(
                #     "Multiple protocols detected in a single UDP packet: ",
                #     packet.number,
                #     protocols,
                # )
                multi_proto_pkts.append(["UDP", protocols, packet.number])

    print(f"Results: {protocol_dict}")
    print(f"Total Packets: {count}")
    print(f"UDP Packets: {udp_count}")
    print(f"TCP Packets: {tcp_count}")
    print(f"Multi-Protocol Packets: {len(multi_proto_pkts)}")
    print(f"Error Counts: {len(log)}")

    metrics_dict = {
        "Total Packets": count,
        "UDP Packets": udp_count,
        "TCP Packets": tcp_count,
    }

    cap.close()
    return protocol_dict, protocol_compliance, metrics_dict, log, multi_proto_pkts


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
            nearest_timestamp = min(
                timestamp_dict, key=lambda x: abs(x - stream_start_time)
            )
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
    protocol_compliance,
    metrics_dict,
    packet_count_list,
    file_name="protocol_analysis.xlsx",
    sheet_name="sheet1",
    filter_code="",
    log=[],
    multi_proto_pkts=[],
    p2p=False,
):
    def merge_protocols(protocol_dict, protocol_compliance):
        marked_protocols = set()
        for protocol in protocol_dict["TCP"]:
            if protocol != "Unknown" and protocol in protocol_dict["UDP"]:
                marked_protocols.add(protocol)
                if "UDP/TCP" not in protocol_dict.keys():
                    protocol_dict["UDP/TCP"] = {}
                tcp_count = protocol_dict["TCP"][protocol]
                udp_count = protocol_dict["UDP"][protocol]
                protocol_dict["UDP/TCP"][protocol] = tcp_count + udp_count

        for protocol in marked_protocols:
            if "UDP/TCP" not in protocol_compliance.keys():
                protocol_compliance["UDP/TCP"] = {}
            tcp_compliance = protocol_compliance["TCP"].get(protocol, {})
            udp_compliance = protocol_compliance["UDP"].get(protocol, {})
            merged_compliance = deep_dict_merge(tcp_compliance, udp_compliance)
            protocol_compliance["UDP/TCP"][protocol] = merged_compliance

            protocol_dict["TCP"].pop(protocol)
            protocol_dict["UDP"].pop(protocol)
            protocol_compliance["TCP"].pop(protocol)
            protocol_compliance["UDP"].pop(protocol)

    def save_json_results(
        log,
        multi_proto_pkts,
        protocol_compliance,
        filter_code,
        p2p,
        file_name,
        packet_count_list,
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

        message_types = {}
        for transport_protocol, protocols in protocol_compliance.items():
            for protocol, values in protocols.items():
                message_types[protocol] = list(values.get("Message Types", set()))

        non_compliant_pkts = {}
        for transport_protocol, protocols in protocol_compliance.items():
            for protocol, values in protocols.items():
                if non_compliant_pkts.get(protocol) is None:
                    non_compliant_pkts[protocol] = {}
                non_compliant_pkts[protocol]["Undefined Message"] = list(values.get("Undefined Message Packets", set()))
                non_compliant_pkts[protocol]["Invalid Header"] = list(values.get("Invalid Header Packets", set()))
                non_compliant_pkts[protocol]["Undefined Attributes"] = list(values.get("Undefined Attributes Packets", set()))
                non_compliant_pkts[protocol]["Invalid Attributes"] = list(values.get("Invalid Attributes Packets", set()))
                non_compliant_pkts[protocol]["Invalid Semantics"] = list(values.get("Invalid Semantics Packets", set()))

        data = {
            "P2P Found?": p2p,
            "Filter Code": filter_code,
            "Packet Count (Raw)": packet_count_list[0],
            "Packet Count (Filtered)": packet_count_list[1],
            "Packet Count (Final)": packet_count_list[2],
            "Error Log": log_dict,
            "Multi-Protocol Packets": multi_proto_dict,
            "Message Types": message_types,
            "Non-Compliant Packets": non_compliant_pkts,
        }
        save_dict_to_json(data, file_name + ".json")
        print(f"Results saved to '{file_name}.json'")

    # Create data structure for saving to Excel
    data1 = {
        "Transport Protocol": [],
        "Protocol": [],
        "Packets": [],
        "Proprietary Header": [],
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
        # "Proprietary Header": [],
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
        "Total Percentage": [],
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

    merge_protocols(protocol_dict, protocol_compliance)

    save_json_results(
        log,
        multi_proto_pkts,
        protocol_compliance,
        filter_code,
        p2p,
        file_name,
        packet_count_list,
    )

    # Iterate through the protocol dictionary to populate the Excel data
    for transport_protocol, protocols in protocol_dict.items():
        for protocol, values in protocols.items():
            # Check if the protocol value is an integer or a dictionary

            packet_count = values

            # Get compliance data from protocol_compliance
            compliance = protocol_compliance.get(transport_protocol, {}).get(
                protocol, {}
            )
            num_message_types = len(compliance.get("Message Types", set()))
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
                if "Undefined Message" in values:
                    type_with_undefined_msg += 1
                if "Invalid Header" in values:
                    type_with_invalid_header += 1
                if "Undefined Attributes" in values:
                    type_with_undefined_attr += 1
                if "Invalid Attributes" in values:
                    type_with_invalid_attr += 1
                if "Invalid Semantics" in values:
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
            proprietary_header = len(compliance.get("Proprietary Header Packets", set()))

            # Add the extracted data to the Excel data structure
            data1["Transport Protocol"].append(transport_protocol)
            data1["Protocol"].append(protocol)
            data1["Packets"].append(packet_count)
            data1["Undefined Message"].append(undefined_msg)
            data1["Invalid Header"].append(invalid_header)
            data1["Undefined Attributes"].append(undefined_attr)
            data1["Invalid Attributes"].append(invalid_attr)
            data1["Invalid Semantics"].append(invalid_semantics)
            data1["Proprietary Header"].append(proprietary_header)

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
                data1["Non-Compliant Packets"].append(
                    undefined_msg
                    + invalid_header
                    + undefined_attr
                    + invalid_attr
                    + invalid_semantics
                )
                data1["Compliant Packets"].append(
                    packet_count
                    - undefined_msg
                    - invalid_header
                    - undefined_attr
                    - invalid_attr
                    - invalid_semantics
                )
                # data1["Non-Compliance Ratio"].append(data1["Non-Compliant Packets"][-1] / packet_count)
                data1["Compliance Ratio"].append(
                    data1["Compliant Packets"][-1] / packet_count
                )

    data2["Percent of Unknown Packets"].append(
        total_unknown_packets / metrics_dict["Total Packets"] * 100
    )
    data2["Percent of Undefined Messenge"].append(
        sum(data1["Undefined Message"]) / metrics_dict["Total Packets"] * 100
    )
    data2["Percent of Invalid Header"].append(
        sum(data1["Invalid Header"]) / metrics_dict["Total Packets"] * 100
    )
    data2["Percent of Undefined Attributes"].append(
        sum(data1["Undefined Attributes"]) / metrics_dict["Total Packets"] * 100
    )
    data2["Percent of Invalid Attributes"].append(
        sum(data1["Invalid Attributes"]) / metrics_dict["Total Packets"] * 100
    )
    data2["Percent of Invalid Semantics"].append(
        sum(data1["Invalid Semantics"]) / metrics_dict["Total Packets"] * 100
    )
    data2["Percent of Proprietary Header"].append(
        sum(data1["Proprietary Header"]) / metrics_dict["Total Packets"] * 100
    )
    data2["Percent of Non-Compliant Packets"].append(
        sum(data1["Non-Compliant Packets"]) / metrics_dict["Total Packets"] * 100
    )
    data2["Percent of Compliant Packets"].append(
        sum(data1["Compliant Packets"]) / metrics_dict["Total Packets"] * 100
    )
    data2["Total Percentage"].append(
        data2["Percent of Non-Compliant Packets"][0]
        + data2["Percent of Compliant Packets"][0]
    )

    # Convert to DataFrame
    df1 = pd.DataFrame(data1)
    df1_ext = pd.DataFrame(data1_ext)
    df2 = pd.DataFrame(data2)
    # df3 = pd.DataFrame(data3).T
    # df3.columns = ["" if col == 0 else col for col in df3.columns]

    file_name_xlsx = file_name + ".xlsx"
    with pd.ExcelWriter(file_name_xlsx, engine="openpyxl") as writer:
        df1.to_excel(writer, sheet_name=sheet_name, index=False)
        df1_ext.to_excel(
            writer, sheet_name=sheet_name, startcol=len(df1.columns) + 1, index=False
        )
        # df2.to_excel(writer, sheet_name=sheet_name, startrow=len(df1) + 1, index=False)
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


# def main(app_name, test_name, test_round, client_type, call_num=1):
def main(pcap_file, save_name, app_name, call_num=1, noise_duration=0):
    # main_folder = "Apps"
    # output_folder = "metrics" + "/" + app_name + "/" + test_name
    # if not os.path.exists(output_folder):
    #     os.makedirs(output_folder)
    # pcap_file = f"./{main_folder}/{app_name}/{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
    # save_name = f"./{output_folder}/{app_name}_{test_name}_{test_round}_{client_type}"

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

    avoid_protocols = "(!mdns and !tls and !icmp and !icmpv6 and !dns)"

    if app_name == "Zoom":
        p2p_protocol = "zoom"
        lua_file = "zoom.lua"
        target_protocols.remove("QUIC")
        standard_protocols.remove("QUIC")
        extractable_protocols.pop("QUIC")
    elif app_name == "FaceTime":
        p2p_protocol = "facetime"
        lua_file = "facetime.lua"
    elif app_name == "WhatsApp" or app_name == "Messenger":
        p2p_protocol = "wasp"
        lua_file = "wasp.lua"
        target_protocols.remove("QUIC")
        standard_protocols.remove("QUIC")
        extractable_protocols.pop("QUIC")
        extractable_protocols["STUN"] = "stun or classicstun or wasp"
        extractable_protocols["Unknown"] = (
            "!(rtp or rtcp or quic or stun or wasp or classicstun)"
        )
    elif app_name == "Discord":
        p2p_protocol = ""
        lua_file = "discord.lua"
        target_protocols.remove("QUIC")
        standard_protocols.remove("QUIC")
        extractable_protocols.pop("QUIC")
        target_protocols.remove("STUN")
        standard_protocols.remove("STUN")
        extractable_protocols.pop("STUN")
    else:
        raise Exception("Invalid app name.")

    target_folder_path = "/Users/sam/.local/lib/wireshark/plugins"
    storage_folder_path = "/Users/sam/.local/lib/wireshark/disabled"
    move_file_to_target(target_folder_path, lua_file, storage_folder_path)

    print(f"Pcap file: {pcap_file}")
    
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
    
    for i in range(0, call_num):
        part_save_name = f"{save_name}_part_{i+1}"
        gap = 3
        if app_name == "Discord":
            gap = 4
        start = i * gap
        end = (i + 1) * gap

        timestamp_dict, zone_offset = find_timestamps(text_file)
        time_filter = get_time_filter(timestamp_dict, start=start, end=end)

        print(f"\nProcessing part {i+1} ...")
        stream_dict, p2p_ports, packet_count_raw, packet_count_filter = get_streams(
            pcap_file,
            target_protocols,
            zone_offset,
            noise_stream_dict,
            filter_code=time_filter + "and " + avoid_protocols,
        )
        print(f"Raw packets: {packet_count_raw}, Filtered packets: {packet_count_filter}")
        # stream_dict = add_delta_time(timestamp_dict, stream_dict)
        stream_filter = get_stream_filter(
            list(stream_dict["TCP"].keys()), list(stream_dict["UDP"].keys())
        )

        if len(stream_dict["P2P_TCP"]) != 0 or len(stream_dict["P2P_UDP"]) != 0:
            print("P2P streams found.")
            p2p_filter = get_stream_filter(
                list(stream_dict["P2P_TCP"].keys()), list(stream_dict["P2P_UDP"].keys())
            )
            decode_as = get_decode_as(p2p_ports, p2p_protocol)
            print(f"P2P filer: {p2p_filter}")
            print(f"Decode as: {decode_as}")
        else:
            print("No P2P streams found.")
            decode_as = {}
            p2p_filter = ""

        traffic_filter_no_p2p = (
            stream_filter + " and " + time_filter + " and " + avoid_protocols
        )
        if p2p_filter != "":
            traffic_filter = (
                "("
                + stream_filter
                + " or "
                + p2p_filter
                + ")"
                + " and "
                + time_filter
                + " and "
                + avoid_protocols
            )
            p2p_filter = p2p_filter + " and " + time_filter + " and " + avoid_protocols
        else:
            traffic_filter = traffic_filter_no_p2p
        print("\nFilter Code:")
        print(traffic_filter)

        print("\nMeasuring traffic ...")
        protocol_dict, protocol_compliance, metrics_dict, log, multi_proto_pkts = (
            count_packets(
                pcap_file,
                standard_protocols,
                # filter_code=traffic_filter_no_p2p,
                filter_code=traffic_filter,
                decode_as=decode_as,
            )
        )

        # if p2p_filter != "":
        #     print("\nMeasuring P2P traffic ...")
        #     prev_results = {
        #         "protocol_dict": protocol_dict,
        #         "protocol_compliance": protocol_compliance,
        #         "metrics_dict": metrics_dict,
        #         "log": log,
        #         "multi_proto_pkts": multi_proto_pkts,
        #     }
        #     protocol_dict, protocol_compliance, metrics_dict, log = count_packets(
        #         pcap_file,
        #         standard_protocols,
        #         filter_code=p2p_filter,
        #         decode_as=decode_as,
        #         prev_results=prev_results,
        #     )

        print("\nSaving results and pcaps ...")
        save_results(
            protocol_dict,
            protocol_compliance,
            metrics_dict,
            [packet_count_raw, packet_count_filter, metrics_dict["Total Packets"]],
            file_name=part_save_name,
            sheet_name=f"Part {i+1}",
            filter_code=traffic_filter,
            log=log,
            multi_proto_pkts=multi_proto_pkts,
            p2p=len(stream_dict["P2P_TCP"]) != 0 or len(stream_dict["P2P_UDP"]) != 0,
        )

        total = 0
        for name, code in extractable_protocols.items():
            total += extract_protocol(
                pcap_file,
                # f"./{output_folder}/{app_name}_{test_name}_{test_round}_{client_type}_part_{i+1}_{name}.pcap",
                f"{part_save_name}_{name}.pcap",
                code,
                filter_code=traffic_filter,
                decode_as=decode_as,
            )
        print(f"Total packets extracted: {total}")


if __name__ == "__main__":
    # app_name = "WhatsApp"  # or "Zoom", "FaceTime", "Discord", "Messenger", "WhatsApp"
    # test_name = "multicall_2ip_av_p2pcellular_c"
    # test_round = "t1"
    # client_type = "caller"
    # # main(app_name, test_name, test_round, client_type, call_num=3)  # Call the main function

    # main_folder = "Apps"
    # output_folder = "metrics" + "/" + app_name + "/" + test_name
    # if not os.path.exists(output_folder):
    #     os.makedirs(output_folder)
    # pcap_file = f"./{main_folder}/{app_name}/{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
    # save_name = f"./{output_folder}/{app_name}_{test_name}_{test_round}_{client_type}"
    # main(pcap_file, save_name, call_num=3)
    app_name = "Messenger"
    # pcap_file = f"./test_metrics/{app_name}_multicall_2ip_av_wifi_w_t1_caller.pcapng"
    # save_name = f"./test_metrics/{app_name}_multicall_2ip_av_wifi_w_t1_caller"
    pcap_file = f"./test_metrics/{app_name}_multicall_2mac_av_wifi_w_t1_caller.pcapng"
    save_name = f"./test_metrics/{app_name}_multicall_2mac_av_wifi_w_t1_caller"
    main(pcap_file, save_name, app_name, call_num=1, noise_duration=10)

    # apps = ["Zoom", "FaceTime", "WhatsApp", "Messenger", "Discord"]
    # tests = [
    #     "multicall_2mac_av_p2pwifi_w",
    #     "multicall_2mac_av_wifi_w",
    #     "multicall_2ip_av_p2pcellular_c",
    #     "multicall_2ip_av_p2pwifi_wc",
    #     "multicall_2ip_av_p2pwifi_w",
    #     "multicall_2ip_av_wifi_wc",
    #     "multicall_2ip_av_wifi_w",
    # ]
    # rounds = ["t1"]
    # client_types = ["caller"]
    # tasks = []
    # for app_name in apps:
    #     for test_name in tests:
    #         for test_round in rounds:
    #             for client_type in client_types:
    #                 tasks.append((app_name, test_name, test_round, client_type))
    # print(f"Total tasks: {len(tasks)}\n")
    # start = 0
    # end = len(tasks)
    # for i in range(start, end):
    #     app_name, test_name, test_round, client_type = tasks[i]
    #     print(
    #         f"\n==================== TASK {i+1}/{len(tasks)}: {app_name}_{test_name}_{test_round}_{client_type} ====================\n"
    #     )
    #     main(app_name, test_name, test_round, client_type, call_num=3)
