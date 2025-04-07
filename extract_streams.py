import os
import re
import sys
import time
import copy
import pyshark
import datetime
import multiprocessing
import numpy as np
import matplotlib.pyplot as plt
from scipy.ndimage import gaussian_filter1d

from utils import get_asn_description, read_from_json, save_dict_to_json, get_stream_filter, get_time_filter_from_str, find_timestamps, get_ip_type, save_as_new_pcap

this_file_location = os.path.dirname(os.path.realpath(__file__))


def extract_streams_from_pcap(pcap_file, filter_code="", noise=False, decode_as={}, save_file="", suppress_output=False):

    if suppress_output:
        sys.stdout = open(os.devnull, "w")

    asn_file = this_file_location + "/asn_description.json"
    ip_asn = read_from_json(asn_file) if os.path.exists(asn_file) else {}

    print(f"Extracting streams from {pcap_file}")

    streams = {}
    cap = pyshark.FileCapture(pcap_file, keep_packets=False, display_filter=filter_code, decode_as=decode_as)
    for packet in cap:
        print(f"Processing packet {int(packet.number)}", end="\r")

        if packet.number == "204":
            pass

        # No try/except: any missing attribute will raise an error.
        if hasattr(packet, "tcp") or hasattr(packet, "udp"):
            stream_type = "TCP" if hasattr(packet, "tcp") else "UDP"
            stream_id = int(packet.tcp.stream) if stream_type == "TCP" else int(packet.udp.stream)
            ip_layer = packet.ipv6 if hasattr(packet, "ipv6") else packet.ip
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            src_port = int(packet.tcp.srcport) if stream_type == "TCP" else int(packet.udp.srcport)
            dst_port = int(packet.tcp.dstport) if stream_type == "TCP" else int(packet.udp.dstport)
            ts = float(packet.sniff_timestamp)
            size = int(packet.tcp.len) if stream_type == "TCP" else (int(packet.udp.length) - 8)
        else:
            continue

        domain_name = ""
        if hasattr(packet, "TLS") and hasattr(packet.TLS, "handshake_extensions_server_name"):
            domain_name = packet.tls.handshake_extensions_server_name
        if hasattr(packet, "QUIC") and hasattr(packet.QUIC, "tls_handshake_extensions_server_name"):
            domain_name = packet.quic.tls_handshake_extensions_server_name

        for ip in [src_ip, dst_ip]:
            if ip not in ip_asn:
                ip_asn[ip] = get_asn_description(ip)
                if type(ip_asn[ip]) != str:
                    raise Exception(f"Error when getting ASN description for {ip}")
                save_dict_to_json(ip_asn, asn_file)

        if stream_type not in streams:
            streams[stream_type] = {}
        if stream_id not in streams[stream_type]:
            streams[stream_type][stream_id] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "src_asn": ip_asn.get(src_ip),
                "dst_asn": ip_asn.get(dst_ip),
                "timestamps": [],
                "payload_sizes": [],
                "domain_names": [],
                "packet_details": {},
            }
            if noise:
                streams[stream_type][stream_id]["label"] = False

        streams[stream_type][stream_id]["packet_details"][int(packet.number)] = {
            "timestamp": ts,
            "transport_protocol": stream_type,
            "stream_id": stream_id,
            "payload_size": size,
        }
        streams[stream_type][stream_id]["timestamps"].append(ts)
        streams[stream_type][stream_id]["payload_sizes"].append(size)
        if domain_name not in streams[stream_type][stream_id]["domain_names"] and domain_name != "":
            streams[stream_type][stream_id]["domain_names"].append(domain_name)

    print()
    cap.close()

    for stream_type, stream_dict in streams.items():
        for sid, info in stream_dict.items():
            timestamps = sorted(info["timestamps"])
            info["interpacket_times"] = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])] if len(timestamps) > 1 else []

    if save_file != "":
        save_dict_to_json(streams, save_file)
        print(f"Saved extracted streams to {save_file}")

    if suppress_output:
        sys.stdout.close()
        sys.stdout = sys.__stdout__

    return streams


def priorcall_filter(
    streams, start_time_dt, offset=0, five_tuple_filter=False, three_tuple_filter=False, local_ip_filter=False, domain_name_filter=False, heuristic_dn_filter=False, heuristic_port_filter=False
):
    start_time_dt -= datetime.timedelta(seconds=offset)
    start_time_ts = start_time_dt.timestamp()
    to_be_filtered = []
    dest_ip_port_pairs = {
        "TCP": set(),
        "UDP": set(),
    }
    local_ip_pairs = {
        "TCP": set(),
        "UDP": set(),
    }
    background_domain_names = set()
    for stream_type, stream_dict in streams.items():
        for stream_id, stream_info in stream_dict.items():
            timestamps = stream_info["timestamps"]
            if timestamps[0] < start_time_ts:
                if domain_name_filter:
                    background_domain_names.update(stream_info["domain_names"])
                dest_ip_port_pairs[stream_type].add((stream_info["dst_ip"], stream_info["dst_port"]))
                if get_ip_type(stream_info["src_ip"]) == get_ip_type(stream_info["dst_ip"]):
                    local_ip_pairs[stream_type].add((stream_info["src_ip"], stream_info["dst_ip"]))
                if five_tuple_filter:
                    to_be_filtered.append([stream_type, stream_id])
    if three_tuple_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                dest_ip_port_pair = (stream_info["dst_ip"], stream_info["dst_port"])
                if dest_ip_port_pair in dest_ip_port_pairs[stream_type] and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if local_ip_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                ip_pair = (stream_info["src_ip"], stream_info["dst_ip"])
                ip_pair_rev = (stream_info["dst_ip"], stream_info["src_ip"])
                if (ip_pair in local_ip_pairs[stream_type] or ip_pair_rev in local_ip_pairs[stream_type]) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if domain_name_filter:
        # print(f"Background domain names: {background_domain_names}")
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if any(domain_name in background_domain_names for domain_name in stream_info["domain_names"]) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if heuristic_dn_filter:
        bg_domains = ["google", "apple", "icloud"]
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                for domain_name in stream_info["domain_names"]:
                    if any(domain in domain_name for domain in bg_domains) and [stream_type, stream_id] not in to_be_filtered:
                        to_be_filtered.append([stream_type, stream_id])
                        break
    if heuristic_port_filter:
        bg_ports = [80, 53, 5353]
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if (stream_info["src_port"] in bg_ports or stream_info["dst_port"] in bg_ports) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    filtered_streams = {
        "TCP": set(),
        "UDP": set(),
    }
    for stream_type, stream_id in to_be_filtered:
        # print(f"Filtering stream {stream_id} of type {stream_type} due to precall filter.")
        filtered_streams[stream_type].add(stream_id)
        del streams[stream_type][stream_id]
    return filtered_streams, dest_ip_port_pairs, local_ip_pairs, background_domain_names


def postcall_filter(
    streams, end_time_dt, offset=0, five_tuple_filter=False, three_tuple_filter=False, local_ip_filter=False, domain_name_filter=False, heuristic_dn_filter=False, heuristic_port_filter=False
):
    end_time_dt += datetime.timedelta(seconds=offset)
    end_time_ts = end_time_dt.timestamp()
    to_be_filtered = []
    dest_ip_port_pairs = {
        "TCP": set(),
        "UDP": set(),
    }
    local_ip_pairs = {
        "TCP": set(),
        "UDP": set(),
    }
    background_domain_names = set()
    for stream_type, stream_dict in streams.items():
        for stream_id, stream_info in stream_dict.items():
            timestamps = stream_info["timestamps"]
            if timestamps[-1] > end_time_ts:
                if domain_name_filter:
                    background_domain_names.update(stream_info["domain_names"])
                dest_ip_port_pairs[stream_type].add((stream_info["dst_ip"], stream_info["dst_port"]))
                if get_ip_type(stream_info["src_ip"]) == get_ip_type(stream_info["dst_ip"]):
                    local_ip_pairs[stream_type].add((stream_info["src_ip"], stream_info["dst_ip"]))
                if five_tuple_filter:
                    to_be_filtered.append([stream_type, stream_id])
    if three_tuple_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                dest_ip_port_pair = (stream_info["dst_ip"], stream_info["dst_port"])
                if dest_ip_port_pair in dest_ip_port_pairs[stream_type] and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if local_ip_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                ip_pair = (stream_info["src_ip"], stream_info["dst_ip"])
                ip_pair_rev = (stream_info["dst_ip"], stream_info["src_ip"])
                if (ip_pair in local_ip_pairs[stream_type] or ip_pair_rev in local_ip_pairs[stream_type]) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if domain_name_filter:
        # print("Background domain names:", background_domain_names)
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if any(domain_name in background_domain_names for domain_name in stream_info["domain_names"]) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if heuristic_dn_filter:
        bg_domains = ["google", "apple", "icloud"]
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                for domain_name in stream_info["domain_names"]:
                    if any(domain in domain_name for domain in bg_domains) and [stream_type, stream_id] not in to_be_filtered:
                        to_be_filtered.append([stream_type, stream_id])
                        break
    if heuristic_port_filter:
        bg_ports = [80, 53, 5353]
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if (stream_info["src_port"] in bg_ports or stream_info["dst_port"] in bg_ports) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    filtered_streams = {
        "TCP": set(),
        "UDP": set(),
    }
    for stream_type, stream_id in to_be_filtered:
        # print(f"Filtering stream {stream_id} of type {stream_type} due to postcall filter.")
        filtered_streams[stream_type].add(stream_id)
        del streams[stream_type][stream_id]
    return filtered_streams, dest_ip_port_pairs, local_ip_pairs, background_domain_names


def history_filter(
    streams,
    all_dest_ip_port_pairs,
    all_local_ip_pairs,
    all_background_domain_names,
    three_tuple_filter=False,
    local_ip_filter=False,
    domain_name_filter=False,
    heuristic_dn_filter=False,
    heuristic_port_filter=False,
):
    to_be_filtered = []
    if three_tuple_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                dest_ip_port_pair = (stream_info["dst_ip"], stream_info["dst_port"])
                if dest_ip_port_pair in all_dest_ip_port_pairs[stream_type] and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if local_ip_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                ip_pair = (stream_info["src_ip"], stream_info["dst_ip"])
                ip_pair_rev = (stream_info["dst_ip"], stream_info["src_ip"])
                if (ip_pair in all_local_ip_pairs[stream_type] or ip_pair_rev in all_local_ip_pairs[stream_type]) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if domain_name_filter:
        # print("Background domain names:", background_domain_names)
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if any(domain_name in all_background_domain_names for domain_name in stream_info["domain_names"]) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if heuristic_dn_filter:
        bg_domains = ["google", "apple", "icloud"]
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                for domain_name in stream_info["domain_names"]:
                    if any(domain in domain_name for domain in bg_domains) and [stream_type, stream_id] not in to_be_filtered:
                        to_be_filtered.append([stream_type, stream_id])
                        break
    if heuristic_port_filter:
        bg_ports = [80, 53, 5353]
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if (stream_info["src_port"] in bg_ports or stream_info["dst_port"] in bg_ports) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    filtered_streams = {
        "TCP": set(),
        "UDP": set(),
    }
    for stream_type, stream_id in to_be_filtered:
        # print(f"Filtering stream {stream_id} of type {stream_type} due to histogram filter.")
        filtered_streams[stream_type].add(stream_id)
        del streams[stream_type][stream_id]
    return filtered_streams


def check_protocol_metric(streams, original_streams, rtc_protocol):
    """
    Compare filtered streams against original streams to evaluate protocol-specific metrics.

    Args:
        streams: The filtered streams after processing
        original_streams: The original streams before filtering
        rtc_protocol: Protocol to evaluate (e.g., "RTP", "RTCP", "STUN")

    Returns:
        tuple: (protocol_precision, protocol_recall)
            - protocol_precision: What percentage of packets in filtered streams are of the specified protocol
            - protocol_recall: What percentage of protocol packets from original streams are retained
    """
    # Track counts for precision and recall calculation
    protocol_packets_in_filtered = 0
    total_packets_in_filtered = 0
    protocol_packets_in_original = 0
    protocol_packets_retained = 0

    # Process each stream type (TCP/UDP)
    for stream_type in original_streams:
        orig_streams = original_streams.get(stream_type, {})
        filtered_streams = streams.get(stream_type, {})

        # Count protocol packets in original streams
        for sid, info in orig_streams.items():
            packet_details = info.get("packet_details", {})
            for packet_id, packet_info in packet_details.items():
                total_packets = len(info.get("timestamps", []))
                # Check if protocol information is available
                if "rtc_protocol" in packet_info and rtc_protocol in packet_info["rtc_protocol"]:
                    protocol_packets_in_original += 1
                    # Check if this packet is retained in filtered streams
                    if sid in filtered_streams:
                        protocol_packets_retained += 1

        # Count protocol packets in filtered streams
        for sid, info in filtered_streams.items():
            packet_details = info.get("packet_details", {})
            total_packets_in_filtered += len(info.get("timestamps", []))
            for packet_id, packet_info in packet_details.items():
                if "rtc_protocol" in packet_info and rtc_protocol in packet_info["rtc_protocol"]:
                    protocol_packets_in_filtered += 1

    # Calculate metrics
    protocol_precision = None
    if total_packets_in_filtered > 0:
        protocol_precision = protocol_packets_in_filtered / total_packets_in_filtered

    protocol_recall = None
    if protocol_packets_in_original > 0:
        protocol_recall = protocol_packets_retained / protocol_packets_in_original

    return protocol_precision, protocol_recall


def check_precision(streams, original_streams, show=False):
    """
    Compare the filtered streams against the original streams and print precision metrics:
    - Background streams (label == false) should be filtered out (i.e. missing from streams).
    - RTC streams (label == true) should be retained in streams.
    """

    # New variables for packet count precision in background streams.
    total_original_background_streams = 0
    total_original_background_packets = 0
    filtered_background_streams = 0
    filtered_background_packets = 0
    leftover_background_streams = 0
    leftover_background_packets = 0

    # New variables for packet count precision in RTC streams.
    total_original_rtc_streams = 0
    total_original_rtc_packets = 0
    lost_rtc_streams = 0
    lost_rtc_packets = 0
    kept_rtc_streams = 0
    kept_rtc_packets = 0

    for stream_type in original_streams:
        orig_streams = original_streams.get(stream_type, {})
        filtered_streams = streams.get(stream_type, {})
        for sid, info in orig_streams.items():
            label = info.get("label", True)
            num_packets = len(info.get("timestamps", []))
            if label is False:
                total_original_background_streams += 1
                total_original_background_packets += num_packets
                if sid not in filtered_streams:
                    filtered_background_streams += 1
                    filtered_background_packets += num_packets
                else:
                    leftover_background_streams += 1
                    leftover_background_packets += num_packets
            else:
                total_original_rtc_streams += 1
                total_original_rtc_packets += num_packets
                if sid not in filtered_streams:
                    lost_rtc_streams += 1
                    lost_rtc_packets += num_packets
                else:
                    kept_rtc_streams += 1
                    kept_rtc_packets += num_packets
    assert (
        total_original_background_streams == filtered_background_streams + leftover_background_streams
    ), f"{total_original_background_streams} != {filtered_background_streams} + {leftover_background_streams}"
    assert (
        total_original_background_packets == filtered_background_packets + leftover_background_packets
    ), f"{total_original_background_packets} != {filtered_background_packets} + {leftover_background_packets}"
    assert total_original_rtc_streams == lost_rtc_streams + kept_rtc_streams, f"{total_original_rtc_streams} != {lost_rtc_streams} + {kept_rtc_streams}"
    assert total_original_rtc_packets == lost_rtc_packets + kept_rtc_packets, f"{total_original_rtc_packets} != {lost_rtc_packets} + {kept_rtc_packets}"
    if show:
        print("Background streams:")
        print("  Total:", total_original_background_streams)
        print("  Correctly filtered:", filtered_background_streams)
        if total_original_background_streams > 0:
            print("  Filtering precision: {:.2f}%".format((filtered_background_streams / total_original_background_streams) * 100))
        else:
            print("  No background streams found.")

        # Packet-level precision for background streams.
        print("\nBackground stream packets:")
        print("  Total packets:", total_original_background_packets)
        print("  Correctly filtered packets:", filtered_background_packets)
        if total_original_background_packets > 0:
            print("  Packet filtering precision: {:.2f}%".format((filtered_background_packets / total_original_background_packets) * 100))
        else:
            print("  No background packets found.")

        print("\nRTC streams:")
        print("  Total:", total_original_rtc_streams)
        print("  Kept streams:", kept_rtc_streams)
        if total_original_rtc_streams > 0:
            print("  Retention precision: {:.2f}%".format((kept_rtc_streams / total_original_rtc_streams) * 100))
        else:
            print("  No RTC streams found.")

        # New RTC packet-level retention precision.
        print("\nRTC stream packets:")
        print("  Total packets:", total_original_rtc_packets)
        print("  Kept packets:", kept_rtc_packets)
        if total_original_rtc_packets > 0:
            print("  Packet retention precision: {:.2f}%".format((kept_rtc_packets / total_original_rtc_packets) * 100))
        else:
            print("  No RTC packets found.")

    filtered_background_stream_precision = filtered_background_streams / total_original_background_streams
    filtered_background_packets_precision = filtered_background_packets / total_original_background_packets
    rtc_stream_precision = kept_rtc_streams / (leftover_background_streams + kept_rtc_streams)
    rtc_packet_precision = kept_rtc_packets / (leftover_background_packets + kept_rtc_packets)
    rtc_stream_recall = kept_rtc_streams / total_original_rtc_streams
    rtc_packet_recall = kept_rtc_packets / total_original_rtc_packets

    return filtered_background_packets_precision, rtc_packet_precision, rtc_packet_recall


def print_streams(streams):
    rtc_streams = {
        "TCP": set(),
        "UDP": set(),
    }
    background_streams = {
        "TCP": set(),
        "UDP": set(),
    }
    for stream_type, stream_dict in streams.items():
        for stream_id, info in stream_dict.items():
            if "label" in info and info["label"] is False:
                background_streams[stream_type].add(int(stream_id))
            else:
                rtc_streams[stream_type].add(int(stream_id))

    rtc_filter_code = get_stream_filter(rtc_streams["TCP"], rtc_streams["UDP"])
    background_filter_code = get_stream_filter(background_streams["TCP"], background_streams["UDP"])
    print(f"RTC streams: \nTCP: {list(rtc_streams['TCP'])}\nUDP: {list(rtc_streams['UDP'])}")
    print(f"Background streams: \nTCP: {list(background_streams['TCP'])}\nUDP: {list(background_streams['UDP'])}")
    print(f"RTC streams: \n{rtc_filter_code}")
    print(f"Background streams: \n{background_filter_code}")

    return rtc_filter_code, background_filter_code


def get_rtc_streams(filter_code):
    rtc_streams = {
        "TCP": set(),
        "UDP": set(),
    }

    udp_ids = re.findall(r"udp\.stream\s*==\s*(\d+)", filter_code)
    if udp_ids:
        rtc_streams["UDP"] = udp_ids
    tcp_ids = re.findall(r"tcp\.stream\s*==\s*(\d+)", filter_code)
    if tcp_ids:
        rtc_streams["TCP"] = tcp_ids

    return rtc_streams


def label_streams(rtc_streams, streams):
    for stream_type, stream_dict in streams.items():
        for stream_id, info in stream_dict.items():
            if stream_id in rtc_streams[stream_type]:
                info["label"] = True
            else:
                info["label"] = False


def collect_background_info(streams, dest_ip_port_pairs, local_ip_pairs, background_domain_names):
    for stream_type, stream_dict in streams.items():
        for stream_id, info in stream_dict.items():
            if "label" in info and info["label"] is False:
                dest_ip_port_pairs[stream_type].add((info["dst_ip"], info["dst_port"]))
                if get_ip_type(info["src_ip"]) == get_ip_type(info["dst_ip"]):
                    local_ip_pairs[stream_type].add((info["src_ip"], info["dst_ip"]))
                background_domain_names.update(info["domain_names"])
    return dest_ip_port_pairs, local_ip_pairs, background_domain_names


def save_metrics_table(metrics_dict, save_path):
    """
    Process filter metrics dictionary and save as CSV table.

    Args:
        metrics_dict: Dictionary containing protocol metrics by app
        save_path: Path to save the CSV file
    """
    import pandas as pd
    import os

    # Create table structure for all apps
    all_apps_data = {}
    protocols = list(next(iter(metrics_dict.values())).keys())

    # Calculate median precision and recall for each app and protocol
    for app_name, app_metrics in metrics_dict.items():
        app_data = {}
        for protocol, protocol_metrics in app_metrics.items():
            precision_median = np.median(protocol_metrics["precision"]) if protocol_metrics["precision"] else 0
            recall_median = np.median(protocol_metrics["recall"]) if protocol_metrics["recall"] else 0
            app_data[f"{protocol}_precision"] = precision_median
            app_data[f"{protocol}_recall"] = recall_median
        all_apps_data[app_name] = app_data

    # Create DataFrame
    df = pd.DataFrame.from_dict(all_apps_data, orient="index")

    # Create overall metrics
    overall_data = {"Overall": {}}
    for protocol in protocols:
        all_precision = []
        all_recall = []
        for app_metrics in metrics_dict.values():
            all_precision.extend(app_metrics[protocol]["precision"])
            all_recall.extend(app_metrics[protocol]["recall"])

        overall_precision = np.median(all_precision) if all_precision else 0
        overall_recall = np.median(all_recall) if all_recall else 0
        overall_data["Overall"][f"{protocol}_precision"] = overall_precision
        overall_data["Overall"][f"{protocol}_recall"] = overall_recall

    overall_df = pd.DataFrame.from_dict(overall_data, orient="index")
    df = pd.concat([df, overall_df])

    # Rearrange to create the desired format
    result_df = pd.DataFrame(index=["Precision", "Recall"])
    for protocol in protocols:
        result_df[protocol] = [df[f"{protocol}_precision"]["Overall"], df[f"{protocol}_recall"]["Overall"]]

    # Save results
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    result_df.to_csv(save_path)

    # Also save the detailed results by app
    detailed_path = save_path.replace(".csv", "_detailed.csv")
    df.to_csv(detailed_path)

    print(f"Metrics table saved to {save_path}")
    print(f"Detailed metrics by app saved to {detailed_path}")

    # Print the summary table to console
    print("\nProtocol Performance Metrics (Median Values):")
    print(result_df)


def load_filters(folder):
    all_dest_ip_port_pairs = {
        "TCP": set(),
        "UDP": set(),
    }
    all_local_ip_pairs = {
        "TCP": set(),
        "UDP": set(),
    }
    all_background_domain_names = set()

    if os.path.exists(f"{folder}/dest_ip_port_pairs.json"):
        all_dest_ip_port_pairs = read_from_json(f"{folder}/dest_ip_port_pairs.json")
        temp_set = set()
        for s in all_dest_ip_port_pairs["TCP"]:
            temp_set.add(tuple(s))
        all_dest_ip_port_pairs["TCP"] = temp_set
        temp_set = set()
        for s in all_dest_ip_port_pairs["UDP"]:
            temp_set.add(tuple(s))
        all_dest_ip_port_pairs["UDP"] = temp_set
    if os.path.exists(f"{folder}/local_ip_pairs.json"):
        all_local_ip_pairs = read_from_json(f"{folder}/local_ip_pairs.json")
        temp_set = set()
        for s in all_local_ip_pairs["TCP"]:
            temp_set.add(tuple(s))
        all_local_ip_pairs["TCP"] = temp_set
        temp_set = set()
        for s in all_local_ip_pairs["UDP"]:
            temp_set.add(tuple(s))
        all_local_ip_pairs["UDP"] = temp_set
    if os.path.exists(f"{folder}/background_domain_names.json"):
        all_background_domain_names_dict = read_from_json(f"{folder}/background_domain_names.json")
        all_background_domain_names = set(all_background_domain_names_dict["background_domain_names"])

    return all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names


def save_filters(folder, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names):
    for key in all_dest_ip_port_pairs:
        all_dest_ip_port_pairs[key] = list(all_dest_ip_port_pairs[key])
    for key in all_local_ip_pairs:
        all_local_ip_pairs[key] = list(all_local_ip_pairs[key])
    all_background_domain_names_dict = {"background_domain_names": list(all_background_domain_names)}
    # save all_dest_ip_port_pairs to json file
    save_dict_to_json(all_dest_ip_port_pairs, f"{folder}/dest_ip_port_pairs.json")
    # save all_local_ip_pairs to json file
    save_dict_to_json(all_local_ip_pairs, f"{folder}/local_ip_pairs.json")
    # save all_background_domain_names to json file
    save_dict_to_json(all_background_domain_names_dict, f"{folder}/background_domain_names.json")


if __name__ == "__main__":

    pcap_main_folder = "/Users/sam/Downloads/data"
    save_main_folder = "/Users/sam/Downloads/metrics"
    # save_main_folder = "./test_metrics"
    # save_main_folder = "/Users/sam/Downloads/noise_metrics"
    # save_main_folder = "/Users/sam/Downloads/noise_metrics2"
    # save_main_folder = "/Users/sam/Downloads/noise_metrics3"

    # Get data and noise info

    multiprocess = True
    # multiprocess = False

    apps = [
        "Zoom",
        "FaceTime",
        "WhatsApp",
        "Messenger",
        "Discord",
    ]
    tests = {
        "2ip_av_cellular_cc": 1,
        "2ip_av_p2pwifi_ww": 1,
        "2ip_av_wifi_ww": 1,
        "noise_2ip_av_cellular_cc": 1,
        "noise_2ip_av_p2pwifi_ww": 1,
        "noise_2ip_av_wifi_ww": 1,
    }
    rounds = ["t1", "t2", "t3", "t4", "t5"]
    client_types = [
        "caller",
        "callee",
    ]
    noise_duration = 60
    base_gap = 3

    # for app_name in apps:

    #     pcap_files = []
    #     stream_files = []
    #     time_filters = []
    #     is_noise_flags = []
    #     save_names = []

    #     for test_name in tests:
    #         is_noise = "noise" in test_name

    #         for test_round in rounds:
    #             for client_type in client_types:
    #                 text_file = f"{pcap_main_folder}/{app_name}/{app_name}_{test_name}_{test_round}.txt"
    #                 pcap_file = f"{pcap_main_folder}/{app_name}/{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
    #                 if not os.path.exists(pcap_file):
    #                     continue

    #                 for i in range(1, tests[test_name] + 1):
    #                     stream_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}_streams.json"
    #                     if not os.path.exists(stream_file):
    #                         if not os.path.exists(f"{save_main_folder}/{app_name}/{test_name}/"):
    #                             os.makedirs(f"{save_main_folder}/{app_name}/{test_name}/")

    #                         time_code = ""
    #                         if not is_noise:
    #                             timestamp_dict, zone_offset = find_timestamps(text_file)
    #                             ts = list(timestamp_dict.keys())
    #                             gap = base_gap
    #                             if app_name == "Discord":
    #                                 gap = base_gap + 1
    #                             start = (i - 1) * gap
    #                             end = (i) * gap
    #                             start_time_str = ts[start].strftime("%Y-%m-%d %H:%M:%S.%f%z")
    #                             end_time_str = ts[end].strftime("%Y-%m-%d %H:%M:%S.%f%z")
    #                             time_code = get_time_filter_from_str(start_time_str, end_time_str, offset=noise_duration)

    #                         pcap_files.append(pcap_file)
    #                         stream_files.append(stream_file)
    #                         time_filters.append(time_code)
    #                         is_noise_flags.append(is_noise)
    #                         save_names.append(f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}")

    #     processes = []
    #     process_start_times = []
    #     for pcap_file, stream_file, time_filter, is_noise in zip(pcap_files, stream_files, time_filters, is_noise_flags):
    #         if multiprocess:
    #             p = multiprocessing.Process(target=extract_streams_from_pcap, args=(pcap_file, time_filter, is_noise, {}, stream_file, True))
    #             process_start_times.append(time.time())
    #             processes.append(p)
    #             p.start()
    #         else:
    #             extract_streams_from_pcap(pcap_file, filter_code=time_filter, save_file=stream_file, suppress_output=False, noise=is_noise)

    #     if multiprocess:
    #         print(f"\n{app_name} tasks started.\n")

    #         lines = len(processes)
    #         elapsed_times = [0] * len(processes)
    #         print("\n" * lines, end="")
    #         while True:
    #             all_finished = True
    #             status = ""
    #             for i, p in enumerate(processes):
    #                 if p.is_alive():
    #                     elapsed_time = int(time.time() - process_start_times[i])
    #                     elapsed_times[i] = elapsed_time
    #                     all_finished = False
    #                     status += f"Running\t|{elapsed_time}s\t|{save_names[i]}\n"
    #                 else:
    #                     elapsed_time = elapsed_times[i]
    #                     if p.exitcode is None:
    #                         status += f"Unknown\t|{elapsed_time}s\t|{save_names[i]}\n"
    #                     elif p.exitcode == 0:
    #                         status += f"Done\t|{elapsed_time}s\t|{save_names[i]}\n"
    #                     else:
    #                         status += f"Code {p.exitcode}\t|{elapsed_time}s\t|{save_names[i]}\n"

    #             if status[-1] == "\n":
    #                 status = status[:-1]
    #             print("\033[F" * lines, end="")  # Move cursor up
    #             for _ in range(lines):
    #                 print("\033[K\n", end="")  # Clear the line
    #             print("\033[F" * lines, end="")  # Move cursor up
    #             print(status)

    #             if all_finished:
    #                 print(f"\nAll {app_name} tasks are finished. (Average Runtime: {sum(elapsed_times) / len(elapsed_times):.2f}s)")
    #                 break
    #             time.sleep(1)

    #         for p in processes:
    #             p.join()

    # all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters(save_main_folder)

    # for app_name in apps:
    #     for test_name in tests:
    #         if "noise" not in test_name:
    #             continue

    #         for test_round in rounds:
    #             for client_type in client_types:
    #                 pcap_file = f"{pcap_main_folder}/{app_name}/{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
    #                 if not os.path.exists(pcap_file):
    #                     continue

    #                 for i in range(1, tests[test_name] + 1):
    #                     stream_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}_streams.json"
    #                     if os.path.exists(stream_file):
    #                         streams = read_from_json(stream_file)
    #                         collect_background_info(streams, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)
    #                     else:
    #                         raise FileNotFoundError(f"Stream file not found: {stream_file}. Make sure the extraction was successful.")

    # save_filters(save_main_folder, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)

    # exit()

    # Filter data

    all_filter_precision = []
    all_rtc_precision = []
    all_rtc_recall = []

    filter_metrics_dict = {}

    all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters(save_main_folder)

    for app_name in apps:
        filter_metrics_dict[app_name] = {
            "STUN": {
                "precision": [],
                "recall": [],
            },
            "RTP": {
                "precision": [],
                "recall": [],
            },
            "RTCP": {
                "precision": [],
                "recall": [],
            },
            "QUIC": {
                "precision": [],
                "recall": [],
            },
        }
        rtc_protocols = filter_metrics_dict[app_name].keys()
        for test_name in tests:
            if "noise" in test_name:
                continue
            for test_round in rounds:
                for client_type in client_types:
                    for i in range(1, tests[test_name] + 1):
                        text_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}.txt"
                        pcap_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
                        stream_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}_streams.json"
                        info_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}.json"

                        if os.path.exists(info_file):
                            print(f"Processing {app_name} {test_name} {test_round} {client_type} part {i}")
                        else:
                            print(f"Skipping {app_name} {test_name} {test_round} {client_type} part {i}")
                            continue

                        timestamp_dict, zone_offset = find_timestamps(text_file)
                        ts = list(timestamp_dict.keys())
                        gap = base_gap
                        if app_name == "Discord":
                            gap = base_gap + 1
                        start = (i - 1) * gap
                        end = (i) * gap
                        start_time_dt = ts[start]
                        end_time_dt = ts[end]

                        info = read_from_json(info_file)
                        streams = read_from_json(stream_file)
                        filter_code = info["Filter Code"]
                        rtc_streams = get_rtc_streams(filter_code)
                        label_streams(rtc_streams, streams)
                        offset = 10

                        original_streams = copy.deepcopy(streams)
                        # print("\nOriginal:")
                        # print_streams(original_streams)

                        # collect_background_info(streams, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)

                        results = priorcall_filter(
                            streams,
                            start_time_dt,
                            offset,
                            five_tuple_filter=True,
                            three_tuple_filter=True,
                            local_ip_filter=True,
                            domain_name_filter=True,
                            heuristic_dn_filter=True,
                            heuristic_port_filter=True,
                        )
                        filtered1, dest_ip_port_pairs, local_ip_pairs, background_domain_names = results
                        p, rtc_p, rtc_rtn = check_precision(streams, original_streams)
                        # all_dest_ip_port_pairs["TCP"].update(dest_ip_port_pairs["TCP"])
                        # all_dest_ip_port_pairs["UDP"].update(dest_ip_port_pairs["UDP"])
                        # all_local_ip_pairs["TCP"].update(local_ip_pairs["TCP"])
                        # all_local_ip_pairs["UDP"].update(local_ip_pairs["UDP"])
                        # all_background_domain_names.update(background_domain_names)
                        # print(f"\nFilter 1:")
                        # print_streams(streams)
                        # print(f"Filtered streams: \n{get_stream_filter(filtered1['TCP'], filtered1['UDP'])}")

                        results = postcall_filter(
                            streams,
                            end_time_dt,
                            offset,
                            five_tuple_filter=True,
                            three_tuple_filter=True,
                            local_ip_filter=True,
                            domain_name_filter=True,
                            heuristic_dn_filter=True,
                            heuristic_port_filter=True,
                        )
                        filtered2, dest_ip_port_pairs, local_ip_pairs, background_domain_names = results
                        p, rtc_p, rtc_rtn = check_precision(streams, original_streams)
                        # all_dest_ip_port_pairs["TCP"].update(dest_ip_port_pairs["TCP"])
                        # all_dest_ip_port_pairs["UDP"].update(dest_ip_port_pairs["UDP"])
                        # all_local_ip_pairs["TCP"].update(local_ip_pairs["TCP"])
                        # all_local_ip_pairs["UDP"].update(local_ip_pairs["UDP"])
                        # all_background_domain_names.update(background_domain_names)
                        # print(f"\nFilter 2:")
                        # print_streams(streams)
                        # print(f"Filtered streams: \n{get_stream_filter(filtered2['TCP'], filtered2['UDP'])}")

                        results = history_filter(
                            streams,
                            all_dest_ip_port_pairs,
                            all_local_ip_pairs,
                            all_background_domain_names,
                            three_tuple_filter=True,
                            local_ip_filter=True,
                            domain_name_filter=True,
                            heuristic_dn_filter=True,
                            heuristic_port_filter=True,
                        )
                        filtered = results
                        p, rtc_p, rtc_rtn = check_precision(streams, original_streams)
                        # print(f"\nHistory Filter:")
                        # _, bg_filter = print_streams(streams)
                        # print(f"Filtered streams: \n{get_stream_filter(filtered['TCP'], filtered['UDP'])}")

                        # noise_pcap_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part_{i}_noise.pcapng"
                        # save_as_new_pcap(pcap_file, noise_pcap_file, bg_filter)

                        all_filter_precision.append(p)
                        all_rtc_precision.append(rtc_p)
                        all_rtc_recall.append(rtc_rtn)

                        for rtc_protocol in rtc_protocols:
                            precision, recall = check_protocol_metric(streams, original_streams, rtc_protocol)
                            if precision is not None and recall is not None:
                                filter_metrics_dict[app_name][rtc_protocol]["precision"].append(precision)
                                filter_metrics_dict[app_name][rtc_protocol]["recall"].append(recall)

    # print(f"Average filter precision: {np.mean(all_filter_precision)}")
    # print(f"Median filter precision: {np.median(all_filter_precision)}")
    print(f"Average filter precision: {np.mean(all_rtc_precision)}")
    print(f"Median filter precision: {np.median(all_rtc_precision)}")
    print(f"Average filter reacll: {np.mean(all_rtc_recall)}")
    print(f"Median filter recall: {np.median(all_rtc_recall)}")

    # save_filters(save_main_folder, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)

    # Save the metrics table
    metrics_table_path = f"{save_main_folder}/protocol_metrics_table.csv"
    save_metrics_table(filter_metrics_dict, metrics_table_path)
