import os
import re
import copy
import pyshark
import datetime
import numpy as np
import matplotlib.pyplot as plt
from scipy.ndimage import gaussian_filter1d

from utils import get_asn_description, read_from_json, save_dict_to_json, get_stream_filter, get_time_filter_from_str, find_timestamps, get_ip_type, save_as_new_pcap

this_file_location = os.path.dirname(os.path.realpath(__file__))


def extract_streams_from_pcap(pcap_file, filter_code="", noise=False, decode_as={}):
    asn_file = this_file_location + "/asn_description.json"
    ip_asn = read_from_json(asn_file) if os.path.exists(asn_file) else {}

    streams = {}
    domain_names = set()
    cap = pyshark.FileCapture(pcap_file, keep_packets=False, display_filter=filter_code, decode_as=decode_as, use_json=True, include_raw=True)
    for packet in cap:
        print(f"Processing packet {packet.number}", end="\r")

        # if packet.number == "658":
        #     pass

        # No try/except: any missing attribute will raise an error.
        if hasattr(packet, "tcp") or hasattr(packet, "udp"):
            stream_type = "TCP" if hasattr(packet, "tcp") else "UDP"
            stream_id = packet.tcp.stream if stream_type == "TCP" else getattr(packet.udp, "stream", packet.number)
            ip_layer = packet.ipv6 if hasattr(packet, "ipv6") else packet.ip
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            src_port = packet.tcp.srcport if stream_type == "TCP" else packet.udp.srcport
            dst_port = packet.tcp.dstport if stream_type == "TCP" else packet.udp.dstport
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
                "timestamps": [],
                "payload_sizes": [],
                "src_asn": ip_asn.get(src_ip),
                "dst_asn": ip_asn.get(dst_ip),
                "domain_names": [],
            }
            if noise:
                streams[stream_type][stream_id]["label"] = False

        # Directly convert; potential errors will be visible.
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
    return streams


def generate_histograms(dataset_p, dataset_q, bins=50):
    dataset_p = np.asarray(dataset_p)
    dataset_q = np.asarray(dataset_q)

    if len(dataset_p) == 0 or len(dataset_q) == 0:
        raise ValueError("Datasets must not be empty.")

    combined = np.concatenate([dataset_p, dataset_q])
    min_val = np.min(combined)
    max_val = np.max(combined)

    bin_edges = np.linspace(min_val, max_val, bins + 1)
    hist_p, bins_p = np.histogram(dataset_p, bins=bin_edges)
    hist_q, bins_q = np.histogram(dataset_q, bins=bin_edges)

    return hist_p, bins_p, hist_q, bins_q


def kl_divergence(dataset_p, dataset_q, bins=50, epsilon=1e-9, sigma=2):
    """
    Compute the Kullback-Leibler divergence between two datasets.

    Parameters:
    - dataset_p, dataset_q: Lists or arrays of 1D data points.
    - bins: Number of bins to use for histogram estimation.
    - epsilon: Smoothing term to avoid zero probabilities.

    Returns:
    - KL divergence (KL(P || Q)).
    """
    hist_p, _, hist_q, _ = generate_histograms(dataset_p, dataset_q, bins)
    hist_p = hist_p.astype(float) + epsilon
    hist_q = hist_q.astype(float) + epsilon

    hist_p = gaussian_filter1d(hist_p, sigma=sigma)
    hist_q = gaussian_filter1d(hist_q, sigma=sigma)

    prob_p = hist_p / np.sum(hist_p)
    prob_q = hist_q / np.sum(hist_q)
    kl = np.sum(prob_p * np.log(prob_p / prob_q))

    return kl


def plot_comparison(stream_A, stream_B, sigma=2):
    ip_A = stream_A["interpacket_times"]
    ip_B = stream_B["interpacket_times"]
    ps_A = stream_A["payload_sizes"]
    ps_B = stream_B["payload_sizes"]

    ip_hist_A, ip_bins_A, ip_hist_B, ip_bins_B = generate_histograms(ip_A, ip_B)
    ps_hist_A, ps_bins_A, ps_hist_B, ps_bins_B = generate_histograms(ps_A, ps_B)

    # smoothen histograms
    smoothed_ip_hist_A = gaussian_filter1d(ip_hist_A, sigma=sigma)
    smoothed_ip_hist_B = gaussian_filter1d(ip_hist_B, sigma=sigma)
    smoothed_ps_hist_A = gaussian_filter1d(ps_hist_A, sigma=sigma)
    smoothed_ps_hist_B = gaussian_filter1d(ps_hist_B, sigma=sigma)

    fig, axs = plt.subplots(2, 2, figsize=(12, 8))
    axs[0, 0].bar(ip_bins_A[:-1], ip_hist_A, width=np.diff(ip_bins_A), align="edge", alpha=0.5)
    axs[0, 0].plot(ip_bins_A[:-1], smoothed_ip_hist_A, color="red", marker="o")
    axs[0, 0].set_title("Stream A: Interpacket Time Distribution")
    axs[0, 0].set_xlabel("Interpacket Time")
    axs[0, 0].set_ylabel("Frequency")

    axs[0, 1].bar(ip_bins_B[:-1], ip_hist_B, width=np.diff(ip_bins_B), align="edge", alpha=0.5)
    axs[0, 1].plot(ip_bins_B[:-1], smoothed_ip_hist_B, color="red", marker="o")
    axs[0, 1].set_title("Stream B: Interpacket Time Distribution")
    axs[0, 1].set_xlabel("Interpacket Time")
    axs[0, 1].set_ylabel("Frequency")

    axs[1, 0].bar(ps_bins_A[:-1], ps_hist_A, width=np.diff(ps_bins_A), align="edge", alpha=0.5)
    axs[1, 0].plot(ps_bins_A[:-1], smoothed_ps_hist_A, color="red", marker="o")
    axs[1, 0].set_title("Stream A: Packet Size Distribution")
    axs[1, 0].set_xlabel("Packet Size")
    axs[1, 0].set_ylabel("Frequency")

    axs[1, 1].bar(ps_bins_B[:-1], ps_hist_B, width=np.diff(ps_bins_B), align="edge", alpha=0.5)
    axs[1, 1].plot(ps_bins_B[:-1], smoothed_ps_hist_B, color="red", marker="o")
    axs[1, 1].set_title("Stream B: Packet Size Distribution")
    axs[1, 1].set_xlabel("Packet Size")
    axs[1, 1].set_ylabel("Frequency")

    plt.tight_layout()
    plt.show()


def compare_dual_streams(dict_A, dict_B):
    """
    For each stream in dict_A, find any matching stream in dict_B with the same stream type and same set of ASN values.
    For every such match, compute the KL divergence for interpacket time and packet size distributions, and append the results.
    Each stream info dict will have a key "kl_divergence" storing a list of comparisons, with each comparison being a dict:
      - "interpacket_time": divergence score,
      - "packet_size": divergence score,
      - "compared_with": the matching stream id
    """
    for stream_type in dict_A:
        if stream_type not in dict_B:
            continue
        for stream_id_A, info_A in dict_A[stream_type].items():
            if len(info_A["interpacket_times"]) == 0 or len(info_A["payload_sizes"]) == 0:
                continue
            asn_set_A = {info_A.get("src_asn"), info_A.get("dst_asn")}
            for stream_id_B, info_B in dict_B[stream_type].items():
                if len(info_B["interpacket_times"]) == 0 or len(info_B["payload_sizes"]) == 0:
                    continue
                asn_set_B = {info_B.get("src_asn"), info_B.get("dst_asn")}
                if asn_set_A == asn_set_B:
                    kl_ip = kl_divergence(info_A["interpacket_times"], info_B["interpacket_times"])
                    kl_ps = kl_divergence(info_A["payload_sizes"], info_B["payload_sizes"])
                    comp_A = {"interpacket_time": kl_ip, "packet_size": kl_ps, "compared_with": stream_id_B}
                    comp_B = {"interpacket_time": kl_ip, "packet_size": kl_ps, "compared_with": stream_id_A}
                    info_A.setdefault("kl_divergence", []).append(comp_A)
                    info_B.setdefault("kl_divergence", []).append(comp_B)


def filter_dual_streams(streams_A, streams_B):
    to_be_keep_A = set()
    to_be_keep_B = set()
    for stream_type, stream_dict in streams_A.items():
        for stream_id, info in stream_dict.items():
            if "kl_divergence" not in info:
                continue
            for peer_stream in info["kl_divergence"]:
                if peer_stream["interpacket_time"] < 1 and peer_stream["packet_size"] < 1:
                    to_be_keep_A.add((stream_type, stream_id))
                    to_be_keep_B.add((stream_type, peer_stream["compared_with"]))

    to_be_filtered_A = []
    to_be_filtered_B = []
    for stream_type, stream_dict in streams_A.items():
        for stream_id, info in stream_dict.items():
            if (stream_type, stream_id) not in to_be_keep_A:
                to_be_filtered_A.append([stream_type, stream_id])
    for stream_type, stream_dict in streams_B.items():
        for stream_id, info in stream_dict.items():
            if (stream_type, stream_id) not in to_be_keep_B:
                to_be_filtered_B.append([stream_type, stream_id])
    for stream_type, stream_id in to_be_filtered_A:
        # print(f"Filtering stream {stream_id} of type {stream_type} due to crosscall filter.")
        del streams_A[stream_type][stream_id]
    for stream_type, stream_id in to_be_filtered_B:
        # print(f"Filtering stream {stream_id} of type {stream_type} due to crosscall filter.")
        del streams_B[stream_type][stream_id]


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
        bg_ports = ["80", "53", "5353"]
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
        bg_ports = ["80", "53", "5353"]
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


def crosscall_filter(streams_group):
    for i in range(len(streams_group) - 1):
        streams_A = streams_group[i]
        streams_B = streams_group[i + 1]
        compare_dual_streams(streams_A, streams_B)
        filter_dual_streams(streams_A, streams_B)
        for stream_type, stream_dict in streams_B.items():
            for stream_id, info in stream_dict.items():
                if "kl_divergence" in info:
                    del info["kl_divergence"]


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
    rtc_stream_retention = kept_rtc_streams / total_original_rtc_streams
    rtc_packet_retention = kept_rtc_packets / total_original_rtc_packets

    return filtered_background_packets_precision, rtc_packet_precision, rtc_packet_retention


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

    # pcap_main_folder = "/Users/sam/Downloads/data"
    # save_main_folder = "/Users/sam/Downloads/metrics"

    # apps = [
    #     "Zoom",
    #     "FaceTime",
    #     "WhatsApp",
    #     "Messenger",
    #     "Discord",
    # ]
    # tests = {  # test_name: call_num
    #     "noise_2ip_av_cellular_cc": 1,
    # }
    # rounds = ["t1"]
    # client_types = [
    #     "caller",
    #     "callee",
    # ]

    # all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters(save_main_folder)

    # for app_name in apps:
    #     for test_name in tests:
    #         for test_round in rounds:
    #             for client_type in client_types:
    #                 for i in range(1, tests[test_name] + 1):
    #                     noise_file = f"{pcap_main_folder}/{app_name}/{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
    #                     stream_file = f"{pcap_main_folder}/{app_name}/{app_name}_{test_name}_{test_round}_{client_type}_part_{i}_streams.json"
    #                     if os.path.exists(stream_file):
    #                         streams = read_from_json(stream_file)
    #                     else:
    #                         streams = extract_streams_from_pcap(noise_file, noise=True)
    #                     save_dict_to_json(streams, stream_file)
    #                     collect_background_info(streams, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)
    # save_filters(save_main_folder, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)

    # exit()

    # # noise_file = "/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_noise_2ip_av_wifi_ww_t1_caller.pcapng"
    # # stream_file = "/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_noise_2ip_av_wifi_ww_t1_caller_streams.json"
    # noise_file = "/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_noise_2ip_av_wifi_ww_t1_callee.pcapng"
    # stream_file = "/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_noise_2ip_av_wifi_ww_t1_callee_streams.json"
    # if os.path.exists(stream_file):
    #     streams = read_from_json(stream_file)
    # else:
    #     streams = extract_streams_from_pcap(noise_file, noise=True)
    # save_dict_to_json(streams, stream_file)
    # all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters("/Users/sam/Downloads/noise_metrics3")
    # collect_background_info(streams, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)
    # save_filters("/Users/sam/Downloads/noise_metrics3", all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)

    # exit()

    # # text_file = "/Users/sam/Desktop/rtc_code/test_metrics/Zoom/multicall_2ip_av_wifi_w/Zoom_multicall_2ip_av_wifi_w_t1.txt"
    # # pcap_file = "/Users/sam/Desktop/rtc_code/test_metrics/Zoom/multicall_2ip_av_wifi_w/Zoom_multicall_2ip_av_wifi_w_t1_caller.pcapng"
    # # stream_file = "/Users/sam/Desktop/rtc_code/test_metrics/Zoom/multicall_2ip_av_wifi_w/Zoom_multicall_2ip_av_wifi_w_t1_callee_part_1_streams.json"
    # # info_file = "/Users/sam/Desktop/rtc_code/test_metrics/Zoom/multicall_2ip_av_wifi_w/Zoom_multicall_2ip_av_wifi_w_t1_caller_part_1.json"
    # text_file = "/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_5minNoise_2ip_av_wifi_ww_t1.txt"
    # pcap_file = "/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_5minNoise_2ip_av_wifi_ww_t1_caller.pcapng"
    # stream_file = "/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_5minNoise_2ip_av_wifi_ww_t1_caller_part_1_streams.json"
    # info_file = "/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_5minNoise_2ip_av_wifi_ww_t1_caller_part_1.json"
    # # text_file = "/Users/sam/Downloads/noise_metrics2/Zoom/nc_2ip_av_wifi_ww/Zoom_nc_2ip_av_wifi_ww_t1.txt"
    # # pcap_file = "/Users/sam/Downloads/noise_metrics2/Zoom/nc_2ip_av_wifi_ww/Zoom_nc_2ip_av_wifi_ww_t1_caller.pcapng"
    # # stream_file = "/Users/sam/Downloads/noise_metrics2/Zoom/nc_2ip_av_wifi_ww/Zoom_nc_2ip_av_wifi_ww_t1_caller_part_1_streams.json"
    # # info_file = "/Users/sam/Downloads/noise_metrics2/Zoom/nc_2ip_av_wifi_ww/Zoom_nc_2ip_av_wifi_ww_t1_caller_part_1.json"

    # # all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters("./test_metrics")
    # all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters("/Users/sam/Downloads/noise_metrics3")

    # timestamp_dict, zone_offset = find_timestamps(text_file)
    # ts = list(timestamp_dict.keys())
    # start_time_dt = ts[0]
    # end_time_dt = ts[2]

    # info = read_from_json(info_file)
    # filter_code = info["Filter Code"]
    # rtc_streams = get_rtc_streams(filter_code)
    # if os.path.exists(stream_file):
    #     streams = read_from_json(stream_file)
    # else:
    #     start_time_str = start_time_dt.strftime("%Y-%m-%d %H:%M:%S.%f%z")
    #     end_time_str = end_time_dt.strftime("%Y-%m-%d %H:%M:%S.%f%z")
    #     print(f"Start time: {start_time_str} -> End time: {end_time_str}")
    #     time_code = get_time_filter_from_str(start_time_str, end_time_str, offset=10)
    #     print("Time code:", time_code)
    #     streams = extract_streams_from_pcap(pcap_file, filter_code=time_code)
    #     save_dict_to_json(streams, stream_file)
    # label_streams(rtc_streams, streams)
    # offset = 1

    # print("\nOriginal:")
    # # print_streams(streams)
    # original_streams = copy.deepcopy(streams)

    # # filtered1, _, _, _ = priorcall_filter(streams, start_time_dt, offset, five_tuple_filter=True, three_tuple_filter=True, local_ip_filter=True, domain_name_filter=True, heuristic_dn_filter=True)
    # # p, rtc_p = check_precision(streams, original_streams, show=True)
    # # print(f"\nFilter 1:")
    # # print_streams(streams)
    # # print(f"Filtered streams: \n{get_stream_filter(filtered1['TCP'], filtered1['UDP'])}")

    # # filtered2, _, _, _ = postcall_filter(streams, end_time_dt, offset, five_tuple_filter=True, three_tuple_filter=True, local_ip_filter=True, domain_name_filter=True, heuristic_dn_filter=True)
    # # p, rtc_p = check_precision(streams, original_streams, show=True)
    # # print(f"\nFilter 2:")
    # # print_streams(streams)
    # # print(f"Filtered streams: \n{get_stream_filter(filtered2['TCP'], filtered2['UDP'])}")

    # results = history_filter(streams, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names,
    #                         three_tuple_filter=True,
    #                         local_ip_filter=True,
    #                         domain_name_filter=True,
    #                         heuristic_dn_filter=True
    #                         )
    # filtered = results
    # p, rtc_p = check_precision(streams, original_streams, show=True)
    # print(f"\nHistory Filter:")
    # print_streams(streams)
    # # print(f"Filtered streams: \n{get_stream_filter(filtered['TCP'], filtered['UDP'])}")

    # exit()

    # pcap_file_A = "./test_msgr_a.pcapng"
    # pcap_file_B = "./test_msgr_b.pcapng"
    # json_file_A = "./test_msgr_a_streams.json"
    # json_file_B = "./test_msgr_b_streams.json"
    # if os.path.exists(json_file_A):
    #     streams_A = read_from_json(json_file_A)
    # else:
    #     streams_A = extract_streams_from_pcap(pcap_file_A)
    #     save_dict_to_json(streams_A, json_file_A)
    # if os.path.exists(json_file_B):
    #     streams_B = read_from_json(json_file_B)
    # else:
    #     streams_B = extract_streams_from_pcap(pcap_file_B)
    #     save_dict_to_json(streams_B, json_file_B)
    # compare_dual_streams(streams_A, streams_B)
    # exit()

    apps = [
        "Zoom",
        "FaceTime",
        "WhatsApp",
        "Messenger",
        "Discord",
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
        "2ip_av_cellular_cc": 1,
    }
    rounds = [
        "t1",
        "t2",
        "t3",
        "t4",
        "t5"
    ]
    client_types = [
        "caller",
        "callee",
    ]

    # save_main_folder = "./test_metrics"
    # save_main_folder = "/Users/sam/Downloads/noise_metrics"
    # save_main_folder = "/Users/sam/Downloads/noise_metrics2"
    # save_main_folder = "/Users/sam/Downloads/noise_metrics3"
    save_main_folder = "/Users/sam/Downloads/metrics"
    base_gap = 3
    all_filter_precision = []
    all_rtc_precision = []
    all_rtc_retention = []

    # all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters("./test_metrics")
    all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters(save_main_folder)

    for app_name in apps:
        for test_name in tests:
            for test_round in rounds:
                for client_type in client_types:
                    # streams_group = []
                    for i in range(1, tests[test_name] + 1):
                        text_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}.txt"
                        pcap_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
                        stream_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part_{i}_streams.json"
                        info_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part_{i}.json"

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
                        filter_code = info["Filter Code"]
                        rtc_streams = get_rtc_streams(filter_code)
                        if os.path.exists(stream_file):
                            streams = read_from_json(stream_file)
                        else:
                            start_time_str = start_time_dt.strftime("%Y-%m-%d %H:%M:%S.%f%z")
                            end_time_str = end_time_dt.strftime("%Y-%m-%d %H:%M:%S.%f%z")
                            time_code = get_time_filter_from_str(start_time_str, end_time_str, offset=10)
                            # print(f"Start time: {start_time_str} -> End time: {end_time_str}")
                            # print("Time code:", time_code)
                            streams = extract_streams_from_pcap(pcap_file, filter_code=time_code)
                            save_dict_to_json(streams, stream_file)
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
                        all_rtc_retention.append(rtc_rtn)

                    # if len(streams_group) > 1:
                    #     crosscall_filter(streams_group)
                    #     for i in range(len(streams_group)):
                    #         print(f"Crosscall filtering {save_subfolder.split('/')[-1]}_part_{i + 1}.json")
                    #         check_precision(streams_group[i], original_streams)

    print(f"Average filter precision: {np.mean(all_filter_precision)}")
    print(f"Median filter precision: {np.median(all_filter_precision)}")
    print(f"Average RTC precision: {np.mean(all_rtc_precision)}")
    print(f"Median RTC precision: {np.median(all_rtc_precision)}")
    print(f"Average RTC retention: {np.mean(all_rtc_retention)}")
    print(f"Median RTC retention: {np.median(all_rtc_retention)}")
    
    # save_filters("./test_metrics", all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)
    # save_filters("/Users/sam/Downloads/noise_metrics3", all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)
