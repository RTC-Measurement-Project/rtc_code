import pyshark
import matplotlib.pyplot as plt
from datetime import datetime
from IPy import IP
import numpy as np
import pandas as pd
import json
import os
from utils import find_timestamps, move_file_to_target


def save_packets_to_file(tcp_packets, udp_packets, filename):
    # Define a custom JSON encoder to handle datetime objects
    def datetime_converter(o):
        if isinstance(o, datetime):
            return o.__str__()

    # Convert datetime objects to strings
    def convert_packets(packets):
        converted = []
        for packet in packets:
            stream_id, timestamp, ip_src, ip_dst, src_port, dst_port, protocol = packet
            # Convert timestamp to string
            timestamp = timestamp.isoformat()
            converted.append(
                (stream_id, timestamp, ip_src, ip_dst, src_port, dst_port, protocol)
            )
        return converted

    tcp_packets = convert_packets(tcp_packets)
    udp_packets = convert_packets(udp_packets)
    data = {"tcp_packets": tcp_packets, "udp_packets": udp_packets}
    with open(filename, "w") as file:
        json.dump(data, file, default=datetime_converter)


def load_packets_from_file(filename):
    with open(filename, "r") as file:
        data = json.load(file)

    def convert_packets(packets):
        converted = []
        for packet in packets:
            stream_id, timestamp, ip_src, ip_dst, src_port, dst_port, protocol = packet
            # Convert timestamp string back to datetime
            timestamp = datetime.fromisoformat(timestamp)
            converted.append(
                (stream_id, timestamp, ip_src, ip_dst, src_port, dst_port, protocol)
            )
        return converted

    tcp_packets = convert_packets(data["tcp_packets"])
    udp_packets = convert_packets(data["udp_packets"])
    return tcp_packets, udp_packets


def process_pcap(pcap_file, zone_offset_tz=None, filter_code=""):
    # Open the pcap file using PyShark
    capture = pyshark.FileCapture(pcap_file, display_filter=filter_code)

    # Initialize lists to store packet information
    tcp_packets = []
    udp_packets = []

    # Iterate through the packets in the pcap file
    for packet in capture:
        ip_src = None
        ip_dst = None
        src_port = None
        dst_port = None
        protocol = None

        # Check for IPv4 or IPv6 and extract IP addresses
        if "IP" in packet:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
        elif "IPv6" in packet:
            ip_src = packet.ipv6.src
            ip_dst = packet.ipv6.dst

        # Extract ports and protocol for TCP and UDP
        if "TCP" in packet:
            stream_id = int(packet.tcp.stream)
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            protocol = packet.highest_layer  # Get the highest protocol layer
            timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp))
            timestamp = timestamp.replace(tzinfo=zone_offset_tz)
            tcp_packets.append(
                (stream_id, timestamp, ip_src, ip_dst, src_port, dst_port, protocol)
            )
        elif "UDP" in packet:
            stream_id = int(packet.udp.stream)
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            protocol = packet.highest_layer  # Get the highest protocol layer
            timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp))
            timestamp = timestamp.replace(tzinfo=zone_offset_tz)
            udp_packets.append(
                (stream_id, timestamp, ip_src, ip_dst, src_port, dst_port, protocol)
            )

    # Close the capture file
    capture.close()
    return tcp_packets, udp_packets


def get_streams(packets, exclude_protocols=[]):
    streams = {}
    for stream_id, timestamp, ip_src, ip_dst, src_port, dst_port, protocol in packets:
        # if protocol in exclude_protocols:
        #     # print(f"Excluding {protocol}")
        #     continue

        if stream_id in streams:
            streams[stream_id]["timestamps"].append(timestamp)
            if protocol not in streams[stream_id]["protocols"]:
                streams[stream_id]["protocols"].append(protocol)
        else:
            ip_src_IP = IP(ip_src)
            ip_dst_IP = IP(ip_dst)
            if (ip_src_IP.iptype() == "PUBLIC" and ip_dst_IP.iptype() == "PRIVATE") or (
                int(src_port) < int(dst_port)
            ):
                ip_src, ip_dst = ip_dst, ip_src
                src_port, dst_port = dst_port, src_port
            streams[stream_id] = {
                "timestamps": [timestamp],
                "ip_src": ip_src,
                "ip_dst": ip_dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocols": [protocol],
            }

    stream_ids_to_delete = []
    for stream_id in streams.keys():
        if any(
            protocol in exclude_protocols
            for protocol in streams[stream_id]["protocols"]
        ):
            stream_ids_to_delete.append(stream_id)
    for stream_id in stream_ids_to_delete:
        # print(f"Removing {stream_id} because it contains excluded protocols")
        del streams[stream_id]

    return streams


def get_sessions(packets, exclude_protocols=[]):
    sessions = {}

    for stream_id, timestamp, ip_src, ip_dst, src_port, dst_port, protocol in packets:
        # if protocol in exclude_protocols:
        #     # print(f"Excluding {protocol}")
        #     continue

        ip_pair = (ip_src, ip_dst)
        ip_pair_flipped = (ip_dst, ip_src)

        if ip_pair in sessions:
            sessions[ip_pair]["timestamps"].append(timestamp)
            if protocol not in sessions[ip_pair]["protocols"]:
                sessions[ip_pair]["protocols"].append(protocol)
            if stream_id not in sessions[ip_pair]["stream_ids"]:
                sessions[ip_pair]["stream_ids"].append(stream_id)
        elif ip_pair_flipped in sessions:
            sessions[ip_pair_flipped]["timestamps"].append(timestamp)
            if protocol not in sessions[ip_pair_flipped]["protocols"]:
                sessions[ip_pair_flipped]["protocols"].append(protocol)
            if stream_id not in sessions[ip_pair_flipped]["stream_ids"]:
                sessions[ip_pair_flipped]["stream_ids"].append(stream_id)
        else:
            sessions[ip_pair] = {
                "timestamps": [timestamp],
                "ip_src": ip_src,
                "ip_dst": ip_dst,
                "protocols": [protocol],
                "stream_ids": [stream_id],
            }

    ip_pair_to_delete = []
    for ip_pair in sessions.keys():
        if any(
            protocol in exclude_protocols for protocol in sessions[ip_pair]["protocols"]
        ):
            ip_pair_to_delete.append(ip_pair)
    for ip_pair in ip_pair_to_delete:
        # print(f"Removing {ip_pair} because it contains excluded protocols")
        del sessions[ip_pair]

    return sessions


def plot_streams(ax, all_streams_labelled):
    print(f"There are {len(all_streams_labelled)} streams")

    color_checks = {}

    for i, (label, timestamps, protocols, src_port, dst_port, stream_id, color, name) in enumerate(
        all_streams_labelled
    ):

        if "TCP" in label:
            label_txt = "TCP" + f" {name}"
        elif "UDP" in label:
            label_txt = "UDP" + f" {name}"
        else:
            label_txt = "Unknown" + f" {name}"

        if color not in color_checks:
            color_checks[color] = {}
        if label_txt not in color_checks[color]:
            color_checks[color][label_txt] = False

        ax.scatter(
            timestamps,
            [i] * len(timestamps),
            color=color,
            label=label_txt if not color_checks[color][label_txt] else "",
        )
        color_checks[color][label_txt] = True

        protocol_text = ", ".join(protocols) + "(" + str(stream_id) + ")"
        ax.text(timestamps[0], i, protocol_text, ha="left", va="center", color="green")
        ports = f"({src_port}<->{dst_port})"
        ax.text(1, i, ports, transform=ax.get_yaxis_transform(), ha="left", va="center")

    # Add labels and formatting
    ax.set_yticks(range(len(all_streams_labelled)))
    ax.set_yticklabels([f"{label}" for label, _, _, _, _, _, _, _ in all_streams_labelled])
    ax.set_xlabel("Time")
    ax.set_ylabel("Stream")
    ax.grid(True, which="both", linestyle="--")
    ax.legend()


def plot_sessions(ax, all_sessions_labelled):
    print(f"There are {len(all_sessions_labelled)} sessions")

    color_checks = {}

    for i, (label, timestamps, protocols, stream_ids, color, name) in enumerate(
        all_sessions_labelled
    ):        
        if "TCP" in label:
            label_txt = "TCP" + f" {name}"
        elif "UDP" in label:
            label_txt = "UDP" + f" {name}"
        else:
            label_txt = "Unknown" + f" {name}"

        if color not in color_checks:
            color_checks[color] = {}
        if label_txt not in color_checks[color]:
            color_checks[color][label_txt] = False

        ax.scatter(
            timestamps,
            [i] * len(timestamps),
            color=color,
            label=label_txt if not color_checks[color][label_txt] else "",
        )
        color_checks[color][label_txt] = True

        protocol_text = ", ".join(protocols)
        stream_text = (
            "(" + ", ".join([str(stream_id) for stream_id in stream_ids]) + ")"
        )
        all_text = f"{protocol_text} {stream_text}"
        ax.text(timestamps[1], i, all_text, ha="left", va="center", color="green")

    # Add labels and formatting
    ax.set_yticks(range(len(all_sessions_labelled)))
    ax.set_yticklabels([label for label, _, _, _, _, _ in all_sessions_labelled])
    ax.set_xlabel("Time")
    ax.set_ylabel("Session")
    ax.grid(True, which="both", linestyle="--")
    ax.legend()


def save_stream_table(file_name, test_name, tcp_streams, udp_streams):
    rows = []

    two_streams = [tcp_streams, udp_streams]
    for i in range(2):
        streams = two_streams[i]
        if len(streams) == 0:
            continue
        for stream in streams.values():
            timestamp_diff = np.diff(stream["timestamps"])
            row = {
                "Test Name": test_name,
                "Src IP": stream["ip_src"],
                "Src Port": stream["src_port"],
                "Dst IP": stream["ip_dst"],
                "Dst Port": stream["dst_port"],
                "TCP/UDP": "TCP" if i == 0 else "UDP",
                "Protocols": ", ".join(stream["protocols"]),
                "Num Packets": len(stream["timestamps"]),
                "Mean Inter-Pkt Time (s)": (
                    timestamp_diff.mean().total_seconds()
                    if len(timestamp_diff) > 0
                    else 0
                ),
                "Median Inter-Pkt Time (s)": (
                    np.median(timestamp_diff).total_seconds()
                    if len(timestamp_diff) > 0
                    else 0
                ),
                # 'Packet Freq': len(stream['timestamps']) / (stream['timestamps'][-1] - stream['timestamps'][0]).total_seconds(),
            }
            rows.append(row)

    df = pd.DataFrame(
        rows,
        columns=[
            "Test Name",
            "Src IP",
            "Src Port",
            "Dst IP",
            "Dst Port",
            "TCP/UDP",
            "Protocols",
            "Num Packets",
            "Mean Inter-Pkt Time (s)",
            "Median Inter-Pkt Time (s)",
        ],
    )

    try:
        existing_df = pd.read_csv(file_name)
        df = pd.concat([existing_df, df], ignore_index=True)
    except FileNotFoundError:
        pass

    # Save the DataFrame to the CSV file
    df.to_csv(file_name, index=False)


def one_pcap_flow(
    pcap_file, zone_offset_tz=None, filter_code="", use_json=False, get_session=False, peer=False, colors=["blue", "orange"], name=""
):
    json_file = pcap_file.replace(pcap_file.split(".")[1], ".json")
    if not os.path.exists(json_file) or not use_json:
        print(f"Processing {pcap_file}...")
        tcp_packets, udp_packets = process_pcap(pcap_file, filter_code=filter_code)
        save_packets_to_file(tcp_packets, udp_packets, json_file)
    else:
        print(f"Loading {json_file}...")
        tcp_packets, udp_packets = load_packets_from_file(json_file)

    all_flows_labelled = []
    if not get_session:
        tcp_streams = get_streams(tcp_packets)
        udp_streams = get_streams(udp_packets)
        # save_stream_table(
        #     "quic_streams.csv",
        #     pcap_file.split("/")[-1].split(".")[0],
        #     tcp_streams,
        #     udp_streams,
        # )
        all_flows_labelled = [
            (
                f'TCP: {stream["ip_src"]} <-> {stream["ip_dst"]}',
                stream["timestamps"],
                stream["protocols"],
                stream["src_port"],
                stream["dst_port"],
                stream_id,
                colors[0],
                name,
            )
            for stream_id, stream in tcp_streams.items()
        ]
        all_flows_labelled += [
            (
                f'UDP: {stream["ip_src"]} <-> {stream["ip_dst"]}',
                stream["timestamps"],
                stream["protocols"],
                stream["src_port"],
                stream["dst_port"],
                stream_id,
                colors[1],
                name,
            )
            for stream_id, stream in udp_streams.items()
        ]
    else:
        udp_sessions = get_sessions(udp_packets)
        tcp_sessions = get_sessions(tcp_packets)
        all_flows_labelled = [
            (
                f'TCP: {session["ip_src"]} <-> {session["ip_dst"]}',
                session["timestamps"],
                session["protocols"],
                session["stream_ids"],
                colors[0],
                name,
            )
            for session in tcp_sessions.values()
        ]
        all_flows_labelled += [
            (
                f'UDP: {session["ip_src"]} <-> {session["ip_dst"]}',
                session["timestamps"],
                session["protocols"],
                session["stream_ids"],
                colors[1],
                name,
            )
            for session in udp_sessions.values()
        ]

    return all_flows_labelled


def main(pcap_file, text_file=None, filter_code="", use_json=False, get_session=False, peer_pcap=None, peer_name="", host_name=""):
    timestamp_dict = {}
    zone_offset_tz = None
    if text_file:
        timestamp_dict, zone_offset_tz = find_timestamps(text_file)
        
    all_flows_labelled = one_pcap_flow(
        pcap_file,
        zone_offset_tz=zone_offset_tz,
        filter_code=filter_code,
        use_json=use_json,
        get_session=get_session,
        name=host_name,
    )
    
    if peer_pcap is not None:
        peer_flows_labelled = one_pcap_flow(
            peer_pcap,
            zone_offset_tz=zone_offset_tz,
            filter_code=filter_code,
            use_json=use_json,
            get_session=get_session,
            peer=True,
            name=peer_name,
            colors=["green", "red"],
        )
        all_flows_labelled += peer_flows_labelled

    fig, ax = plt.subplots()
    fig.suptitle(pcap_file)

    all_flows_labelled.sort(key=lambda x: x[1])
    if get_session:
        plot_sessions(ax, all_flows_labelled)
    else:
        plot_streams(ax, all_flows_labelled)

    if text_file:
        for time_point, action in timestamp_dict.items():
            print(time_point, action)
            time_point = time_point.astimezone(None).replace(tzinfo=None)
            ax.axvline(x=time_point, color="red", linestyle="--", linewidth=1)
            ax.text(
                time_point,
                0,
                f"{action}",
                color="red",
                verticalalignment="bottom",
                rotation="vertical",
            )

    plt.show()


if __name__ == "__main__":
    # if os.path.exists("quic_streams.csv"):
    #     os.remove("quic_streams.csv")
    
    pcap_file = "/Users/sam/Desktop/rtc_code/Apps/Discord/Discord_multicall_2mac_av_wifi_w_t1_caller.pcapng"
    # pcap_file = f"/Users/sam/Desktop/Research Files/code/metrics/Discord/multicall_2ip_av_wifi_w/Discord_multicall_2ip_av_wifi_w_t1_caller_part_1_QUIC.pcap"
    # pcap_file = f"./Apps/Messenger_oh_600s_av_t1_callee_RTCP.pcapng"
    # pcap_file = f"./Apps/google_QUIC.pcapng"
    # pcap_file = f"./Apps/http3_medium.pcapng"

    # app = "FaceTime"
    # name = "flip_"
    # test = "t1"
    # pcap_file = f"/Users/sam/Desktop/rtc_code/testbench/data/{app}/{app}_{name}2ip_av_wifi_ww_{test}_caller_QUIC.pcap"
    # peer_file = f"/Users/sam/Desktop/rtc_code/testbench/data/{app}/{app}_{name}2ip_av_wifi_ww_{test}_callee_QUIC.pcap"
    # host_name = "Caller"
    # peer_name = "Callee"

    # filter_code = "quic and (udp.srcport != 443 and udp.dstport != 443)"
    # filter_code = "quic and (ip.src == 162.159.0.0/16 or ip.dst == 162.159.0.0/16)"

    # pcap_file = f"./tests/http3_cnn_QUIC.pcapng"
    # pcap_file = f"./tests/http3_medium_QUIC.pcapng"
    # host_name = "Medium"

    text_file = pcap_file.split('_calle')[0] + '.txt'
    main(
        pcap_file,
        text_file=text_file,
        # filter_code=filter_code,
        # use_json=True,
        # peer_pcap=peer_file,
        # peer_name=peer_name,
        # host_name=host_name,
    )

    # apps = [
    #     # "Zoom",
    #     # "FaceTime",
    #     # "WhatsApp",
    #     # "Messenger",
    #     "Discord"
    # ]
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
    # parts = [3]
    # protocols = ["QUIC"]

    # lua_file = "facetime.lua"
    # target_folder_path = "/Users/sam/.local/lib/wireshark/plugins"
    # storage_folder_path = "/Users/sam/.local/lib/wireshark/disabled"
    # move_file_to_target(target_folder_path, lua_file, storage_folder_path)

    # for app_name in apps:
    #     for test_name in tests:
    #         for test_round in rounds:
    #             for client_type in client_types:
    #                 for part in parts:
    #                     for protocol in protocols:
    #                         pcap_file = f"./metrics/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part_{part}_{protocol}.pcap"
    #                         # filter_code = protocol.lower()  + " and udp.srcport != 443 and udp.dstport != 443"
    #                         filter_code = protocol.lower()
    #                         # text_file = pcap_file.split('_calle')[0] + '.txt'
    #                         if not os.path.exists(pcap_file):
    #                             print(f"File not found: {pcap_file}")
    #                             continue
    #                         main(
    #                             pcap_file,
    #                             filter_code=filter_code,
    #                             # text_file=text_file,
    #                         )
