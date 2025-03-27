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
        print(f"Processing packet {packet.number}" + " "*10, end="\r")
        
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
    print()
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
    pcap_file, zone_offset_tz=None, filter_code="", use_json=False, get_session=False, peer=False, colors=["blue", "orange", "cyan", "yellow"], name="", marked_udp_stream_ids=[], marked_tcp_stream_ids=[]
):
    json_file = pcap_file.replace(pcap_file.split(".")[-1], "json")
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
        for stream_id, stream in tcp_streams.items():
            if stream_id in marked_tcp_stream_ids:
                color  = colors[2]
                name_ =  name + " (marked)"
            else:
                color = colors[0]
                name_ = name
            all_flows_labelled.append(
                (
                    f'TCP: {stream["ip_src"]} <-> {stream["ip_dst"]}',
                    stream["timestamps"],
                    stream["protocols"],
                    stream["src_port"],
                    stream["dst_port"],
                    stream_id,
                    color,
                    name_,
                )
            )
        for stream_id, stream in udp_streams.items():
            if stream_id in marked_udp_stream_ids:
                color  = colors[3]
                name_ =  name + " (marked)"
            else:
                color = colors[1]
                name_ = name
            all_flows_labelled.append(
                (
                    f'UDP: {stream["ip_src"]} <-> {stream["ip_dst"]}',
                    stream["timestamps"],
                    stream["protocols"],
                    stream["src_port"],
                    stream["dst_port"],
                    stream_id,
                    color,
                    name_,
                )
            )  
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


def main(pcap_file, text_file=None, filter_code="", use_json=False, get_session=False, peer_pcap=None, peer_name="", host_name="", marked_udp_stream_ids=[], marked_tcp_stream_ids=[]):
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
        marked_udp_stream_ids=marked_udp_stream_ids,
        marked_tcp_stream_ids=marked_tcp_stream_ids,
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
            print(time_point, action, all_flows_labelled[0][1][0])
            time_point = time_point.astimezone(None).replace(tzinfo=None)
            if all(time_point < all_flows_labelled[i][1][0] for i in range(len(all_flows_labelled))):
                continue
            if all(time_point > all_flows_labelled[i][1][-1] for i in range(len(all_flows_labelled))):
                continue
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
    filter_code = ""

    # lua_file = "facetime.lua"
    # app = "FaceTime"

    # lua_file  = "discord.lua"
    # app = "Discord"

    lua_file = "zoom.lua"
    app = "Zoom"

    # lua_file = "wasp.lua"
    # app = "WhatsApp"

    # lua_file = "wasp.lua"
    # app = "Messenger"

    target_folder_path = "/Users/sam/.local/lib/wireshark/plugins"
    storage_folder_path = "/Users/sam/.local/lib/wireshark/disabled"
    move_file_to_target(target_folder_path, lua_file, storage_folder_path)
    # pcap_file = f"./test_noise/raw/{app}/{app}_nc_2ip_av_wifi_ww_t1_caller.pcapng"
    # pcap_file = f"./test_noise/raw/{app}/{app}_nc_2ip_av_wifi_ww_t1_caller_filtered.pcapng"
    # pcap_file = f"./Apps/{app}/{app}_multicall_2ip_av_wifi_w_t1_caller.pcapng"
    # filter_code = '(frame.time >= "2024-08-30 17:00:59.998119-0700" and frame.time <= "2024-08-30 17:01:55.556649-0700")'
    # pcap_file = f"./Apps/{app}/{app}_multicall_2ip_av_wifi_wc_t1_caller.pcapng"
    # filter_code = '(frame.time >= "2024-08-30 17:05:18.288172-0700" and frame.time <= "2024-08-30 17:06:10.393367-0700")'
    # pcap_file = "./Apps/FaceTime/FaceTime_multicall_2mac_av_wifi_w_t1_caller.pcapng"
    # pcap_file = "/Users/sam/Desktop/rtc_code/Apps/Discord/Discord_multicall_2mac_av_wifi_w_t1_caller.pcapng"
    # pcap_file = f"/Users/sam/Desktop/Research Files/code/metrics/Discord/multicall_2ip_av_wifi_w/Discord_multicall_2ip_av_wifi_w_t1_caller_part_1_QUIC.pcap"
    # pcap_file = f"./Apps/Messenger_oh_600s_av_t1_callee_RTCP.pcapng"
    # pcap_file = f"./Apps/google_QUIC.pcapng"
    # pcap_file = f"./Apps/http3_medium.pcapng"
    # pcap_file = f"./test_msgr_a.pcapng"
    # filter_code = "udp and ((tcp.stream == 0 or tcp.stream == 1 or tcp.stream == 2 or tcp.stream == 3 or tcp.stream == 4 or tcp.stream == 5 or tcp.stream == 6 or tcp.stream == 7 or tcp.stream == 9 or tcp.stream == 11 or tcp.stream == 12 or tcp.stream == 13 or tcp.stream == 14) or (udp.stream == 0 or udp.stream == 1 or udp.stream == 2 or udp.stream == 7 or udp.stream == 8 or udp.stream == 9 or udp.stream == 12 or udp.stream == 13 or udp.stream == 14 or udp.stream == 15 or udp.stream == 21))"
    # pcap_file = f"./test_msgr_b.pcapng"
    # filter_code = "udp and ((tcp.stream == 0 or tcp.stream == 2 or tcp.stream == 3 or tcp.stream == 5 or tcp.stream == 6 or tcp.stream == 9 or tcp.stream == 10 or tcp.stream == 15 or tcp.stream == 16 or tcp.stream == 55) or (udp.stream == 0 or udp.stream == 1 or udp.stream == 2 or udp.stream == 3 or udp.stream == 4 or udp.stream == 5 or udp.stream == 35 or udp.stream == 10 or udp.stream == 11))"
    # pcap_file = f"/Users/sam/Desktop/rtc_code/test_metrics/Zoom/600s_2ip_av_wifi_w/Zoom_600s_2ip_av_wifi_w_t1_caller.pcapng"
    # marked_udp_stream_ids = [23, 24, 25, 26, 27, 28, 29, 30, 31, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97]
    # marked_tcp_stream_ids = [51, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 104, 105, 106, 107, 108, 109, 110, 111, 113]

    # pcap_file = f"/Users/sam/Desktop/rtc_code/test_metrics/Zoom/multicall_2ip_av_wifi_w/Zoom_multicall_2ip_av_wifi_w_t1_caller.pcapng"
    # marked_tcp_stream_ids = []
    # marked_udp_stream_ids = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
    # filter_code = '(frame.time >= "2025-01-07 20:04:00.378784-0500" and frame.time <= "2025-01-07 20:05:30.489823-0500")'
    # filter_code = '(frame.time >= "2025-01-07 20:04:08.378784-0500" and frame.time <= "2025-01-07 20:05:23.489823-0500") and ((tcp.stream == 64 or tcp.stream == 65 or tcp.stream == 66 or tcp.stream == 67 or tcp.stream == 68 or tcp.stream == 70 or tcp.stream == 71 or tcp.stream == 72 or tcp.stream == 73 or tcp.stream == 74 or tcp.stream == 75 or tcp.stream == 58 or tcp.stream == 59 or tcp.stream == 60 or tcp.stream == 61 or tcp.stream == 62 or tcp.stream == 63) or (udp.stream == 32 or udp.stream == 33 or udp.stream == 18 or udp.stream == 19 or udp.stream == 20 or udp.stream == 21 or udp.stream == 22 or udp.stream == 23 or udp.stream == 24 or udp.stream == 25 or udp.stream == 26 or udp.stream == 28 or udp.stream == 29 or udp.stream == 30 or udp.stream == 31))'
    # filter_code = '(frame.time >= "2025-01-07 20:06:12.331739-0500" and frame.time <= "2025-01-07 20:08:03.886618-0500") and !(((tcp.stream == 4 or tcp.stream == 93 or tcp.stream == 7 or tcp.stream == 87 or tcp.stream == 42 or tcp.stream == 2 or tcp.stream == 43 or tcp.stream == 1 or tcp.stream == 90 or tcp.stream == 3 or tcp.stream == 103 or tcp.stream == 0 or tcp.stream == 10 or tcp.stream == 69 or tcp.stream == 56 or tcp.stream == 76 or tcp.stream == 6 or tcp.stream == 5) or (udp.stream == 52 or udp.stream == 7 or udp.stream == 6)) or ((tcp.stream == 67 or tcp.stream == 104 or tcp.stream == 30) or (udp.stream == 65 or udp.stream == 66 or udp.stream == 50)))'
    # filter_code = '(frame.time >= "2025-01-07 20:06:12.331739-0500" and frame.time <= "2025-01-07 20:08:03.886618-0500")'

    # pcap_file = "/Users/sam/Desktop/rtc_code/testbench/data/Zoom/Zoom_5minNoise_2ip_av_wifi_ww_t1_caller.pcapng"
    # marked_tcp_stream_ids = [282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 338, 339, 340, 341, 342, 345]
    # marked_udp_stream_ids = [128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 90, 91, 102, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127]
    # filter_code = '(frame.time >= "2025-02-28 19:05:40.526046-0500" and frame.time <= "2025-02-28 19:11:15.460183-0500")'
    # filter_code = "((tcp.stream == 282 or tcp.stream == 283 or tcp.stream == 284 or tcp.stream == 285 or tcp.stream == 286 or tcp.stream == 287 or tcp.stream == 288 or tcp.stream == 289 or tcp.stream == 290 or tcp.stream == 291 or tcp.stream == 292 or tcp.stream == 293 or tcp.stream == 294 or tcp.stream == 295 or tcp.stream == 296 or tcp.stream == 297 or tcp.stream == 298 or tcp.stream == 299 or tcp.stream == 300 or tcp.stream == 301 or tcp.stream == 302 or tcp.stream == 303 or tcp.stream == 304 or tcp.stream == 306 or tcp.stream == 307 or tcp.stream == 308 or tcp.stream == 309 or tcp.stream == 310 or tcp.stream == 311 or tcp.stream == 312 or tcp.stream == 313 or tcp.stream == 314 or tcp.stream == 315 or tcp.stream == 316 or tcp.stream == 317 or tcp.stream == 318 or tcp.stream == 319 or tcp.stream == 320 or tcp.stream == 321 or tcp.stream == 322 or tcp.stream == 323 or tcp.stream == 324 or tcp.stream == 326 or tcp.stream == 327 or tcp.stream == 328 or tcp.stream == 329 or tcp.stream == 330 or tcp.stream == 331 or tcp.stream == 332 or tcp.stream == 333 or tcp.stream == 334 or tcp.stream == 335 or tcp.stream == 336 or tcp.stream == 338 or tcp.stream == 339 or tcp.stream == 340 or tcp.stream == 341 or tcp.stream == 342 or tcp.stream == 345) or (udp.stream == 128 or udp.stream == 129 or udp.stream == 130 or udp.stream == 131 or udp.stream == 132 or udp.stream == 133 or udp.stream == 134 or udp.stream == 135 or udp.stream == 136 or udp.stream == 137 or udp.stream == 138 or udp.stream == 139 or udp.stream == 140 or udp.stream == 141 or udp.stream == 142 or udp.stream == 143 or udp.stream == 144 or udp.stream == 145 or udp.stream == 146 or udp.stream == 147 or udp.stream == 148 or udp.stream == 149 or udp.stream == 150 or udp.stream == 151 or udp.stream == 90 or udp.stream == 91 or udp.stream == 102 or udp.stream == 105 or udp.stream == 106 or udp.stream == 107 or udp.stream == 108 or udp.stream == 109 or udp.stream == 110 or udp.stream == 111 or udp.stream == 112 or udp.stream == 113 or udp.stream == 114 or udp.stream == 115 or udp.stream == 116 or udp.stream == 117 or udp.stream == 118 or udp.stream == 119 or udp.stream == 120 or udp.stream == 121 or udp.stream == 122 or udp.stream == 123 or udp.stream == 124 or udp.stream == 125 or udp.stream == 126 or udp.stream == 127))"
    # filter_code = "((tcp.stream == 282 or tcp.stream == 283 or tcp.stream == 284 or tcp.stream == 285 or tcp.stream == 286 or tcp.stream == 287 or tcp.stream == 288 or tcp.stream == 289 or tcp.stream == 290 or tcp.stream == 291 or tcp.stream == 292 or tcp.stream == 293 or tcp.stream == 295 or tcp.stream == 296 or tcp.stream == 297 or tcp.stream == 298 or tcp.stream == 299 or tcp.stream == 300 or tcp.stream == 301 or tcp.stream == 302 or tcp.stream == 303 or tcp.stream == 304 or tcp.stream == 307 or tcp.stream == 308 or tcp.stream == 309 or tcp.stream == 310 or tcp.stream == 311 or tcp.stream == 312 or tcp.stream == 313 or tcp.stream == 314 or tcp.stream == 315 or tcp.stream == 316 or tcp.stream == 317 or tcp.stream == 318 or tcp.stream == 319 or tcp.stream == 320 or tcp.stream == 321 or tcp.stream == 322 or tcp.stream == 323 or tcp.stream == 324 or tcp.stream == 326 or tcp.stream == 327 or tcp.stream == 328 or tcp.stream == 330 or tcp.stream == 331 or tcp.stream == 332 or tcp.stream == 333 or tcp.stream == 334 or tcp.stream == 335 or tcp.stream == 337 or tcp.stream == 338 or tcp.stream == 339 or tcp.stream == 340 or tcp.stream == 341 or tcp.stream == 342 or tcp.stream == 345) or (udp.stream == 128 or udp.stream == 129 or udp.stream == 131 or udp.stream == 132 or udp.stream == 133 or udp.stream == 134 or udp.stream == 135 or udp.stream == 136 or udp.stream == 137 or udp.stream == 138 or udp.stream == 139 or udp.stream == 140 or udp.stream == 142 or udp.stream == 143 or udp.stream == 144 or udp.stream == 145 or udp.stream == 146 or udp.stream == 147 or udp.stream == 148 or udp.stream == 149 or udp.stream == 150 or udp.stream == 151 or udp.stream == 90 or udp.stream == 102 or udp.stream == 105 or udp.stream == 108 or udp.stream == 109 or udp.stream == 110 or udp.stream == 111 or udp.stream == 112 or udp.stream == 114 or udp.stream == 115 or udp.stream == 116 or udp.stream == 117 or udp.stream == 119 or udp.stream == 120 or udp.stream == 121 or udp.stream == 122 or udp.stream == 123 or udp.stream == 124 or udp.stream == 126 or udp.stream == 127))"
    # filter_code = "((tcp.stream == 284 or tcp.stream == 285 or tcp.stream == 286 or tcp.stream == 287 or tcp.stream == 288 or tcp.stream == 289 or tcp.stream == 299 or tcp.stream == 300 or tcp.stream == 308 or tcp.stream == 309 or tcp.stream == 315 or tcp.stream == 321 or tcp.stream == 322 or tcp.stream == 323 or tcp.stream == 324 or tcp.stream == 326 or tcp.stream == 327 or tcp.stream == 341 or tcp.stream == 342) or (udp.stream == 137 or udp.stream == 134 or udp.stream == 135))"
    # filter_code = "((tcp.stream == 288 or tcp.stream == 289 or tcp.stream == 321 or tcp.stream == 322 or tcp.stream == 323 or tcp.stream == 324 or tcp.stream == 326 or tcp.stream == 327 or tcp.stream == 341 or tcp.stream == 342 or tcp.stream == 284 or tcp.stream == 285 or tcp.stream == 286 or tcp.stream == 287) or (udp.stream == 137))"
    # filter_code = "((tcp.stream == 4 or tcp.stream == 6 or tcp.stream == 9 or tcp.stream == 10 or tcp.stream == 11 or tcp.stream == 12 or tcp.stream == 13 or tcp.stream == 14 or tcp.stream == 15 or tcp.stream == 16 or tcp.stream == 17 or tcp.stream == 18 or tcp.stream == 20 or tcp.stream == 21 or tcp.stream == 22 or tcp.stream == 23 or tcp.stream == 24 or tcp.stream == 25 or tcp.stream == 26 or tcp.stream == 27 or tcp.stream == 28 or tcp.stream == 29 or tcp.stream == 30 or tcp.stream == 31 or tcp.stream == 32 or tcp.stream == 34 or tcp.stream == 38 or tcp.stream == 39 or tcp.stream == 40 or tcp.stream == 41 or tcp.stream == 65 or tcp.stream == 66 or tcp.stream == 67 or tcp.stream == 71 or tcp.stream == 72 or tcp.stream == 73 or tcp.stream == 74 or tcp.stream == 75 or tcp.stream == 76 or tcp.stream == 78 or tcp.stream == 81 or tcp.stream == 82 or tcp.stream == 83 or tcp.stream == 84 or tcp.stream == 85 or tcp.stream == 86 or tcp.stream == 87 or tcp.stream == 88 or tcp.stream == 89 or tcp.stream == 90 or tcp.stream == 91 or tcp.stream == 92 or tcp.stream == 93 or tcp.stream == 94 or tcp.stream == 95 or tcp.stream == 96 or tcp.stream == 97 or tcp.stream == 98 or tcp.stream == 99 or tcp.stream == 100 or tcp.stream == 101 or tcp.stream == 102 or tcp.stream == 103 or tcp.stream == 104 or tcp.stream == 105 or tcp.stream == 106 or tcp.stream == 107 or tcp.stream == 108 or tcp.stream == 109 or tcp.stream == 110 or tcp.stream == 113 or tcp.stream == 114 or tcp.stream == 115 or tcp.stream == 116 or tcp.stream == 117 or tcp.stream == 118 or tcp.stream == 119 or tcp.stream == 120 or tcp.stream == 121 or tcp.stream == 122 or tcp.stream == 123 or tcp.stream == 124 or tcp.stream == 125 or tcp.stream == 126 or tcp.stream == 127 or tcp.stream == 128 or tcp.stream == 129 or tcp.stream == 130 or tcp.stream == 131 or tcp.stream == 132 or tcp.stream == 133 or tcp.stream == 134 or tcp.stream == 135 or tcp.stream == 136 or tcp.stream == 137 or tcp.stream == 138 or tcp.stream == 139 or tcp.stream == 140 or tcp.stream == 141 or tcp.stream == 142 or tcp.stream == 143 or tcp.stream == 144 or tcp.stream == 145 or tcp.stream == 146 or tcp.stream == 147 or tcp.stream == 148 or tcp.stream == 149 or tcp.stream == 150 or tcp.stream == 151 or tcp.stream == 152 or tcp.stream == 153 or tcp.stream == 154 or tcp.stream == 155 or tcp.stream == 156 or tcp.stream == 157 or tcp.stream == 158 or tcp.stream == 159 or tcp.stream == 160 or tcp.stream == 161 or tcp.stream == 162 or tcp.stream == 163 or tcp.stream == 166 or tcp.stream == 167 or tcp.stream == 168 or tcp.stream == 185 or tcp.stream == 189 or tcp.stream == 197 or tcp.stream == 199 or tcp.stream == 205 or tcp.stream == 206 or tcp.stream == 207 or tcp.stream == 208 or tcp.stream == 216 or tcp.stream == 218 or tcp.stream == 220 or tcp.stream == 234 or tcp.stream == 235 or tcp.stream == 246 or tcp.stream == 249 or tcp.stream == 271 or tcp.stream == 273 or tcp.stream == 274 or tcp.stream == 275 or tcp.stream == 280 or tcp.stream == 283 or tcp.stream == 284 or tcp.stream == 285 or tcp.stream == 286 or tcp.stream == 287 or tcp.stream == 288 or tcp.stream == 289 or tcp.stream == 290 or tcp.stream == 294 or tcp.stream == 297 or tcp.stream == 301 or tcp.stream == 313 or tcp.stream == 316 or tcp.stream == 320 or tcp.stream == 321 or tcp.stream == 322 or tcp.stream == 323 or tcp.stream == 324 or tcp.stream == 325 or tcp.stream == 326 or tcp.stream == 327 or tcp.stream == 330 or tcp.stream == 340 or tcp.stream == 341 or tcp.stream == 342 or tcp.stream == 345 or tcp.stream == 349 or tcp.stream == 350 or tcp.stream == 351 or tcp.stream == 357 or tcp.stream == 358 or tcp.stream == 363 or tcp.stream == 364) or (udp.stream == 0 or udp.stream == 1 or udp.stream == 128 or udp.stream == 129 or udp.stream == 131 or udp.stream == 132 or udp.stream == 133 or udp.stream == 136 or udp.stream == 137 or udp.stream == 10 or udp.stream == 11 or udp.stream == 12 or udp.stream == 138 or udp.stream == 14 or udp.stream == 139 or udp.stream == 140 or udp.stream == 142 or udp.stream == 143 or udp.stream == 144 or udp.stream == 145 or udp.stream == 146 or udp.stream == 22 or udp.stream == 147 or udp.stream == 148 or udp.stream == 149 or udp.stream == 150 or udp.stream == 151 or udp.stream == 152 or udp.stream == 34 or udp.stream == 55 or udp.stream == 57 or udp.stream == 77 or udp.stream == 79 or udp.stream == 80 or udp.stream == 81 or udp.stream == 86 or udp.stream == 102 or udp.stream == 105 or udp.stream == 112 or udp.stream == 114 or udp.stream == 115 or udp.stream == 116 or udp.stream == 117 or udp.stream == 119 or udp.stream == 120 or udp.stream == 121 or udp.stream == 122 or udp.stream == 126 or udp.stream == 127))"

    # pcap_file = "/Users/sam/Downloads/noise_metrics3/Zoom/151call_2ip_av_wifi_ww/Zoom_151call_2ip_av_wifi_ww_t1_caller_part_1_noise.pcapng"

    pcap_file = "/Users/sam/Downloads/metrics/Zoom/2ip_av_cellular_cc/Zoom_2ip_av_cellular_cc_t1_caller.pcapng"
    filter_code = "((tcp.stream == 5 or tcp.stream == 39 or tcp.stream == 40 or tcp.stream == 41 or tcp.stream == 42 or tcp.stream == 43 or tcp.stream == 44) or (udp.stream == 40 or udp.stream == 19))"
    # marked_tcp_stream_ids = []
    # marked_udp_stream_ids = [20, 21, 22, 23, 24, 25, 26, 27, 28, 29]
    
    # app = "FaceTime"
    # name = "flip_"
    # test = "t1"
    # pcap_file = f"/Users/sam/Desktop/rtc_code/testbench/data/{app}/{app}_{name}2ip_av_wifi_ww_{test}_caller_QUIC.pcap"
    # peer_file = f"/Users/sam/Desktop/rtc_code/testbench/data/{app}/{app}_{name}2ip_av_wifi_ww_{test}_callee_QUIC.pcap"

    # filter_code = "quic and (udp.srcport != 443 and udp.dstport != 443)"
    # filter_code = "quic and (ip.src == 162.159.0.0/16 or ip.dst == 162.159.0.0/16)"

    # pcap_file = f"./tests/http3_cnn_QUIC.pcapng"
    # pcap_file = f"./tests/http3_medium_QUIC.pcapng"
    # host_name = "Medium"

    text_file = pcap_file.split('_calle')[0] + '.txt'
    # host_name = "Caller"
    # peer_name = "Callee"
    main(
        pcap_file,
        text_file=text_file,
        filter_code=filter_code,
        # use_json=True,
        # peer_pcap=peer_file,
        # peer_name=peer_name,
        # host_name=host_name,
        # marked_tcp_stream_ids=marked_tcp_stream_ids,
        # marked_udp_stream_ids=marked_udp_stream_ids,
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
