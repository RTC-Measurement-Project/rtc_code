import pyshark
from datetime import datetime, timedelta
from IPy import IP
from utils import move_file_to_target


def discard_ip(ip_addr, print_debug=False):
    ip = IP(ip_addr)
    if print_debug: print(f"IP type: {ip.iptype()}, IP: {ip}")
    # we want to preserve the following IP types:
    check = not (ip.iptype() in ("PRIVATE", "CARRIER_GRADE_NAT", "ALLOCATED ARIN", "ALLOCATED RIPE NCC"))
    return check


def extract_filter_para(input_file, duration_seconds=10, end_time=None):
    # Open the input pcapng file
    cap = pyshark.FileCapture(input_file)
    if end_time is not None:
        end_time = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S.%f")

    # Get the timestamp of the first packet
    start_time = None
    discard_ips = set()
    tcp_stream_ids = set()
    udp_stream_ids = set()

    for packet in cap:
        packet_time = packet.sniff_time

        if start_time is None:
            start_time = packet_time
            # print(f"Start time: {start_time}")

        if end_time is None:
            if (packet_time - start_time).total_seconds() > duration_seconds:
                break
        else:
            if packet_time > end_time:
                break

        # Check if the packet has a stream ID
        if 'tcp' in packet:
            if hasattr(packet.tcp, 'stream'):
                tcp_stream_ids.add(packet.tcp.stream)
        elif 'udp' in packet:
            if hasattr(packet.udp, 'stream'):
                udp_stream_ids.add(packet.udp.stream)

        # Check if the packet has IP or IPv6 layer
        if 'ip' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            # print(f"IPv4 packet found: {src_ip} -> {dst_ip}")
            if discard_ip(src_ip):
                discard_ips.add(src_ip)
                # print(f"Public IPv4 found: {src_ip} (source)")
            if discard_ip(dst_ip):
                discard_ips.add(dst_ip)
            # print(f"Public IPv4 found: {dst_ip} (destination)")
        elif 'ipv6' in packet:
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
            # print(f"IPv6 packet found: {packet.ipv6.src} -> {packet.ipv6.dst}")
            if discard_ip(src_ip):
                discard_ips.add(src_ip)
                # print(f"Public IPv6 found: {src_ip} (source)")
            if discard_ip(dst_ip):
                discard_ips.add(dst_ip)
            # print(f"Public IPv6 found: {dst_ip} (destination)")

    cap.close()

    return discard_ips, tcp_stream_ids, udp_stream_ids


def generate_filter_code(discard_ips, tcp_stream_ids, udp_stream_ids):
    # Generate a filter code string for Wireshark
    filters = []
    
    # # IPv4 source filter
    # filters += [f'ip.src == {ip}' for ip in discard_ips if ':' not in ip]
    # # IPv4 destination filter
    # filters += [f'ip.dst == {ip}' for ip in discard_ips if ':' not in ip]
    # # IPv6 source filter
    # filters += [f'ipv6.src == {ip}' for ip in discard_ips if ':' in ip]
    # # IPv6 destination filter
    # filters += [f'ipv6.dst == {ip}' for ip in discard_ips if ':' in ip]
    
    filters += [f'tcp.stream eq {stream_id}' for stream_id in tcp_stream_ids]
    filters += [f'udp.stream eq {stream_id}' for stream_id in udp_stream_ids]
    
    filter_code = ' or '.join(filters)

    return "!(" + filter_code + ")"


def save_as_new_pcap(input_file, output_file, filter_code):
    print(f"Saving filtered packets to {output_file}")
    cap = pyshark.FileCapture(
        input_file, display_filter=filter_code, output_file=output_file)
    cap.load_packets()
    cap.close()
    print(f"Filtered packets saved to {output_file}")
    return


def main(input_file, duration_seconds=10, end_time=None, extra_filter="", save_filtered=False):
    output_file = input_file.replace(".pcapng", "_filtered.pcapng")

    # Extract public IPs from the first 10 seconds of packets
    discard_ips, tcp_stream_ids, udp_stream_ids = extract_filter_para(
        input_file, duration_seconds, end_time)

    # Generate filter code
    filter_code = generate_filter_code(
        discard_ips, tcp_stream_ids, udp_stream_ids)
    filter_code += " and " + extra_filter
    print(filter_code)

    # Save the filtered packets to a new pcapng file
    if save_filtered:
        save_as_new_pcap(input_file, output_file, filter_code)

    return filter_code


if __name__ == "__main__":
    import os

    lua_file = "facetime.lua"
    app = "FaceTime"

    lua_file = "discord.lua"
    app = "Discord"

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
    pcap_file = f"./testbench/data/Zoom/Zoom_2ip_av_wifi_ww_tNone_callee.pcapng"

    code = main(
        pcap_file,
        duration_seconds=30,
        # save_filtered=True,
        extra_filter="!(mdns or dns or ssdp or icmp or icmpv6 or dhcpv6 or dhcp)",
    )
    # print(code)

    # app_names = ["WhatsApp", "Zoom", "Messenger", "FaceTime", "Discord"]
    # test_names = ["2mac", "ipmac"]
    # medias = ["av", "a"]
    # test_rounds = ["t1", "t2", "t3", "t4", "t5"]
    # clients = ["caller", "callee"]
    # for app_name in app_names:
    #     for test_name in test_names:
    #         for media in medias:
    #             for test_round in test_rounds:
    #                 for client in clients:
    #                     input_file = f"{app_name}_{test_name}_{media}_{test_round}_{client}.pcapng"
    #                     if os.path.exists(input_file):
    #                         code = main(input_file)
    #                         print(input_file + ": " + code)
