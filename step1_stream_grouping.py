import os
import sys
import time
import pyshark
import multiprocessing
import argparse
from IPy import IP

from utils import get_asn_description, read_from_json, save_dict_to_json, get_time_filter_from_str, find_timestamps, get_ip_type, load_config, update_json_attribute

this_file_location = os.path.dirname(os.path.realpath(__file__))
p2p_isp_types = ["T-MOBILE", "ATT", "UUNET", "CHINAMOBILE", "COMCAST", "CELLCO-PART", "UMDNET"]  # for T-Mobile, AT&T, Verizon, China Mobile

asn_file = this_file_location + "/asn_description.json"
ip_asn = read_from_json(asn_file) if os.path.exists(asn_file) else {}

def extract_streams_from_pcap(pcap_file, filter_code="", noise=False, decode_as={}, save_file="", suppress_output=False):

    if suppress_output:
        sys.stdout = open(os.devnull, "w")

    print(f"Extracting streams from {pcap_file}")

    streams = {}
    cap = pyshark.FileCapture(pcap_file, keep_packets=False, display_filter=filter_code, decode_as=decode_as)
    for packet in cap:
        print(f"Processing packet {int(packet.number)}", end="\r")

        # if packet.number == "204": # for debug
        #     pass

        if hasattr(packet, "tcp") or hasattr(packet, "udp"):
            stream_type = "TCP" if hasattr(packet, "tcp") else "UDP"
            stream_id = int(packet.tcp.stream) if stream_type == "TCP" else int(packet.udp.stream)
            ip_layer = packet.ipv6 if hasattr(packet, "ipv6") else packet.ip
            src_ip, dst_ip = ip_layer.src, ip_layer.dst
            src_port = int(packet.tcp.srcport) if stream_type == "TCP" else int(packet.udp.srcport)
            dst_port = int(packet.tcp.dstport) if stream_type == "TCP" else int(packet.udp.dstport)
            ts = float(packet.sniff_timestamp)
            payload_size = int(packet.tcp.len) if stream_type == "TCP" else (int(packet.udp.length) - 8)
            packet_size = int(packet.length)
        else:
            print(f"Invalid packet {packet.number} (No TCP or UDP layer)")
            continue

        domain_name = ""
        if hasattr(packet, "TLS") and hasattr(packet.TLS, "handshake_extensions_server_name"):
            domain_name = packet.tls.handshake_extensions_server_name
        if hasattr(packet, "QUIC") and hasattr(packet.QUIC, "tls_handshake_extensions_server_name"):
            domain_name = packet.quic.tls_handshake_extensions_server_name

        if stream_type not in streams:
            streams[stream_type] = {}
        if stream_id not in streams[stream_type]:
            src_dot_count = max(src_ip.count("."), src_ip.count(":"))
            dst_dot_count = max(dst_ip.count("."), dst_ip.count(":"))
            for ip in [src_ip, dst_ip]:
                if ip not in ip_asn:
                    ip_asn[ip] = get_asn_description(ip)
                    if type(ip_asn[ip]) != str:
                        raise Exception(f"Error when getting ASN description for {ip}")
            ip_src_IP = IP(src_ip)
            ip_dst_IP = IP(dst_ip)
            p2p_option1 = ip_src_IP.iptype() == ip_dst_IP.iptype() == "PRIVATE"
            p2p_option2 = ip_asn[dst_ip] == ip_asn[src_ip] and any(isp_type in ip_asn[dst_ip] for isp_type in p2p_isp_types)
            p2p_option3 = ip_dst_IP.iptype() == "PRIVATE" and any(isp_type in ip_asn[src_ip] for isp_type in p2p_isp_types)
            p2p_option4 = any(isp_type in ip_asn[dst_ip] for isp_type in p2p_isp_types) and ip_src_IP.iptype() == "PRIVATE"
            p2p_option5 = ip_asn[dst_ip] in ["Unknown", "NA"] and any(isp_type in ip_asn[src_ip] for isp_type in p2p_isp_types)
            p2p_option6 = any(isp_type in ip_asn[dst_ip] for isp_type in p2p_isp_types) and ip_asn[src_ip] in ["Unknown", "NA"]
            # assume p2p is only over UDP
            is_p2p = (p2p_option1 or p2p_option2 or p2p_option3 or p2p_option4 or p2p_option5 or p2p_option6) and ("UDP" in packet and src_dot_count == dst_dot_count)
            streams[stream_type][stream_id] = {
                "is_p2p": is_p2p,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "src_asn": ip_asn.get(src_ip),
                "dst_asn": ip_asn.get(dst_ip),
                "timestamps": [],
                "payload_sizes": [],
                "packet_sizes": [],
                "domain_names": [],
                "packet_details": {},
            }
            if noise:
                streams[stream_type][stream_id]["label"] = False

        streams[stream_type][stream_id]["packet_details"][int(packet.number)] = {
            "timestamp": ts,
            "transport_protocol": stream_type,
            "stream_id": stream_id,
            "payload_size": payload_size,
            "packet_size": packet_size,
        }
        streams[stream_type][stream_id]["timestamps"].append(ts)
        streams[stream_type][stream_id]["payload_sizes"].append(payload_size)
        streams[stream_type][stream_id]["packet_sizes"].append(packet_size)
        if domain_name not in streams[stream_type][stream_id]["domain_names"] and domain_name != "":
            streams[stream_type][stream_id]["domain_names"].append(domain_name)

    print()
    cap.close()

    old_ip_asn = read_from_json(asn_file) if os.path.exists(asn_file) else {}
    combined_ip_asn = {**old_ip_asn, **ip_asn}
    save_dict_to_json(combined_ip_asn, asn_file)

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


def collect_background_info(streams, dest_ip_port_pairs, local_ip_pairs, background_domain_names):
    for stream_type, stream_dict in streams.items():
        for stream_id, info in stream_dict.items():
            if "label" in info and info["label"] is False:
                dest_ip_port_pairs[stream_type].add((info["dst_ip"], info["dst_port"]))
                if get_ip_type(info["src_ip"]) == get_ip_type(info["dst_ip"]):
                    local_ip_pairs[stream_type].add((info["src_ip"], info["dst_ip"]))
                background_domain_names.update(info["domain_names"])
    return dest_ip_port_pairs, local_ip_pairs, background_domain_names


def stream_grouping(pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, precall_noise_duration, postcall_noise_duration, multiprocess=False, no_skip=False):
    """
    Preprocess the pcap file and extract streams.
    """
    base_gap = 3

    for app_name in apps:

        pcap_files = []
        stream_files = []
        time_filters = []
        is_noise_flags = []
        save_names = []

        for test_name in tests:
            is_noise = "noise" in test_name

            for test_round in rounds:
                for client_type in client_types:
                    text_file = f"{pcap_main_folder}/{app_name}/{app_name}_{test_name}_{test_round}.txt"
                    pcap_file = f"{pcap_main_folder}/{app_name}/{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
                    if not os.path.exists(pcap_file):
                        continue

                    for i in range(1, tests[test_name] + 1):
                        stream_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}_streams.json"
                        if not os.path.exists(stream_file) or no_skip:
                            if not os.path.exists(f"{save_main_folder}/{app_name}/{test_name}/"):
                                os.makedirs(f"{save_main_folder}/{app_name}/{test_name}/")

                            time_code = ""
                            if not is_noise:
                                timestamp_dict, zone_offset = find_timestamps(text_file)
                                ts = list(timestamp_dict.keys())
                                gap = base_gap
                                if app_name == "Discord":
                                    gap = base_gap + 1
                                start = (i - 1) * gap
                                end = (i) * gap
                                start_time_str = ts[start].strftime("%Y-%m-%d %H:%M:%S.%f%z")
                                end_time_str = ts[end].strftime("%Y-%m-%d %H:%M:%S.%f%z")
                                time_code = get_time_filter_from_str(start_time_str, end_time_str, pre_offset=precall_noise_duration, post_offset=postcall_noise_duration)

                            pcap_files.append(pcap_file)
                            stream_files.append(stream_file)
                            time_filters.append(time_code)
                            is_noise_flags.append(is_noise)
                            save_names.append(f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}")

        processes = []
        process_start_times = []
        for pcap_file, stream_file, time_filter, is_noise in zip(pcap_files, stream_files, time_filters, is_noise_flags):
            if multiprocess:
                p = multiprocessing.Process(target=extract_streams_from_pcap, args=(pcap_file, time_filter, is_noise, {}, stream_file, True))
                process_start_times.append(time.time())
                processes.append(p)
                p.start()
            else:
                extract_streams_from_pcap(pcap_file, filter_code=time_filter, save_file=stream_file, suppress_output=False, noise=is_noise)

        if len(processes) == 0:
            print(f"Skip {app_name} tasks.")
            continue

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

    all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters(save_main_folder)

    for app_name in apps:
        for test_name in tests:
            if "noise" not in test_name:
                continue

            for test_round in rounds:
                for client_type in client_types:
                    pcap_file = f"{pcap_main_folder}/{app_name}/{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
                    if not os.path.exists(pcap_file):
                        continue

                    for i in range(1, tests[test_name] + 1):
                        stream_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}_streams.json"
                        if os.path.exists(stream_file):
                            streams = read_from_json(stream_file)
                            collect_background_info(streams, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)
                        else:
                            raise FileNotFoundError(f"Stream file not found: {stream_file}. Make sure the extraction was successful.")

    save_filters(save_main_folder, all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names)


if __name__ == "__main__":
    # python step1_stream_grouping.py --config config.json --multiprocess

    parser = argparse.ArgumentParser(description="Extract streams and prepare background info from pcap files.")
    parser.add_argument("--multiprocess", action="store_true", help="Use multiprocessing for extraction.")
    parser.add_argument("--config", type=str, default="config.json", help="Path to the configuration file.")
    parser.add_argument("--no-skip", action="store_true", help="Do not skip the extraction if the stream file already exists.")
    args = parser.parse_args()
    config_path = args.config
    multiprocess = args.multiprocess
    no_skip = args.no_skip
    pcap_main_folder, save_main_folder, apps, tests, rounds, clients, precall_noise, postcall_noise, plugin_enable_folder, plugin_disable_folder = load_config(config_path)
    stream_grouping(pcap_main_folder, save_main_folder, apps, tests, rounds, clients, precall_noise, postcall_noise, multiprocess=multiprocess, no_skip=no_skip)
