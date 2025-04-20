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
import argparse

from utils import read_from_json, get_stream_filter, find_timestamps, get_ip_type, load_config, update_json_attribute
from step1_stream_grouping import load_filters

bg_domains = ["google", "apple", "icloud"]
bg_ports = [80, 53, 5353]


def time_based_filter(
    streams, time_dt, filter_type, offset=0, five_tuple_filter=False, three_tuple_filter=False, local_ip_filter=False, domain_name_filter=False, heuristic_dn_filter=False, heuristic_port_filter=False
):
    """
    Filters streams based on their start or end time relative to a given timestamp.

    Args:
        streams: Dictionary of streams.
        time_dt: The datetime object to compare against.
        filter_type: 'precall' to filter streams starting before time_dt, 'postcall' to filter streams ending after time_dt.
        offset: Time offset in seconds to adjust time_dt.
        five_tuple_filter: Flag to filter based on 5-tuple.
        three_tuple_filter: Flag to filter based on 3-tuple.
        local_ip_filter: Flag to filter based on local IP pairs.
        domain_name_filter: Flag to filter based on domain names.
        heuristic_dn_filter: Flag to filter based on heuristic domain names.
        heuristic_port_filter: Flag to filter based on heuristic ports.

    Returns:
        Tuple containing filtered stream sets, destination IP/port pairs, local IP pairs, and background domain names.
    """
    if filter_type == "precall":
        time_dt -= datetime.timedelta(seconds=offset)
        time_ts = time_dt.timestamp()
        time_index = 0  # Compare first timestamp
        comparison = lambda t, threshold: t < threshold
    elif filter_type == "postcall":
        time_dt += datetime.timedelta(seconds=offset)
        time_ts = time_dt.timestamp()
        time_index = -1  # Compare last timestamp
        comparison = lambda t, threshold: t > threshold
    else:
        raise ValueError("filter_type must be 'precall' or 'postcall'")

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

    # Identify streams active before 'precall' time or after 'postcall' time
    for stream_type, stream_dict in streams.items():
        for stream_id, stream_info in stream_dict.items():
            timestamps = stream_info["timestamps"]
            if comparison(timestamps[time_index], time_ts):
                if domain_name_filter:
                    background_domain_names.update(stream_info["domain_names"])
                dest_ip_port_pairs[stream_type].add((stream_info["dst_ip"], stream_info["dst_port"]))
                if get_ip_type(stream_info["src_ip"]) == get_ip_type(stream_info["dst_ip"]):
                    local_ip_pairs[stream_type].add((stream_info["src_ip"], stream_info["dst_ip"]))
                if five_tuple_filter:
                    to_be_filtered.append([stream_type, stream_id])

    # Apply subsequent filters based on the identified background activity
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
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if any(domain_name in background_domain_names for domain_name in stream_info["domain_names"]) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if heuristic_dn_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                for domain_name in stream_info["domain_names"]:
                    if any(domain in domain_name for domain in bg_domains) and [stream_type, stream_id] not in to_be_filtered:
                        to_be_filtered.append([stream_type, stream_id])
                        break
    if heuristic_port_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if (stream_info["src_port"] in bg_ports or stream_info["dst_port"] in bg_ports) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])

    # Remove the filtered streams
    filtered_streams = {
        "TCP": set(),
        "UDP": set(),
    }
    for stream_type, stream_id in to_be_filtered:
        filtered_streams[stream_type].add(stream_id)
        if stream_id in streams[stream_type]:  # Check if not already deleted by another filter
            del streams[stream_type][stream_id]
    return filtered_streams, dest_ip_port_pairs, local_ip_pairs, background_domain_names


def collection_based_filter(
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
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if any(domain_name in all_background_domain_names for domain_name in stream_info["domain_names"]) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    if heuristic_dn_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                for domain_name in stream_info["domain_names"]:
                    if any(domain in domain_name for domain in bg_domains) and [stream_type, stream_id] not in to_be_filtered:
                        to_be_filtered.append([stream_type, stream_id])
                        break
    if heuristic_port_filter:
        for stream_type, stream_dict in streams.items():
            for stream_id, stream_info in stream_dict.items():
                if (stream_info["src_port"] in bg_ports or stream_info["dst_port"] in bg_ports) and [stream_type, stream_id] not in to_be_filtered:
                    to_be_filtered.append([stream_type, stream_id])
    filtered_streams = {
        "TCP": set(),
        "UDP": set(),
    }
    for stream_type, stream_id in to_be_filtered:
        filtered_streams[stream_type].add(stream_id)
        del streams[stream_type][stream_id]
    return filtered_streams


def process_single_file(
    stream_file,
    pcap_info_file,
    start_time_dt,
    end_time_dt,
    offset,
    all_dest_ip_port_pairs,
    all_local_ip_pairs,
    all_background_domain_names,
    suppress_output=False,
):
    """Processes a single stream file for background filtering."""
    if suppress_output:
        original_stdout = sys.stdout
        sys.stdout = open(os.devnull, "w")
    
    print(f"Processing {stream_file}...")

    streams = read_from_json(stream_file)

    # Apply precall filter
    results_precall = time_based_filter(
        streams,
        start_time_dt,
        "precall",
        offset,
        five_tuple_filter=True,
        three_tuple_filter=True,
        local_ip_filter=True,
        domain_name_filter=True,
        heuristic_dn_filter=True,
        heuristic_port_filter=True,
    )

    # Apply postcall filter
    results_postcall = time_based_filter(
        streams,
        end_time_dt,
        "postcall",
        offset,
        five_tuple_filter=True,
        three_tuple_filter=True,
        local_ip_filter=True,
        domain_name_filter=True,
        heuristic_dn_filter=True,
        heuristic_port_filter=True,
    )

    # Apply history filter to the remaining streams
    results_collection = collection_based_filter(
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

    filter_code = get_stream_filter(streams["TCP"], streams["UDP"])
    update_json_attribute(pcap_info_file, "Filter Code", filter_code)

    if suppress_output:
        sys.stdout.close()
        sys.stdout = original_stdout


def background_filtering(pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, multiprocess=False):
    """
    Filter pcap files and save the results.
    """
    base_gap = 3
    offset = 10

    all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters(save_main_folder)

    for app_name in apps:

        tasks = []
        task_names = []

        for test_name in tests:
            if "noise" in test_name:
                continue
            for test_round in rounds:
                for client_type in client_types:
                    for i in range(1, tests[test_name] + 1):
                        text_file = f"{pcap_main_folder}/{app_name}/{app_name}_{test_name}_{test_round}.txt"
                        stream_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}_streams.json"
                        pcap_info_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}.json"

                        if os.path.exists(stream_file) and os.path.exists(text_file):
                            gap = base_gap
                            if app_name == "Discord":
                                gap = base_gap + 1
                            timestamp_dict, zone_offset = find_timestamps(text_file)
                            ts = list(timestamp_dict.keys())
                            start = (i - 1) * gap
                            end = i * gap
                            start_time_dt = ts[start]
                            end_time_dt = ts[end]

                            task_args = (
                                stream_file,
                                pcap_info_file,
                                start_time_dt,
                                end_time_dt,
                                offset,
                                all_dest_ip_port_pairs,
                                all_local_ip_pairs,
                                all_background_domain_names,
                                multiprocess,
                            )
                            tasks.append(task_args)
                            task_names.append(f"{app_name}_{test_name}_{test_round}_{client_type}_part{i}")
                        else:
                            if not os.path.exists(stream_file):
                                print(f"Skipping {app_name} {test_name} {test_round} {client_type} part {i} - Stream file missing: {stream_file}")
                            if not os.path.exists(text_file):
                                print(f"Skipping {app_name} {test_name} {test_round} {client_type} part {i} - Text file missing: {text_file}")

        processes = []
        process_start_times = []
        for i, task_args in enumerate(tasks):
            if multiprocess:
                p = multiprocessing.Process(target=process_single_file, args=task_args)
                process_start_times.append(time.time())
                processes.append(p)
                p.start()
            else:
                process_single_file(*task_args)

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
                        status += f"Running\t|{elapsed_time}s\t|{task_names[i]}\n"
                    else:
                        elapsed_time = elapsed_times[i]
                        if p.exitcode is None:
                            status += f"Unknown\t|{elapsed_time}s\t|{task_names[i]}\n"
                        elif p.exitcode == 0:
                            status += f"Done\t|{elapsed_time}s\t|{task_names[i]}\n"
                        else:
                            status += f"Code {p.exitcode}\t|{elapsed_time}s\t|{task_names[i]}\n"

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


if __name__ == "__main__":
    # python step2_background_filtering.py --config config.json --multiprocess

    parser = argparse.ArgumentParser(description="Filter out background traffic from pcap files.")
    parser.add_argument("--multiprocess", action="store_true", help="Use multiprocessing for extraction.")
    parser.add_argument("--config", type=str, default="config.json", help="Path to the configuration file.")
    args = parser.parse_args()
    config_path = args.config
    multiprocess = args.multiprocess
    pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, precall_noise, postcall_noise, plugin_target_folder, plugin_source_folder = load_config(config_path)
    background_filtering(pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, multiprocess=multiprocess)
