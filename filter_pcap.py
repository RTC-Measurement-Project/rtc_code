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

from utils import read_from_json, get_stream_filter, find_timestamps, get_ip_type, load_config
from preprocess_pcap import load_filters


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


def filter_pcap(save_main_folder, apps, tests, rounds, client_types):
    """
    Filter pcap files and save the results.
    """
    base_gap = 3
    offset = 10 


    all_dest_ip_port_pairs, all_local_ip_pairs, all_background_domain_names = load_filters(save_main_folder)

    for app_name in apps:
        for test_name in tests:
            if "noise" in test_name:
                continue
            for test_round in rounds:
                for client_type in client_types:
                    for i in range(1, tests[test_name] + 1):
                        text_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}.txt"
                        stream_file = f"{save_main_folder}/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}_streams.json"

                        if os.path.exists(stream_file):
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

                        streams = read_from_json(stream_file)

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
                        # print(f"\nFilter 1:")
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
                        # print(f"\nFilter 2:")
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
                        # print(f"\nHistory Filter:")
                        print(f"Filtered streams: \n{get_stream_filter(filtered['TCP'], filtered['UDP'])}")

if __name__ == "__main__":
    # python filter_pcap.py --config config.json --multiprocess

    parser = argparse.ArgumentParser(description="Extract streams and prepare background info from pcap files.")
    parser.add_argument("--multiprocess", action="store_true", help="Use multiprocessing for extraction.")
    parser.add_argument("--config", type=str, default="config.json", help="Path to the configuration file.")
    args = parser.parse_args()
    config_path = args.config
    multiprocess = args.multiprocess
    pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, precall_noise_duration, postcall_noise_duration = load_config(config_path)
    filter_pcap(save_main_folder, apps, tests, rounds, client_types)
