import pyshark
import re
import os
import shutil
from datetime import datetime, timezone, timedelta
from ipwhois import IPWhois
import json
import pandas as pd


def read_from_csv(file_path):
    return pd.read_csv(file_path)

def read_from_txt(file_path):
    with open(file_path, "r") as file:
        lines = file.readlines()
    return [line.strip() for line in lines]


def read_from_json(file_path):
    with open(file_path, "r") as file:
        dict = json.load(file)
    return dict


def read_dict_from_txt(file_path):
    result = {}
    with open(file_path, "r") as file:
        for line in file:
            try:
                key, value = line.strip().split(": ", 1)
                result[key] = value
            except ValueError:
                pass
    return result

def save_dict_to_json(d, file_path):
    with open(file_path, "w") as file:
        json.dump(d, file, indent=4)
    return

def move_file_to_target(target_folder, target_file, storage_folder):
    # Ensure that all paths exist
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)

    if not os.path.exists(storage_folder):
        os.makedirs(storage_folder)

    # Define the target file path in both the storage and target folders
    target_file_in_storage = os.path.join(storage_folder, target_file)
    target_file_in_target = os.path.join(target_folder, target_file)

    # Check if the target folder is empty
    if not os.listdir(target_folder):
        # If empty, move the target file from storage to target folder
        if os.path.exists(target_file_in_storage):
            shutil.move(target_file_in_storage, target_folder)
            print(f"Moved '{target_file}' from storage to target folder.")
        else:
            print(f"Target file '{target_file}' not found in storage.")
    else:
        # If the target file is already in the target folder, do nothing
        if os.path.exists(target_file_in_target):
            print(f"Target file '{target_file}' is already in the target folder.")
        else:
            # Move all other files and folders from the target folder to the storage folder
            for item in os.listdir(target_folder):
                if item == ".DS_Store":
                    continue
                item_path = os.path.join(target_folder, item)
                shutil.move(item_path, storage_folder)

            # Move the target file from storage to the target folder
            if os.path.exists(target_file_in_storage):
                shutil.move(target_file_in_storage, target_folder)
                print(f"Moved '{target_file}' from storage to target folder.")
            else:
                print(f"Target file '{target_file}' not found in storage.")


def get_decode_as(ports_dict, protocol):
    protocol = protocol.lower()
    decode_as = {}
    for tcp_port in ports_dict["TCP"]:
        name = "tcp.port == " + str(tcp_port)
        decode_as[name] = protocol
        if protocol == "":
            decode_as[name] = "data"
    for udp_port in ports_dict["UDP"]:
        name = "udp.port == " + str(udp_port)
        decode_as[name] = protocol
        if protocol == "":
            decode_as[name] = "data"
    return decode_as

def find_timestamps(txt_file):
    # time_format = "%Y-%m-%d %H:%M:%S.%f"
    time_format = "%Y-%m-%d %H:%M:%S.%f%z"
    summary_dict = {}
    pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+): (.+)"
    pattern_with_zone = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[+-]\d{4}): (.+)"
    with open(txt_file, "r") as file:
        content = file.read()
    matches = re.findall(pattern, content)
    if len(matches) == 0:
        matches = re.findall(pattern_with_zone, content)
        zone_offset = matches[0][0][-5:]
    else:
        zone_offset = input("No timezone found. Press enter a timezone (e.g. -0700, +0700): ")
        while re.match(r"[+-]\d{4}", zone_offset) is None:
            zone_offset = input("Invalid timezone. Press enter a timezone (e.g. -0700, +0700): ")
        matches = [(match[0] + zone_offset, match[1]) for match in matches]
    for match in matches:
        timestamp, action = match
        timestamp_dt = datetime.strptime(timestamp, time_format)
        summary_dict[timestamp_dt] = action
    zone_offset_tz = timezone(timedelta(hours=int(zone_offset[:3])))
    return summary_dict, zone_offset_tz

def save_as_new_pcap(input_file, output_file, filter_code):
    cap = pyshark.FileCapture(
        input_file, display_filter=filter_code, output_file=output_file
    )
    cap.load_packets()
    cap.close()
    return


def get_time_filter(timestamp_dict, start=0, end=-1):
    timestamps = list(timestamp_dict.keys())
    timestamps.sort()
    start_time = timestamps[start]
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
    if end > len(timestamps) - 1 or end == -1:
        time_filter = f'(frame.time >= "{start_time_str}")'
        end_time = timestamps[-1]
        end_time += timedelta(seconds=5)
        end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
    else:
        end_time = timestamps[end]
        end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
    time_filter = (
        f'(frame.time >= "{start_time_str}" and frame.time <= "{end_time_str}")'
    )
    return time_filter


def get_stream_filter(tcp_stream_ids, udp_stream_ids):
    filters = []

    # Build filter for TCP streams
    if tcp_stream_ids:
        tcp_filter = " or ".join(
            [f"tcp.stream == {stream_id}" for stream_id in tcp_stream_ids]
        )
        filters.append(f"({tcp_filter})")

    # Build filter for UDP streams
    if udp_stream_ids:
        udp_filter = " or ".join(
            [f"udp.stream == {stream_id}" for stream_id in udp_stream_ids]
        )
        filters.append(f"({udp_filter})")

    # Combine TCP and UDP filters
    final_filter = " or ".join(filters)
    final_filter = f"({final_filter})"

    return final_filter


def deep_dict_merge(dict1, dict2):
    dict3 = dict1.copy()
    for key, value in dict2.items():
        if key in dict3:
            if isinstance(value, dict):
                dict3[key] = deep_dict_merge(dict3[key], value)
            if isinstance(value, list) or isinstance(value, int):
                dict3[key] += value
            if isinstance(value, set):
                dict3[key] = dict3[key].union(value)
        else:
            dict3[key] = value
    return dict3

def get_asn_description(ip):
    try:
        r = None
        while r == None:
            obj = IPWhois(ip)
            results = obj.lookup_rdap()
            r = results["asn_description"]
        return r
    except:
        return "Unknown"
