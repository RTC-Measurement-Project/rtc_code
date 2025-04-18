import pyshark
import re
import os
import shutil
from datetime import datetime, timezone, timedelta
from ipwhois import IPWhois
from IPy import IP
import json
import copy
import sys
import pandas as pd
import beepy
import time


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
    backup = {}
    if os.path.exists(file_path):
        backup = read_from_json(file_path)
    try:
        with open(file_path, "w") as file:
            json.dump(d, file, indent=4)
    except Exception as e:
        if backup:
            with open(file_path, "w") as file:
                json.dump(backup, file, indent=4)
        raise e
    return


def record_time(str, time_dict, delay=True, duration=0):
    try:
        duration_txt = re.search(r"\[(.*?)s\]", str).group(1)
        if duration_txt == "?":
            duration_txt = input("Enter the duration in seconds: ")
        elif duration_txt == "x":
            duration_txt = duration
        str = re.sub(r"\[(.*?)s\]", f"[{duration_txt}s]", str)
        duration = int(duration_txt)
    except:
        duration = 0

    input(f"ACTION: Press Enter when {str}: ")
    current_time = datetime.datetime.now()
    time_string = current_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")

    if delay:
        for remaining in range(duration, 0, -1):
            print(f"Time remaining: {remaining} seconds" + " " * 5, end="\r")
            time.sleep(1)

    offset_seconds = -time.timezone if time.localtime().tm_isdst == 0 else -time.altzone
    offset_hours = offset_seconds // 3600
    offset_minutes = (offset_seconds % 3600) // 60
    offset_string = f"{offset_hours:+03d}{offset_minutes:02d}"  # Format the offset as -0x00
    time_string += offset_string

    print(time_string + " " * 10)
    beepy.beep(sound=1)
    time_dict[time_string] = str
    return time_string


def parse_stream_filter(filter_code):
    streams_dict = {"TCP": [], "UDP": []}
    udp_ids = re.findall(r"udp\.stream\s*==\s*(\d+)", filter_code)
    if udp_ids:
        streams_dict["UDP"] = udp_ids
    tcp_ids = re.findall(r"tcp\.stream\s*==\s*(\d+)", filter_code)
    if tcp_ids:
        streams_dict["TCP"] = tcp_ids
    return streams_dict


def update_json_attribute(json_file_path, attribute_name, attribute_value):
    """
    Updates or adds an attribute in a JSON file. Creates the file if it doesn't exist.

    Args:
        json_file_path (str): The path to the JSON file.
        attribute_name (str): The name of the attribute to update or add.
        attribute_value: The value to set for the attribute.
    """
    data = {}
    if os.path.exists(json_file_path):
        try:
            # Check if file is empty before trying to load
            if os.path.getsize(json_file_path) > 0:
                with open(json_file_path, "r") as file:
                    data = json.load(file)
            # If file is empty, data remains {}
        except json.JSONDecodeError:
            print(f"Warning: File {json_file_path} contains invalid JSON. Initializing with new data.")
            data = {}  # Initialize empty dict if JSON is invalid
        except Exception as e:
            print(f"An error occurred while reading {json_file_path}: {e}")
            # Decide how to handle other errors, maybe re-raise or return
            return  # Exit function on other read errors

    # Update or add the attribute
    data[attribute_name] = attribute_value

    # Save the updated dictionary back to the JSON file
    try:
        save_dict_to_json(data, json_file_path)
    except Exception as e:
        print(f"An error occurred while writing to {json_file_path}: {e}")


def clean_up_folder(folder, files=[]):
    if not os.path.exists(folder):
        print(f"Folder '{folder}' does not exist.")
        return
    else:
        if files == []:
            shutil.rmtree(folder)
            os.makedirs(folder)
            print(f"Folder '{folder}' has been cleaned up.")
        else:
            removed_files = []
            for file in files:
                file_path = os.path.join(folder, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    removed_files.append(file_path)
            print(f"Removed files from '{folder}': {removed_files}")


def copy_file_to_target(target_folder, target_file, storage_folder, suppress_output=False, overwrite=False):
    if suppress_output:
        sys.stdout = open(os.devnull, "w")

    # Ensure that all paths exist
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)

    if not os.path.exists(storage_folder):
        os.makedirs(storage_folder)

    # Define the target file path in both the storage and target folders
    target_file_in_storage = os.path.join(storage_folder, target_file)
    target_file_in_target = os.path.join(target_folder, target_file)

    # If the target file is already in the target folder, do nothing
    if os.path.exists(target_file_in_target) and not overwrite:
        print(f"Target file '{target_file}' is already in the target folder.")
    else:
        # Move the target file from storage to the target folder
        if os.path.exists(target_file_in_storage):
            shutil.copy(target_file_in_storage, target_folder)
            print(f"Copied '{target_file}' from storage to target folder.")
        else:
            print(f"Target file '{target_file}' not found in storage.")

    if suppress_output:
        sys.stdout.close()
        sys.stdout = sys.__stdout__


def move_file_to_target(target_folder, target_file, storage_folder, suppress_output=False):
    if suppress_output:
        sys.stdout = open(os.devnull, "w")

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

    if suppress_output:
        sys.stdout.close()
        sys.stdout = sys.__stdout__


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
        # zone_offset = input("No timezone found. Press enter a timezone (e.g. -0700, +0700): ")
        # while re.match(r"[+-]\d{4}", zone_offset) is None:
        #     zone_offset = input("Invalid timezone. Press enter a timezone (e.g. -0700, +0700): ")
        zone_offset = "-0700"
        matches = [(match[0] + zone_offset, match[1]) for match in matches]
    for match in matches:
        timestamp, action = match
        timestamp_dt = datetime.strptime(timestamp, time_format)
        summary_dict[timestamp_dt] = action
    duration_match = re.search(r"\[(\d+)s\]", matches[-1][1])
    if duration_match:
        duration = int(duration_match.group(1))
        timestamp_dt = datetime.strptime(matches[-1][0], time_format) + timedelta(seconds=duration)
        summary_dict[timestamp_dt] = "END"
    zone_offset_tz = timezone(timedelta(hours=int(zone_offset[:3])))
    return summary_dict, zone_offset_tz


def save_as_new_pcap(input_file, output_file, filter_code):
    cap = pyshark.FileCapture(input_file, display_filter=filter_code, output_file=output_file)
    cap.load_packets()
    cap.close()
    return


def get_time_filter(timestamp_dict, start=0, end=-1, pre_offset=0, post_offset=0, target_zone=None, simplify=False):
    timestamps = list(timestamp_dict.keys())
    timestamps.sort()
    start_time = timestamps[start]
    start_time -= timedelta(seconds=pre_offset)
    if target_zone is not None: start_time = start_time.astimezone(target_zone)
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
    if simplify: start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    if end > len(timestamps) - 1 or end == -1:
        end = len(timestamps) - 1
    end_time = timestamps[end]
    end_time += timedelta(seconds=post_offset)
    if target_zone is not None: end_time = end_time.astimezone(target_zone)
    end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
    if simplify: end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S")
    time_filter = f'(frame.time >= "{start_time_str}" and frame.time <= "{end_time_str}")'
    duration_seconds = (end_time - start_time).total_seconds()
    return time_filter, duration_seconds


def get_time_filter_from_str(time1, time2="", pre_offset=0, post_offset=0, target_zone=None, simplify=False):
    def modify_time(time_string, seconds):
        original_time = datetime.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f%z")
        modified_time = original_time + timedelta(seconds=seconds)
        if target_zone is not None: modified_time = modified_time.astimezone(target_zone)
        modified_time_string = modified_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
        if simplify: modified_time_string = modified_time.strftime("%Y-%m-%d %H:%M:%S")
        return modified_time_string

    if time2 == "":
        return f'(frame.time >= "{modify_time(time1, -pre_offset)}")'
    else:
        return f'(frame.time >= "{modify_time(time1, -pre_offset)}" and frame.time <= "{modify_time(time2, post_offset)}")'


def get_stream_filter(tcp_stream_ids, udp_stream_ids):
    filters = []

    # Build filter for TCP streams
    if tcp_stream_ids:
        tcp_filter = " or ".join([f"tcp.stream == {stream_id}" for stream_id in tcp_stream_ids])
        filters.append(f"({tcp_filter})")

    # Build filter for UDP streams
    if udp_stream_ids:
        udp_filter = " or ".join([f"udp.stream == {stream_id}" for stream_id in udp_stream_ids])
        filters.append(f"({udp_filter})")

    # Combine TCP and UDP filters
    final_filter = " or ".join(filters)
    final_filter = f"({final_filter})"

    return final_filter


def deep_dict_merge(dict1, dict2, copy_dict=True):
    if copy_dict:
        dict3 = dict1.copy()
    else:
        dict3 = dict1
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
        time_out = 0
        while r == None and time_out < 5:
            time_out += 1
            obj = IPWhois(ip)
            results = obj.lookup_rdap()
            r = results["asn_description"]
        if r is None:
            return "Unavailable"
        return r
    except:
        return "Unknown"


def get_ip_type(ip):
    parsed_ip = IP(ip)
    return parsed_ip.iptype()


def compare_shared_values(A, B):
    """
    Compare shared key values of two nested dictionaries A and B.

    Returns:
        0 if all shared key numeric values are equal,
        1 if all A's shared key numeric values are >= than B's,
        2 if all B's shared key numeric values are >= than A's,
        3 otherwise.
    """

    # Flags to track comparison results
    all_equal = True
    all_a_ge_b = True
    all_b_ge_a = True

    def traverse(a, b):
        nonlocal all_equal, all_a_ge_b, all_b_ge_a
        if not isinstance(a, dict) or not isinstance(b, dict):
            return

        # Iterate over shared keys
        for key in a:
            if key in b:
                a_val = a[key]
                b_val = b[key]
                if isinstance(a_val, dict) and isinstance(b_val, dict):
                    traverse(a_val, b_val)
                elif isinstance(a_val, (int, float)) and isinstance(b_val, (int, float)):
                    if a_val != b_val:
                        all_equal = False
                    if a_val < b_val:
                        all_a_ge_b = False
                    if b_val < a_val:
                        all_b_ge_a = False
                # If one is dict and the other is not, ignore as per the problem statement

    traverse(A, B)

    if all_equal:
        return 0
    elif all_a_ge_b:
        return 1
    elif all_b_ge_a:
        return 2
    else:
        return 3


def rename_dict_key(data, old_key, new_key, inplace=True, conflict_handler="overwrite"):
    """
    Recursively renames all occurrences of old_key to new_key in a nested dictionary or list.

    :param data: The dictionary or list to process.
    :param old_key: The key name to be renamed.
    :param new_key: The new key name.
    :param inplace: If True, modifies the original dictionary/list. If False, returns a new modified copy.
    :param conflict_handler: Defines behavior when new_key already exists.
                             Options: 'overwrite', 'skip', 'raise'
    :return: The modified dictionary/list if inplace=False, otherwise None.
    """
    if not isinstance(data, (dict, list)):
        raise TypeError("Input data must be a dictionary or a list.")

    if not inplace:
        data = copy.deepcopy(data)  # Create a deep copy to avoid modifying the original

    def _rename(d):
        if isinstance(d, dict):
            keys = list(d.keys())  # Create a list of keys to avoid RuntimeError during iteration
            for key in keys:
                if key == old_key:
                    if new_key in d:
                        if conflict_handler == "overwrite":
                            pass  # Overwrite existing key
                        elif conflict_handler == "skip":
                            continue  # Do not rename this key
                        elif conflict_handler == "raise":
                            raise KeyError(f"Cannot rename '{old_key}' to '{new_key}' as '{new_key}' already exists.")
                        else:
                            raise ValueError("Invalid conflict_handler. Choose from 'overwrite', 'skip', 'raise'.")
                    d[new_key] = d.pop(old_key)
                    key = new_key  # Update key variable to new_key for further processing

                # Recursively process the value
                if isinstance(d[key], (dict, list)):
                    _rename(d[key])

        elif isinstance(d, list):
            for item in d:
                if isinstance(item, (dict, list)):
                    _rename(item)

    _rename(data)

    if not inplace:
        return data


def load_config(config_path="config.json"):
    """
    Load configuration from JSON file

    Args:
        config_path: Path to the config file

    Returns:
        dict: Configuration dictionary
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    config = read_from_json(config_path)

    pcap_main_folder = config["paths"]["pcap_main_folder"]
    save_main_folder = config["paths"]["save_main_folder"]
    plugin_target_folder = config["paths"]["plugin_target_folder"]
    plugin_source_folder = config["paths"]["plugin_source_folder"]
    apps = config["apps"]
    tests = config["tests"]
    rounds = config["rounds"]
    clients = config["client_types"]
    precall_noise = config["precall_noise_duration"]
    postcall_noise = config["postcall_noise_duration"]

    return pcap_main_folder, save_main_folder, apps, tests, rounds, clients, precall_noise, postcall_noise, plugin_target_folder, plugin_source_folder
