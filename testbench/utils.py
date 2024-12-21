import datetime
import json
import re
import time
import beepy
import os


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

    input(f"Press Enter @ {str}: ")
    current_time = datetime.datetime.now()
    time_string = current_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")

    if delay:
        for remaining in range(duration, 0, -1):
            print(f"Time remaining: {remaining} seconds" + " " * 5, end="\r")
            time.sleep(1)

    offset_seconds = -time.timezone if time.localtime().tm_isdst == 0 else -time.altzone
    offset_hours = offset_seconds // 3600
    offset_minutes = (offset_seconds % 3600) // 60
    offset_string = (
        f"{offset_hours:+03d}{offset_minutes:02d}"  # Format the offset as -0x00
    )
    time_string += offset_string

    print(time_string + " " * 10)
    beepy.beep(sound=1)
    time_dict[time_string] = str
    return time_string


def get_time_filter(time1, time2=""):
    def modify_time(time_string, seconds):
        original_time = datetime.datetime.strptime(
            time_string, "%Y-%m-%d %H:%M:%S.%f%z"
        )
        # original_time = datetime.datetime.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
        modified_time = original_time + datetime.timedelta(seconds=seconds)
        modified_time_string = modified_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
        return modified_time_string

    delta_t = 0.5
    if time2 == "":
        return f'(frame.time >= "{modify_time(time1, -delta_t)}")'
    else:
        return f'(frame.time >= "{modify_time(time1, -delta_t)}" and frame.time <= "{modify_time(time2, delta_t)}")'
