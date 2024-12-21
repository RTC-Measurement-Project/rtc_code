import time
import re
import os
import datetime
import noise_cancellation as nc
import beepy


def read_from_file(file_path):
    with open(file_path, 'r') as file:
        actions = file.readlines()
    return [action.strip() for action in actions]


def record_time(str, time_dict, delay=True):
    input(f"Press Enter @ {str}: ")
    current_time = datetime.datetime.now()
    time_string = current_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
    try:
        duration = int(re.search(r'\[(.*?)s\]', str).group(1))
    except:
        duration = 0
    if delay:
        for remaining in range(duration, 0, -1):
            print(f"Time remaining: {remaining} seconds" + " " * 5, end='\r')
            time.sleep(1)
    
    offset_seconds = -time.timezone if time.localtime().tm_isdst == 0 else -time.altzone
    offset_hours = offset_seconds // 3600
    offset_minutes = (offset_seconds % 3600) // 60
    offset_string = f"{offset_hours:+03d}{offset_minutes:02d}" #Format the offset as -0x00  
    time_string += offset_string        
    
    print(time_string + " " * 10)
    beepy.beep(sound=1)
    time_dict[time_string] = str
    return time_string


def get_filter(time1, time2=""):
    def modify_time(time_string, seconds):
        # original_time = datetime.datetime.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f%z")
        original_time = datetime.datetime.strptime(
            time_string, "%Y-%m-%d %H:%M:%S.%f")
        modified_time = original_time + datetime.timedelta(seconds=seconds)
        modified_time_string = modified_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
        return modified_time_string

    delta_t = 0.5
    if time2 == "":
        return f"(frame.time >= \"{modify_time(time1, -delta_t)}\")"
    else:
        return f"(frame.time >= \"{modify_time(time1, -delta_t)}\" and frame.time <= \"{modify_time(time2, delta_t)}\")"


if __name__ == "__main__":
    app_name = "Messenger"
    test_name = "multicall_2mac_av_wifi_w"
    # test_name = "multicall_2mac_av_p2pwifi_w"
    test_round = 1
    noise_duration = 10
    actions = read_from_file("actions/actions.txt")
    time_dict = {}
    devices = {
        # "Google Pixel 7 Pro": "caller",
        # "Samsung Galaxy S22": "callee",
        "MacBook Pro 14": "caller",
        "MacBook Pro 16": "callee",
    }
    
    if (os.system('clear') == 1):
        os.system('cls')

    # Execute the initial commands
    print("Capturing noise for " + str(noise_duration) + " seconds...")
    for remaining in range(noise_duration, 0, -1):
        print(f"Time remaining: {remaining} seconds" + " " * 5, end='\r')
        time.sleep(1)
    print("Noise capture is complete" + " " * 10 + "\n")

    for time_point in actions:
        record_time(time_point, time_dict)

    # write to txt file
    file_name = app_name + "_" + test_name + \
        "_t" + str(test_round) + ".txt"
    with open(file_name, 'w') as file:
        print("\nDevices:")
        file.write("Devices:\n")
        for key in devices:
            print(f"{key}: {devices[key]},")
            file.write(f"{key}: {devices[key]},\n")
        
        print("\nActions:")
        file.write("\nActions:\n")
        for time_point in actions:
            print(time_point)
            file.write(time_point + "\n")
        
        print("\nSummary:")
        file.write("\nSummary:\n")
        for key in time_dict:
            print(f"{key}: { time_dict[key]}")
            file.write(f"{key}: { time_dict[key]}\n")
        times = list(time_dict.keys())
        print(f"\nFilter:\n{get_filter(times[0], times[-1])}")
        file.write(f"\nFilter:\n{get_filter(times[0], times[-1])}\n")
        for i in range(len(list(devices.values()))):
            role = list(devices.values())[i]
            print("\nNoise Cancellation Code ("+ role +")\n")
            file.write("\nNoise Cancellation Code ("+ role +")\n" + "\n")
