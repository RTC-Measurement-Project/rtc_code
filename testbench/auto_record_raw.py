import sys
import os
import time
sys.path.insert(0, os.path.dirname(__file__))

from utils import read_from_file, record_time, get_time_filter

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

    if os.system("clear") == 1:
        os.system("cls")

    # Execute the initial commands
    print("Capturing noise for " + str(noise_duration) + " seconds...")
    for remaining in range(noise_duration, 0, -1):
        print(f"Time remaining: {remaining} seconds" + " " * 5, end="\r")
        time.sleep(1)
    print("Noise capture is complete" + " " * 10 + "\n")

    for time_point in actions:
        record_time(time_point, time_dict)

    # write to txt file
    file_name = app_name + "_" + test_name + "_t" + str(test_round) + ".txt"
    with open(file_name, "w") as file:
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

        print(f"\nFilter:\n{get_time_filter(times[0], times[-1])}")
        file.write(f"\nFilter:\n{get_time_filter(times[0], times[-1])}\n")
