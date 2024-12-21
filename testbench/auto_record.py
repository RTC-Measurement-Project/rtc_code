import subprocess
import time
import re
import os
import datetime
import noise_cancellation as nc
import beepy
import json
import argparse  # Add argparse import

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
    offset_string = f"{offset_hours:+03d}{offset_minutes:02d}" #Format the offset as -0x00  
    time_string += offset_string

    print(time_string + " " * 10)
    beepy.beep(sound=1)
    time_dict[time_string] = str
    return time_string


def get_filter(time1, time2=""):
    def modify_time(time_string, seconds):
        original_time = datetime.datetime.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f%z")
        # original_time = datetime.datetime.strptime(time_string, "%Y-%m-%d %H:%M:%S.%f")
        modified_time = original_time + datetime.timedelta(seconds=seconds)
        modified_time_string = modified_time.strftime("%Y-%m-%d %H:%M:%S.%f%z")
        return modified_time_string

    delta_t = 0.5
    if time2 == "":
        return f'(frame.time >= "{modify_time(time1, -delta_t)}")'
    else:
        return f'(frame.time >= "{modify_time(time1, -delta_t)}" and frame.time <= "{modify_time(time2, delta_t)}")'


def interface_ctrl(devices, init=True):
    interfaces = {}
    for d in devices.keys():
        if len(d) <= 17:
            interfaces[d] = d
            continue
        if init:
            command = "rvictl -s " + d
        else:
            command = "rvictl -x " + d
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # print(f"Command '{command}' executed successfully.")
            if len(result.stdout.decode()) > 0:
                print(result.stdout.decode())

            if init:
                match = re.search(
                    r"[\n\r].*with interface \s*([^\n\r]*)", result.stdout.decode()
                )
                if match:
                    interfaces[d] = match.group(1)
        except subprocess.CalledProcessError as e:
            print(f"Command '{command}' failed.")
            print(e.stderr.decode())
    return interfaces


def tshark_init(tshark_dir, interface, traffic_dir):
    command = [tshark_dir, "-i", interface, "-w", traffic_dir]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("Capturing " + interface + " traffic...")
    return process


def tshark_terminate(process):
    process.terminate()
    print("Terminating tshark process...")
    time.sleep(3)
    if process.poll() is not None:
        # Process has terminated
        returncode = process.returncode
        print("Process has terminated with return code:", returncode)
        return True
    else:
        # Process is still running
        print("Process is still running")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate recording and processing of network traffic.")
    parser.add_argument("-a", "--app_name", required=True, type=str, help="Name of the application.", choices=["Zoom", "FaceTime", "Messenger", "WhatsApp", "Discord"])
    parser.add_argument("--device_setup", type=str, default="2ip", help="Setup of devices.", choices=["2ip", "2mac", "ipmac", "macip"]) # ip: iPhone, mac: Macbook, 1st letter: caller, 2nd letter: callee
    parser.add_argument("--media_setup", type=str, default="av", help="Setup of media.", choices=["av", "v", "a", "nm"])
    parser.add_argument("-n", "--network_setup", required=True, type=str, help="Setup of network.", choices=["wifi", "p2pwifi", "cellular", "p2pcellular"])
    parser.add_argument("-i", "--interface_setup", required=True, type=str, help="Setup of interface.", choices=["ww", "wc", "cc", "cw"]) # w: Wi-Fi, c: Cellular, 1st letter: caller, 2nd letter: callee
    parser.add_argument("--test_name", type=str, default="", help="Name of the test.")
    parser.add_argument("-r", "--test_round", type=int, help="Test round number.")
    parser.add_argument("--noise_duration", type=int, default=10, help="Duration of noise capture in seconds.")
    parser.add_argument("--filter_data", type=bool, default=False, help="Whether to filter the data.")
    parser.add_argument("--duration", type=int, default=60, help="Duration of the call in seconds.")
    parser.add_argument("--temp_actions", type=bool, default=False, help="Use actions in \"actions_temp.txt\" in the actions folder.")
    args = parser.parse_args()

    app_name = args.app_name
    if args.test_name != "":
        args.test_name = args.test_name + "_"
    test_name = args.test_name + args.device_setup + "_" + args.media_setup + "_" + args.network_setup + "_" + args.interface_setup
    test_round = args.test_round
    noise_duration = args.noise_duration
    filter_data = args.filter_data
    devices = read_dict_from_txt("devices.txt")
    caller_network = read_dict_from_txt("caller_network.txt")
    callee_network = read_dict_from_txt("callee_network.txt")

    action_folder = "actions"
    actions = read_from_txt(f"{action_folder}/actions_temp.txt")
    temp = "_discord" if app_name == "Discord" else ""
    if len(devices) == 1 and devices[list(devices.keys())[0]] == "caller":
        if not args.temp_actions: actions = read_from_txt(f"{action_folder}/actions{temp}_caller.txt")
        assert len(caller_network) > 0 and len(callee_network) == 0, "Caller network is empty, or callee network is filled"
        assert caller_network["Connection Type"].lower() in args.network_setup.lower(), "Caller network setup is incorrect"
        if "w" == args.interface_setup[0]:
            assert caller_network["Wi-Fi IP"] != "NA", "Caller Wi-Fi IP is not available"
            assert caller_network["Cellular IP"] == "NA", "Caller Cellular IP is available"
        elif "c" == args.interface_setup[0]:
            assert caller_network["Cellular IP"] != "NA", "Caller Cellular IP is not available"
            assert caller_network["Wi-Fi IP"] == "NA", "Caller Wi-Fi IP is available"
    elif len(devices) == 1 and devices[list(devices.keys())[0]] == "callee":
        if not args.temp_actions: actions = read_from_txt(f"{action_folder}/actions{temp}_callee.txt")
        assert len(callee_network) > 0 and len(caller_network) == 0, "Callee network is empty, or caller network is filled"
        assert callee_network["Connection Type"].lower() in args.network_setup.lower(), "Callee network setup is incorrect"
        if "w" in args.interface_setup[1]:
            assert callee_network["Wi-Fi IP"] != "NA", "Callee Wi-Fi IP is not available"
            assert callee_network["Cellular IP"] == "NA", "Callee Cellular IP is available"
        elif "c" in args.interface_setup[1]:
            assert callee_network["Cellular IP"] != "NA", "Callee Cellular IP is not available"
            assert callee_network["Wi-Fi IP"] == "NA", "Callee Wi-Fi IP is available"
    elif len(devices) == 2:
        if not args.temp_actions: actions = read_from_txt(f"{action_folder}/actions{temp}.txt")
        assert len(caller_network) > 0 and len(callee_network) > 0, "Caller or callee network is empty"
        assert caller_network["Connection Type"].lower() in args.network_setup.lower(), "Caller network setup is incorrect"
        assert callee_network["Connection Type"].lower() in args.network_setup.lower(), "Callee network setup is incorrect"
        if "w" == args.interface_setup[0]:
            assert caller_network["Wi-Fi IP"] != "NA", "Caller Wi-Fi IP is not available"
            assert caller_network["Cellular IP"] == "NA", "Caller Cellular IP is available"
        elif "c" == args.interface_setup[0]:
            assert caller_network["Cellular IP"] != "NA", "Caller Cellular IP is not available"
            assert caller_network["Wi-Fi IP"] == "NA", "Caller Wi-Fi IP is available"
        if "w" in args.interface_setup[1]:
            assert callee_network["Wi-Fi IP"] != "NA", "Callee Wi-Fi IP is not available"
            assert callee_network["Cellular IP"] == "NA", "Callee Cellular IP is available"
        elif "c" in args.interface_setup[1]:
            assert callee_network["Cellular IP"] != "NA", "Callee Cellular IP is not available"
            assert callee_network["Wi-Fi IP"] == "NA", "Callee Wi-Fi IP is available"
    else:
        print("Invalid device setup, check your devices.json")
        exit(1)

    time_dict = {}
    save_folder = "data/" + app_name + "/"
    if not os.path.exists(save_folder):
        os.makedirs(save_folder)

    if os.system("clear") == 1:
        os.system("cls")

    # Execute the initial commands
    interface_ctrl(devices, init=False)
    interfaces = interface_ctrl(devices)

    print(interfaces)
    if len(interfaces) != len(devices):
        print("Error in Remote Virtual Interface setup")
        exit(1)

    process_list = []
    for d in interfaces.keys():
        cap_name = save_folder + app_name + "_" + test_name + "_t" + str(test_round) + "_" + str(devices[d]) + ".pcapng"
        if os.path.exists(cap_name):
            confirm = input(f"File {cap_name} already exists. Do you want to overwrite it? (y/n): ")
            if confirm.lower() != "y":
                exit(1)
        process = tshark_init("tshark", interfaces[d], cap_name)
        process_list.append(process)

    if process_list:
        print("Capturing noise for " + str(noise_duration) + " seconds...")
        for remaining in range(noise_duration, 0, -1):
            print(f"Time remaining: {remaining} seconds" + " " * 5, end="\r")
            time.sleep(1)
        print("Noise capture is complete" + " " * 10 + "\n")

        for time_point in actions:
            record_time(time_point, time_dict, duration=args.duration)

        for process in process_list:
            tshark_terminate(process)
        interface_ctrl(devices, init=False)

        nc_filter_codes = []
        for d in interfaces.keys():
            cap_name = save_folder + app_name + "_" + test_name + "_t" + str(test_round) + "_" + str(devices[d]) + ".pcapng"
            if filter_data:
                nc_filter_codes.append(nc.main(cap_name, duration_seconds=noise_duration))
            # else:
            #     nc_filter_codes.append("")
            # nc_filter_codes.append(nc.main(cap_name, end_time=time_dict[list(time_dict.keys())[0]]))

        # write to txt file
        file_name = save_folder + app_name + "_" + test_name + "_t" + str(test_round) + ".txt"
        # if os.path.exists(file_name):
        #     confirm = input(f"File {file_name} already exists. Do you want to overwrite it? (y/n): ")
        #     if confirm.lower() != "n":
        #         exit(1)

        with open(file_name, "w") as file:
            print("\nDevices:")
            file.write("Devices:\n")
            for key in devices:
                print(f"{key}: {devices[key]},")
                file.write(f"{key}: {devices[key]},\n")

            if len(caller_network) > 0:
                print("\nNetwork (caller):")
                file.write("\nNetwork (caller):\n")
                for key in caller_network:
                    print(f"{key}: {caller_network[key]}")
                    file.write(f"{key}: {caller_network[key]}\n")
            if len(callee_network) > 0:
                print("\nNetwork (callee):")
                file.write("\nNetwork (callee):\n")
                for key in callee_network:
                    print(f"{key}: {callee_network[key]}")
                    file.write(f"{key}: {callee_network[key]}\n")

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

            for i in range(len(nc_filter_codes)):
                role = list(devices.values())[i]
                code = nc_filter_codes[i]
                print("\nNoise Cancellation Code (" + role + "):\n" + code)
                file.write("\nNoise Cancellation Code (" + role + "):\n" + code + "\n")
