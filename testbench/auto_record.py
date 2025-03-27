import sys
import subprocess
import time
import re
import os
import beepy
import argparse  # Add argparse import

sys.path.insert(0, os.path.dirname(__file__))

# import noise_cancellation as nc
from utils import read_from_txt, read_dict_from_txt, record_time, get_time_filter


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
    if os.system("clear") == 1:
        os.system("cls")

    parser = argparse.ArgumentParser(
        description="Automate recording and processing of network traffic."
    )
    parser.add_argument(
        "-a",
        "--app_name",
        required=True,
        type=str,
        help="Name of the application.",
        choices=["Zoom", "FaceTime", "Messenger", "WhatsApp", "Discord"],
    )
    parser.add_argument(
        "--device_setup",
        type=str,
        default="2ip",
        help="Setup of devices.",
        choices=["2ip", "2mac", "ipmac", "macip"],
    )  # ip: iPhone, mac: Macbook, 1st letter: caller, 2nd letter: callee
    parser.add_argument(
        "--media_setup",
        type=str,
        default="av",
        help="Setup of media.",
        choices=["av", "v", "a", "nm"],
    )
    parser.add_argument(
        "-n",
        "--network_setup",
        required=True,
        type=str,
        help="Setup of network.",
        choices=["wifi", "p2pwifi", "cellular", "p2pcellular"],
    )
    parser.add_argument(
        "-i",
        "--interface_setup",
        required=True,
        type=str,
        help="Setup of interface.",
        choices=["ww", "cc"],
    )  # w: Wi-Fi, c: Cellular, 1st letter: caller, 2nd letter: callee
    parser.add_argument("--test_name", type=str, default="", help="Name of the test.")
    parser.add_argument("-r", "--test_round", required=True, type=int, help="Test round number.")
    parser.add_argument(
        "-nd",
        "--noise_duration",
        type=int,
        default=30,
        help="Duration of noise capture in seconds.",
    )
    # parser.add_argument("--filter_data", type=bool, default=False, help="Whether to filter the data.")
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=60,
        help="Duration of the call in seconds.",
    )
    parser.add_argument(
        "--temp_actions",
        action="store_true",
        default=False,
        help='Use actions in "actions_temp.txt" in the actions folder.',
    )
    parser.add_argument(
        "--dual_noise",
        action="store_true",
        default=False,
        help='Collect both pre-call and post-call noise with the same duration',
    )
    parser.add_argument(
        "--pure_noise",
        action="store_true",
        default=False,
        help="Only enable noise collection without any actions",
    )
    args = parser.parse_args()

    app_name = args.app_name
    if args.test_name != "":
        args.test_name = args.test_name + "_"
    test_name = (
        args.test_name
        + args.device_setup
        + "_"
        + args.media_setup
        + "_"
        + args.network_setup
        + "_"
        + args.interface_setup
    )
    test_round = args.test_round
    noise_duration = args.noise_duration
    # filter_data = args.filter_data
    devices = read_dict_from_txt("devices.txt")
    caller_network = read_dict_from_txt("caller_network.txt")
    callee_network = read_dict_from_txt("callee_network.txt")

    action_folder = "actions"
    actions = read_from_txt(f"{action_folder}/actions_temp.txt")
    if args.temp_actions: print("Using actions from actions_temp.txt")
    temp = "_discord" if app_name == "Discord" else ""
    if len(devices) == 1 and devices[list(devices.keys())[0]] == "caller":
        if not args.temp_actions:
            actions = read_from_txt(f"{action_folder}/actions{temp}_caller.txt")
        assert (
            len(caller_network) > 0 and len(callee_network) == 0
        ), "Caller network is empty, or callee network is filled"
        assert (
            caller_network["Connection Type"].lower() in args.network_setup.lower()
        ), "Caller network setup is incorrect"
        if "w" == args.interface_setup[0]:
            assert (
                caller_network["Wi-Fi IP"] != "NA"
            ), "Caller Wi-Fi IP is not available"
            assert (
                caller_network["Cellular IP"] == "NA"
            ), "Caller Cellular IP is available"
        elif "c" == args.interface_setup[0]:
            assert (
                caller_network["Cellular IP"] != "NA"
            ), "Caller Cellular IP is not available"
            assert caller_network["Wi-Fi IP"] == "NA", "Caller Wi-Fi IP is available"
    elif len(devices) == 1 and devices[list(devices.keys())[0]] == "callee":
        if not args.temp_actions:
            actions = read_from_txt(f"{action_folder}/actions{temp}_callee.txt")
        assert (
            len(callee_network) > 0 and len(caller_network) == 0
        ), "Callee network is empty, or caller network is filled"
        assert (
            callee_network["Connection Type"].lower() in args.network_setup.lower()
        ), "Callee network setup is incorrect"
        if "w" in args.interface_setup[1]:
            assert (
                callee_network["Wi-Fi IP"] != "NA"
            ), "Callee Wi-Fi IP is not available"
            assert (
                callee_network["Cellular IP"] == "NA"
            ), "Callee Cellular IP is available"
        elif "c" in args.interface_setup[1]:
            assert (
                callee_network["Cellular IP"] != "NA"
            ), "Callee Cellular IP is not available"
            assert callee_network["Wi-Fi IP"] == "NA", "Callee Wi-Fi IP is available"
    elif len(devices) == 2:
        if not args.temp_actions:
            actions = read_from_txt(f"{action_folder}/actions{temp}.txt")
        assert (
            len(caller_network) > 0 and len(callee_network) > 0
        ), "Caller or callee network is empty"
        assert (
            caller_network["Connection Type"].lower() in args.network_setup.lower()
        ), "Caller network setup is incorrect"
        assert (
            callee_network["Connection Type"].lower() in args.network_setup.lower()
        ), "Callee network setup is incorrect"
        if "w" == args.interface_setup[0]:
            assert (
                caller_network["Wi-Fi IP"] != "NA"
            ), "Caller Wi-Fi IP is not available"
            assert (
                caller_network["Cellular IP"] == "NA"
            ), "Caller Cellular IP is available"
        elif "c" == args.interface_setup[0]:
            assert (
                caller_network["Cellular IP"] != "NA"
            ), "Caller Cellular IP is not available"
            assert caller_network["Wi-Fi IP"] == "NA", "Caller Wi-Fi IP is available"
        if "w" in args.interface_setup[1]:
            assert (
                callee_network["Wi-Fi IP"] != "NA"
            ), "Callee Wi-Fi IP is not available"
            assert (
                callee_network["Cellular IP"] == "NA"
            ), "Callee Cellular IP is available"
        elif "c" in args.interface_setup[1]:
            assert (
                callee_network["Cellular IP"] != "NA"
            ), "Callee Cellular IP is not available"
            assert callee_network["Wi-Fi IP"] == "NA", "Callee Wi-Fi IP is available"
    else:
        print("Invalid device setup, check your devices.json")
        exit(1)

    time_dict = {}
    save_folder = "data/" + app_name + "/"
    if not os.path.exists(save_folder):
        os.makedirs(save_folder)

    # Execute the initial commands
    interface_ctrl(devices, init=False)
    interfaces = interface_ctrl(devices)

    print(interfaces)
    if len(interfaces) != len(devices):
        print("Error in Remote Virtual Interface setup")
        exit(1)

    process_list = []
    cap_names = []
    for d in interfaces.keys():
        cap_name = (
            save_folder
            + app_name
            + "_"
            + test_name
            + "_t"
            + str(test_round)
            + "_"
            + str(devices[d])
            + ".pcapng"
        )
        cap_names.append(cap_name)
        if os.path.exists(cap_name):
            confirm = input(
                f"File {cap_name} already exists. Do you want to overwrite it? (y/n): "
            )
            if confirm.lower() != "y":
                exit(1)
        process = tshark_init("tshark", interfaces[d], cap_name)
        process_list.append(process)

    if process_list:
        if args.pure_noise:
            print("\nCapturing pure noise for " + str(noise_duration) + " seconds...")
            print("ACTION: Please turn OFF auto-sleep on your device.\nYou can leave your device alone during noise collection until hearing a beep when it is finished.\nThe program will automatically save the noise pcap file.")
        else:
            print("\nCapturing pre-call noise for " + str(noise_duration) + " seconds...")
            print("ACTION: You can open the RTC app NOW. DO NOT start the call yet.")
        for remaining in range(noise_duration, 0, -1):
            print(f"Time remaining: {remaining} seconds" + " " * 5, end="\r")
            time.sleep(1)
        print("Noise capture is complete" + " " * 10 + "\n")
        beepy.beep(sound=1)

        if not args.pure_noise:
            for time_point in actions:
                record_time(time_point, time_dict, duration=args.duration)

            if args.dual_noise:
                print("\nCapturing post-call noise for " + str(noise_duration) + " seconds...")
                for remaining in range(noise_duration, 0, -1):
                    print(f"Time remaining: {remaining} seconds" + " " * 5, end="\r")
                    time.sleep(1)
                print("Noise capture is complete" + " " * 10 + "\n")
                beepy.beep(sound=1)

        for process in process_list:
            tshark_terminate(process)
        interface_ctrl(devices, init=False)

        # nc_filter_codes = []
        # for d in interfaces.keys():
        #     cap_name = (
        #         save_folder
        #         + app_name
        #         + "_"
        #         + test_name
        #         + "_t"
        #         + str(test_round)
        #         + "_"
        #         + str(devices[d])
        #         + ".pcapng"
        #     )
        #     if filter_data:
        #         nc_filter_codes.append(nc.main(cap_name, duration_seconds=noise_duration))
        #     else:
        #         nc_filter_codes.append("")
        #     # nc_filter_codes.append(nc.main(cap_name, end_time=time_dict[list(time_dict.keys())[0]]))

        # write to txt file
        file_name = (
            save_folder + app_name + "_" + test_name + "_t" + str(test_round) + ".txt"
        )
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
            
            if not args.pure_noise:
                print("\nActions:")
                file.write("\nActions:\n")
                for time_point in actions:
                    print(time_point)
                    file.write(time_point + "\n")

            if not args.pure_noise:
                print("\nSummary:")
                file.write("\nSummary:\n")
                for key in time_dict:
                    print(f"{key}: { time_dict[key]}")
                    file.write(f"{key}: { time_dict[key]}\n")
                times = list(time_dict.keys())

            # print(f"\nFilter:\n{get_time_filter(times[0], times[-1])}")
            # file.write(f"\nFilter:\n{get_time_filter(times[0], times[-1])}\n")

            # for i in range(len(nc_filter_codes)):
            #     role = list(devices.values())[i]
            #     code = nc_filter_codes[i]
            #     print("\nNoise Cancellation Code (" + role + "):\n" + code)
            #     file.write("\nNoise Cancellation Code (" + role + "):\n" + code + "\n")

            if args.pure_noise:
                print(f"\nPure Noise Duration:\n{noise_duration} seconds")
                file.write(f"\nPure Noise Duration:\n{noise_duration} seconds\n")
            else:
                print(f"\nPre-call Noise Duration:\n{noise_duration} seconds")
                file.write(f"\nPre-call Noise Duration:\n{noise_duration} seconds\n")

                if args.dual_noise:
                    print(f"\nPost-call Noise Duration:\n{noise_duration} seconds")
                    file.write(f"\nPost-call Noise Duration:\n{noise_duration} seconds\n")

        print(f"\nChecking the size of the pcap files:")
        for cap_name in cap_names:
            pcap_size = os.path.getsize(cap_name)
            print(f"File {cap_name} size: {pcap_size} bytes ({pcap_size/1024/1024:.2f} MB)")
