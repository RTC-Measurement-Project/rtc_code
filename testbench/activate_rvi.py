import subprocess
import re


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

def interface_ctrl(devices, init=True):
    interfaces = {}
    for d in devices.keys():
        if init:
            command = "rvictl -s " + d
        else:
            command = "rvictl -x " + d
        try:
            result = subprocess.run(
                command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # print(f"Command '{command}' executed successfully.")
            if len(result.stdout.decode()) > 0:
                print(result.stdout.decode())

            if init:
                match = re.search(r'[\n\r].*with interface \s*([^\n\r]*)',
                                  result.stdout.decode())
                if match:
                    interfaces[d] = match.group(1)
        except subprocess.CalledProcessError as e:
            print(f"Command '{command}' failed.")
            print(e.stderr.decode())
    return interfaces

if __name__ == "__main__":
    devices = read_dict_from_txt("devices.txt")

    # rvictl -s 00008110-001869483EEB801E
    # rvictl -s 00008110-000470D13400401E
    # open new wireshark in terminal: open -n /Applications/Wireshark.app

    # Execute the initial commands
    interface_ctrl(devices, init=False)
    interfaces = interface_ctrl(devices)
    print(interfaces)
    input("Press Enter to end rvi")
    interface_ctrl(devices, init=False)
