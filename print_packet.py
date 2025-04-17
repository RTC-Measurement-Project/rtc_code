import json
import os


def process_packet_data(json_file_path, output_file_path):
    # Load the JSON data from the file
    with open(json_file_path, "r") as file:
        data = json.load(file)

    # Collect all packet details across all streams and protocols
    combined_packets = {}

    # Iterate through each protocol (e.g., TCP)
    for protocol in data:
        # Iterate through each stream under the protocol
        for stream_id in data[protocol]:
            stream = data[protocol][stream_id]
            packet_details = stream.get("packet_details", {})
            # Iterate through each packet in the stream
            for packet_number, details in packet_details.items():
                # Assuming each packet detail has an 'rtc_protocol' list
                # Replace 'rtc_protocols' with the actual key if different
                protocols = details.get("rtc_protocol", [])
                if protocols:
                    combined_packets[packet_number] = protocols

    # Sort packets by their number (converted to integer for correct ordering)
    sorted_packets = sorted(combined_packets.items(), key=lambda x: int(x[0]))

    # Write the output to a text file
    with open(output_file_path, "w") as output_file:
        for packet_number, protocols in sorted_packets:
            for protocol in protocols:
                output_file.write(f"Packet {packet_number} {protocol}\n")


# Example usage
if __name__ == "__main__":
    # input_file = "/Users/sam/Downloads/metrics/Zoom/2ip_av_cellular_cc/Zoom_2ip_av_cellular_cc_t1_caller_part1_streams.json"
    # output_file = "output.txt"
    # process_packet_data(input_file, output_file)

    apps = [
        "Zoom",
        "FaceTime",
        "WhatsApp",
        # "Messenger",
        "Discord",
    ]
    tests = {
        "2ip_av_cellular_cc": 1,
        "2ip_av_p2pwifi_ww": 1,
        "2ip_av_wifi_ww": 1,
    }
    rounds = ["t1", "t2", "t3", "t4", "t5"]
    client_types = [
        "caller",
        "callee",
    ]

    for app_name in apps:
        for test_name in tests:
            for test_round in rounds:
                for client_type in client_types:
                    for i in range(1, tests[test_name] + 1):
                        input_file = f"./metrics/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}_streams.json"
                        output_file = f"./metrics/{app_name}/{test_name}/{app_name}_{test_name}_{test_round}_{client_type}_part{i}_streams.txt"
                        if os.path.exists(input_file):
                            print(f"Processing {app_name} {test_name} {test_round} {client_type} part {i}")
                        else:
                            print(f"Skipping {app_name} {test_name} {test_round} {client_type} part {i}")
                            continue
                        process_packet_data(input_file, output_file)
                        print(f"Processed {input_file} to {output_file}")
