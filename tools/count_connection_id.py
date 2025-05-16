import pyshark
from collections import defaultdict
from prettytable import PrettyTable

na = "No Connection ID"


def analyze_quic_connection_ids(pcap_file, filter_code=""):
    """
    Analyze a QUIC-enabled PCAP file and display a table of connection IDs.

    :param pcap_file: Path to the input PCAP file.
    :param filter_code: Custom display filter for packet selection.
    """
    # Dictionary to count occurrences of all connection IDs
    connection_ids_count = defaultdict(int)
    connection_ids_count[na] = 0
    first_packet_seen = (
        {}
    )  # Tracks the packet number where each connection ID first appears
    connection_ids_address = {na: ""}  # Tracks the IP address the ID belongs to

    print("Analyzing PCAP file, please wait...")

    capture = pyshark.FileCapture(pcap_file, display_filter=filter_code)

    for packet_no, packet in enumerate(capture, start=1):
        try:
            quic_layer = packet.quic

            dest_id = getattr(quic_layer, "quic.dcid", na)
            src_id = getattr(quic_layer, "quic.scid", na)

            if dest_id == src_id == na:
                connection_ids_count[na] += 1
                if na not in first_packet_seen:
                    first_packet_seen[dest_id] = packet_no
                continue
            if dest_id != na:
                connection_ids_count[dest_id] += 1
                if dest_id not in first_packet_seen:
                    first_packet_seen[dest_id] = packet_no

            if src_id != na:
                connection_ids_count[src_id] += 1
                if src_id not in first_packet_seen:
                    first_packet_seen[src_id] = packet_no

            if getattr(quic_layer, "long.packet_type", None) == "0":
                ip_src = getattr(packet.ip, "src", None)
                ip_dst = getattr(packet.ip, "dst", None)

                # Update counts and track first occurrence for Destination IDs
                if dest_id != na:
                    connection_ids_address[dest_id] = (
                        ip_dst  # Destination ID belongs to ip.dst
                    )

                # Update counts and track first occurrence for Source IDs
                if src_id != na:
                    connection_ids_address[src_id] = (
                        ip_src  # Source ID belongs to ip.src
                    )

        except AttributeError:
            # Skip packets that don't have QUIC or IP information
            continue

    # Close capture to release file resources
    capture.close()

    # Display results in a table
    table = PrettyTable()
    table.field_names = [
        "Connection ID",
        "Count",
        "First Packet No.",
        "Belongs To (IP)",
    ]

    # Add connection IDs, counts, first occurrence packet numbers, and IP address to the table
    for conn_id, count in connection_ids_count.items():
        table.add_row(
            [
                conn_id,
                count,
                first_packet_seen.get(conn_id),
                connection_ids_address.get(conn_id),
            ]
        )

    print(f"\n{pcap_file.split('/')[-1]} Connection ID Analysis:")
    print(table)


if __name__ == "__main__":
    # Replace 'input.pcap' with your PCAP file path
    app = "FaceTime"
    name = "normal_"
    test = "t1"
    client = "caller"
    pcap_file_path = f"/Users/sam/Desktop/rtc_code/testbench/data/{app}/{app}_{name}2ip_av_wifi_ww_{test}_{client}_QUIC.pcap"
    
    filter_code = "quic and (udp.srcport != 443 and udp.dstport != 443)"
    # filter_code = "quic and (ip.src == 162.159.0.0/16 or ip.dst == 162.159.0.0/16)"

    # Run the analysis
    analyze_quic_connection_ids(pcap_file_path, filter_code=filter_code)
