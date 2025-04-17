import re
import os
import glob
from collections import defaultdict, Counter
from contextlib import redirect_stdout
PROTOCOLS = ['STUN', 'RTP', 'RTCP']

def parse_baseline(file_path):
    packet_sets = {proto: set() for proto in PROTOCOLS}
    message_sets = {proto: [] for proto in PROTOCOLS}

    with open(file_path, 'r') as f:
        for line in f:
            match = re.match(r"Packet (\d+) (\w+)", line.strip())
            if match:
                packet_id, protocol = match.groups()
                protocol = protocol.upper()
                if protocol in PROTOCOLS:
                    packet_sets[protocol].add(int(packet_id))
                    message_sets[protocol].append(int(packet_id))

    return packet_sets, message_sets

def parse_dpi(file_path):
    packet_sets = {proto: set() for proto in PROTOCOLS}
    message_sets = {proto: [] for proto in PROTOCOLS}

    current_proto = None
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # Check for protocol switch
            for proto in PROTOCOLS:
                if f"{proto} Info:" in line:
                    current_proto = proto
                    break
            else:
                if current_proto:
                    match = re.search(r"Packet (\d+)", line)
                    if match:
                        pkt = int(match.group(1))
                        packet_sets[current_proto].add(pkt)
                        message_sets[current_proto].append(pkt)

    return packet_sets, message_sets

def evaluate(heuristic_packets, heuristic_messages, dpi_packets, dpi_messages, report_file):
    with open(report_file, 'w') as f:
        with redirect_stdout(f):
            for proto in PROTOCOLS:
                print(f"===== {proto} =====")

                # Packet-level comparison
                h_packets = heuristic_packets[proto]
                d_packets = dpi_packets[proto]
                tp_packets = h_packets & d_packets
                fp_packets = d_packets - h_packets
                fn_packets = h_packets - d_packets

                packet_precision = len(tp_packets) / len(d_packets) if d_packets else 0.0
                packet_recall = len(tp_packets) / len(h_packets) if h_packets else 0.0

                print(f"Packet Precision: {packet_precision:.2f}")
                print(f"Packet Recall: {packet_recall:.2f}")
                print(f"False Positive Packets ({len(fp_packets)}): {sorted(fp_packets)}")
                print(f"False Negative Packets ({len(fn_packets)}): {sorted(fn_packets)}")

                # Message-level comparison (allow duplicates)
                h_msg_counter = Counter(heuristic_messages[proto])
                d_msg_counter = Counter(dpi_messages[proto])

                all_msg_ids = set(h_msg_counter.keys()).union(d_msg_counter.keys())
                tp_msgs = sum(min(h_msg_counter[i], d_msg_counter[i]) for i in all_msg_ids)
                total_d_msgs = sum(d_msg_counter.values())
                total_h_msgs = sum(h_msg_counter.values())

                msg_precision = tp_msgs / total_d_msgs if total_d_msgs else 0.0
                msg_recall = tp_msgs / total_h_msgs if total_h_msgs else 0.0

                fp_msgs = []
                fn_msgs = []
                for msg_id in all_msg_ids:
                    diff = d_msg_counter[msg_id] - h_msg_counter[msg_id]
                    if diff > 0:
                        fp_msgs.extend([msg_id] * diff)
                    elif diff < 0:
                        fn_msgs.extend([msg_id] * (-diff))

                print(f"Message Precision: {msg_precision:.2f}")
                print(f"Message Recall: {msg_recall:.2f}")
                print(f"False Positive Messages ({len(fp_msgs)}): {sorted(fp_msgs)}")
                print(f"False Negative Messages ({len(fn_msgs)}): {sorted(fn_msgs)}")
                print()

if __name__ == '__main__':


    dpi_found_dir = 'dpi_found'
    heuristic_baselines_dir = 'heuristic_baselines'
    accuracy_report_dir = 'accuracy_report'

    dpi_files = glob.glob(os.path.join(dpi_found_dir, '*_dpi_detection.txt'))
    for dpi_file in dpi_files:
        dpi_file_name = os.path.basename(dpi_file)
        baseline_file_name = dpi_file_name.replace('_dpi_detection.txt', '_part1_streams.txt')
        baseline_file = os.path.join(heuristic_baselines_dir, baseline_file_name)
        report_file_name = dpi_file_name.replace('_dpi_detection.txt', '_accuracy_report.txt')
        report_file = os.path.join(accuracy_report_dir, report_file_name)

        h_packets, h_messages = parse_baseline(baseline_file)
        d_packets, d_messages = parse_dpi(dpi_file)
        evaluate(h_packets, h_messages, d_packets, d_messages, report_file)