import os
import dpkt
import pyshark
import sys
import struct
from collections import defaultdict, Counter
import socket
from contextlib import redirect_stdout
import argparse
import json
import time
import multiprocessing


protocol = "rtp"  # can be "rtp" or "stun" or "rtcp" or "classicstun"

debug = False

start_packet_index = 1
end_packet_index = 275396
suspecious_flow = ("172.20.10.11", "172.20.10.10", 16393, 16393, 672257842, 100)


ssrc_set = set()
ssrc_set.add(0)  # 特地为了discord

# 定义有效的 RTP Payload Type
VALID_PAYLOAD_TYPES = {0, 3, 4, 7, 8, 9, 13, 14, 15, 18, 26, 31, 32, 33, 34}
VALID_DYNAMIC_PAYLOAD_TYPES = range(96, 128)  # RTP 动态负载类型


def is_valid_payload_type(pt):
    """检查 payload type 是否有效"""
    # return pt in VALID_PAYLOAD_TYPES or pt in VALID_DYNAMIC_PAYLOAD_TYPES
    return True


def detect_rtp(packet_data):
    """
    解析 UDP 负载数据，检测是否为 RTP 协议。
    :param packet_data: bytes, UDP 负载
    :return: dict | None, 如果是 RTP 返回字典，否则返回 None
    """
    if len(packet_data) < 12:  # RTP 头部至少 12 字节
        return None

    # 解析 RTP 头部（12 字节）
    rtp_header = struct.unpack("!BBHII", packet_data[:12])

    first_byte = rtp_header[0]
    version = (first_byte >> 6) & 0x03  # 取高 2 位
    padding = (first_byte >> 5) & 0x01
    extension = (first_byte >> 4) & 0x01
    cc = first_byte & 0x0F  # 取低 4 位

    second_byte = rtp_header[1]
    marker = (second_byte >> 7) & 0x01  # 最高位 Marker 位
    payload_type = second_byte & 0x7F  # 取低 7 位

    seq_num = rtp_header[2]  # 序列号
    timestamp = rtp_header[3]  # 时间戳
    ssrc = rtp_header[4]  # SSRC 标识

    # 检查 RTP 版本是否为 2
    # 我们做了修改，允许rtp version是0!!!
    # if version != 2 and version != 0:
    if version != 2:
        return None

    # 检查 Marker 是否为 0 或 1
    if marker not in {0, 1}:
        return None

    # 检查 timestamp 是否为 0
    if int(timestamp) == 0:
        return None

    # 检查 Payload Type 是否有效
    if not is_valid_payload_type(payload_type):
        return None

    # 解析成功，返回 RTP 头部信息
    return {
        "length": len(packet_data),
        "version": version,
        "padding": padding,
        "extension": extension,
        "cc": cc,
        "marker": marker,
        "payload_type": payload_type,
        "seq_num": seq_num,
        "timestamp": timestamp,
        "ssrc": ssrc,
    }


import struct


def detect_classic_stun(packet_data):
    """
    解析 UDP 负载数据，检测是否为经典 STUN 协议。
    前两byte是message type
    然后是message length
    然后是transaction id 12 bytes
    最后是message
    我们要检查message的长度是否符合message length
    """
    if len(packet_data) < 20:
        return None

    message_type = struct.unpack("!H", packet_data[:2])[0]
    message_length = struct.unpack("!H", packet_data[2:4])[0]
    transaction_id = packet_data[4:16]
    message = packet_data[16:]

    if message_length != len(message):
        return None

    return {
        "message_type": message_type,
        "message_length": message_length,
        "transaction_id": transaction_id.hex(),
    }


def detect_stun(packet_data):
    """
    解析 UDP 负载数据，检测是否为 STUN 协议。
    :param packet_data: bytes, UDP 负载
    :return: dict | None, 如果是 STUN 返回字典，否则返回 None
    """
    if len(packet_data) < 20:  # STUN 头部至少 20 字节
        return None

    # 解析 STUN 头部
    stun_header = struct.unpack("!HHI12s", packet_data[:20])
    msg_type = stun_header[0]
    msg_len = stun_header[1]
    magic_cookie = stun_header[2]
    transaction_id = stun_header[3]

    # trasaction id 之后的东西记录到attributes_string中
    attributes_string = packet_data[20:].hex()

    # STUN 标准 Magic Cookie
    STUN_MAGIC_COOKIE = 0x2112A442

    # 检查 Magic Cookie 是否匹配
    if magic_cookie != STUN_MAGIC_COOKIE:
        return None

    # 解析 STUN 属性
    attributes = {}
    offset = 20
    while offset + 4 <= len(packet_data):
        attr_type, attr_length = struct.unpack("!HH", packet_data[offset : offset + 4])
        attr_value = packet_data[offset + 4 : offset + 4 + attr_length]
        attributes[attr_type] = attr_value
        offset += 4 + attr_length

    # 返回 STUN 头部信息
    return {
        "msg_type": msg_type,
        "msg_length": msg_len,
        "magic_cookie": magic_cookie,
        "transaction_id": transaction_id.hex(),
        "attributes": attributes,
        "attributes_string": attributes_string,
    }


def detect_rtcp(packet_data):
    """
    解析 UDP 负载数据，检测是否为 RTCP 协议。
    :param packet_data: bytes, UDP 负载
    :return: dict | None, 如果是 RTCP 返回字典，否则返回 None
    """
    if len(packet_data) < 8:  # RTCP 头部至少 8 字节
        return None

    # 解析 RTCP 头部
    first_byte, packet_type, length = struct.unpack("!BBH", packet_data[:4])
    version = (first_byte >> 6) & 0x03  # 取高 2 位
    padding = (first_byte >> 5) & 0x01
    rc = first_byte & 0x1F  # 取低 5 位

    # 检查 RTCP 版本是否为 2
    if version != 2:
        return None

    # RTCP 负载类型
    # VALID_RTCP_TYPES = {200, 201, 202, 203, 204, 205, 206} # 添加了205和206 作为payload-specific feedback messages
    # if packet_type not in VALID_RTCP_TYPES:
    #     return None

    # 解析 SSRC (RTCP 头部后紧跟 4 字节 SSRC)
    if len(packet_data) < 8:
        return None
    ssrc = struct.unpack("!I", packet_data[4:8])[0]

    # 解析 RTCP 负载
    payload = packet_data[8:]

    # 判断一下length是否等于payload+header的长度
    if (length + 1) * 4 > len(payload) + 8:
        return None

    return {
        "version": version,
        "padding": padding,
        "rc": rc,
        "packet_type": packet_type,
        "length": length,
        "ssrc": ssrc,
        "payload": payload.hex(),
    }


def validate_rtp_info_list(message_info_list, packet_count):
    filtered_message_info_list = []
    flow_dict = defaultdict(list)

    global ssrc_set

    # Group by flow + payload_type
    for msg in message_info_list:
        flow_id = (msg["flow_info"]["src_ip"], msg["flow_info"]["dst_ip"], msg["flow_info"]["src_port"], msg["flow_info"]["dst_port"], msg["ssrc"], msg["payload_type"])
        # 给每个msg添加一个processed属性，初始为False
        msg["processed"] = False
        flow_dict[flow_id].append(msg)

    for flow_id, messages in flow_dict.items():
        # packet_indices = set(pkt['packet_index'] for pkt in messages)
        # m = len(packet_indices)
        # if m < 10:
        #     continue

        messages_sorted = sorted(messages, key=lambda x: (x["seq_num"], x["timestamp"]))

        clusters = []
        current_cluster = []
        processed_count = 0
        while processed_count < len(messages_sorted):
            for msg in messages_sorted:
                if msg["processed"]:
                    continue
                if not current_cluster:
                    current_cluster.append(msg)
                    msg["processed"] = True
                    processed_count += 1
                else:
                    last_msg = current_cluster[-1]
                    seq_diff = int(msg["seq_num"]) - int(last_msg["seq_num"])
                    ts_diff = int(msg["timestamp"]) - int(last_msg["timestamp"])
                    if seq_diff <= 10 and 0 <= ts_diff <= 100000:
                        current_cluster.append(msg)
                        msg["processed"] = True
                        processed_count += 1
                    else:
                        continue
            if current_cluster:
                clusters.append(current_cluster)
                current_cluster = []

        for cluster in clusters:
            if len(cluster) < 4:
                if debug and flow_id == suspecious_flow:
                    print(f"fail in too few packets: {len(cluster)}")
                continue

            # 如果这个cluster里的message数量小于50，检查他们的packet index的平均间隔是否小于1000
            if len(cluster) < 500:
                packet_index_diff = [cluster[i]["packet_index"] - cluster[i - 1]["packet_index"] for i in range(1, len(cluster))]
                if sum(packet_index_diff) / len(packet_index_diff) > 100:
                    if debug and flow_id == suspecious_flow:
                        print(f"fail in packet_index_diff: {packet_index_diff}")
                    continue
                distinct_seq = set(pkt["seq_num"] for pkt in cluster)
                if len(distinct_seq) <= len(cluster) / 2:
                    if debug and flow_id == suspecious_flow:
                        print(f"fail in distinct_seq: {distinct_seq} out of {len(cluster)}")
                    continue
                # 如果这个cluster的所有message的packet index都一样，也丢掉
                if len(set(pkt["packet_index"] for pkt in cluster)) == 1:
                    if debug and flow_id == suspecious_flow:
                        print(f"fail in packet_index_all_the_same: {cluster}")
                    continue

            distinct_seq = set(pkt["seq_num"] for pkt in cluster)
            if len(distinct_seq) <= 3:
                if debug and flow_id == suspecious_flow:
                    print(f"fail in distinct_seq: {distinct_seq}")
                continue

            timestamps = [pkt["timestamp"] for pkt in sorted(cluster, key=lambda x: x["seq_num"])]
            timestamp_valid = True
            for i in range(1, len(timestamps)):
                if timestamps[i] < timestamps[i - 1] or timestamps[i] > timestamps[i - 1] + 100000:
                    if debug and flow_id == suspecious_flow:
                        print(f"fail in timestamp_valid: {timestamp_valid}")
                        timestamp_valid = False
                    break
                # if not timestamp_valid:
                #     if debug and flow_id == suspecious_flow:
                #         print(f"fail in timestamp_valid: {timestamp_valid}")
                continue

            for pkt in cluster:
                filtered_message_info_list.append(pkt)

    if 1:
        print("RTP Info:")
        debug_flow_group = defaultdict(list)
        for pkt in filtered_message_info_list:
            flow_id = (pkt["flow_info"]["src_ip"], pkt["flow_info"]["dst_ip"], pkt["flow_info"]["src_port"], pkt["flow_info"]["dst_port"], pkt["ssrc"], pkt["payload_type"])
            debug_flow_group[flow_id].append(pkt)
        for flow_id, messages in debug_flow_group.items():
            print(f"Flow {flow_id[0]}:{flow_id[2]} -> {flow_id[1]}:{flow_id[3]} PT={flow_id[5]}: {len(messages)} packets")
            for pkt in messages:
                print(
                    f"  RTP Packet {pkt['packet_index']} (chopped {pkt['chopped_bytes']} bytes), SSRC: {pkt['ssrc']}, Seq Num: {pkt['seq_num']}, Version: {pkt['version']}, Padding: {pkt['padding']}, Extension: {pkt['extension']}, CC: {pkt['cc']}, Marker: {pkt['marker']}, Payload Type: {pkt['payload_type']}, Timestamp: {pkt['timestamp']}"
                )

    # 把filtered_message_info_list中的不重复的ssrc记录到ssrc_set中
    ssrc_set = set(pkt["ssrc"] for pkt in filtered_message_info_list)
    ssrc_set.add(0)

    return filtered_message_info_list


def validate_stun_info_list(message_info_list, packet_count):

    # 对于每一个message，输出他的attributes
    for message_info in message_info_list:
        # print(f"message_info: {message_info}")
        # print(f"attributes_string: {message_info['attributes_string']}")
        # 我要验证stun的message length是否等于attributes_string的长度
        if debug:
            print(f"message_info['msg_length'] * 2: {message_info['msg_length'] * 2}")
            print(f"len(message_info['attributes_string']): {len(message_info['attributes_string'])}")
        if message_info["msg_length"] * 2 != len(message_info["attributes_string"]):
            # 把这个message_info从message_info_list中删除
            message_info_list.remove(message_info)

    if 1:
        print("STUN Info:")
        for message_info in message_info_list:
            # print一下message type, meg len, magic cookie, transaction id,以及packet_index,chopped_bytes
            print(
                f"  STUN Packet {message_info['packet_index']} (chopped {message_info['chopped_bytes']} bytes), "
                f"Msg Type: {message_info['msg_type']}, Msg Len: {message_info['msg_length']}, "
                f"Trans ID: {message_info['transaction_id']}"
            )
            # print(f"  Packet {message_info['packet_index']}")

        #             "msg_type": msg_type,
        # "msg_length": msg_len,
        # "magic_cookie": magic_cookie,
        # "transaction_id": transaction_id.hex(),

    return message_info_list  # 暂时不进行验证


def validate_classic_stun_info_list(message_info_list, packet_count):
    if 1:
        print("Classic STUN Info:")
        for message_info in message_info_list:
            print(
                f"  Classic STUN Packet {message_info['packet_index']} (chopped {message_info['chopped_bytes']} bytes), "
                f"Msg Type: {message_info['message_type']}, Msg Len: {message_info['message_length']}, "
                f"Trans ID: {message_info['transaction_id']}"
            )
            # print(f"  Packet {message_info['packet_index']} (chopped {message_info['chopped_bytes']} bytes), Msg Length: {message_info['message_length']}")
    return message_info_list


def validate_rtcp_info_list(message_info_list, packet_count):
    global ssrc_set
    print(f"ssrc_set: {ssrc_set}")
    print(f"length of message_info_list: {len(message_info_list)}")

    filtered_message_info_list = []

    # 对于每一个message_info，查看是否在ssrc_set中
    for message_info in message_info_list:
        if message_info["ssrc"] in ssrc_set:
            filtered_message_info_list.append(message_info)

    print(f"length of message_info_list after removing: {len(filtered_message_info_list)}")
    if 1:
        print("RTCP Info:")
        for message_info in filtered_message_info_list:
            print(f"  RTCP Packet {message_info['packet_index']} (chopped {message_info['chopped_bytes']} bytes), SSRC: {message_info['ssrc']}, Payload Type: {message_info['packet_type']}")
    return filtered_message_info_list


def ip_to_str(ip_bytes):
    """将IP地址字节转换为字符串，支持IPv4和IPv6"""
    try:
        if len(ip_bytes) == 4:  # IPv4
            return socket.inet_ntoa(ip_bytes)
        elif len(ip_bytes) == 16:  # IPv6
            return socket.inet_ntop(socket.AF_INET6, ip_bytes)
        else:
            return "Invalid IP"
    except Exception:
        return "Invalid IP"


def read_first_packet(file_path):
    """读取 pcap/pcapng 的第一个包，判断是否包含 Ethernet 头部"""
    cap = pyshark.FileCapture(file_path)  # 只读取摘要，提高效率
    # print(f"cap: {cap}")
    for packet in cap:
        # print(f"packet: {packet}")
        if hasattr(packet, "eth"):
            cap.close()
            return True
        cap.close()
        return False
    cap.close()
    return False


def read_pcapng(file_path):
    """解析 pcap/pcapng 文件，转换为 16 进制，并调用 detect_rtp"""
    has_ethernet = read_first_packet(file_path)
    packet_indices = []
    message_info_list = []
    # print(f"has_ethernet: {has_ethernet}")

    with open(file_path, "rb") as f:
        if file_path.endswith(".pcapng"):
            pcap_reader = dpkt.pcapng.Reader(f)
        else:
            pcap_reader = dpkt.pcap.Reader(f)

        packet_index = 0
        for timestamp, buf in pcap_reader:
            packet_index += 1

            # 用于调试
            if debug:
                if packet_index < start_packet_index or packet_index > end_packet_index:
                    continue
            # 解析以太网帧
            if has_ethernet:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue  # 不是 IP 数据包，跳过
                ip_pkt = eth.data
            else:
                if len(buf) < 1:
                    continue  # 避免 buf 为空
                if buf[0] >> 4 == 4:
                    if len(buf) < 20:
                        continue  # IPv4 头部至少 20 字节
                    try:
                        ip_pkt = dpkt.ip.IP(buf)
                    except:
                        continue
                elif buf[0] >> 4 == 6:
                    if len(buf) < 40:
                        continue  # IPv6 头部至少 40 字节
                    try:
                        ip_pkt = dpkt.ip6.IP6(buf)
                    except:
                        continue
                else:
                    continue  # 既不是 IPv4 也不是 IPv6，跳过

            # 解析 UDP 负载
            if isinstance(ip_pkt.data, dpkt.udp.UDP):
                udp_pkt = ip_pkt.data
                udp_payload = bytes(udp_pkt.data)

                # 把udp_payload依次砍掉0,1,2,...,199个字节，然后调用detect_rtp/detect_stun/detect_rtcp
                for i in range(200):
                    # if debug:
                    #     if i != 127:
                    #         continue
                    udp_payload_slice = udp_payload[i:]
                    # print(f"udp_payload_slice: {udp_payload_slice.hex()}")
                    # deal with rtp first
                    if protocol == "rtp":
                        rtp_info = detect_rtp(udp_payload_slice)
                        if rtp_info:
                            packet_indices.append(packet_index)
                            # apppend flow information to rtp_info
                            rtp_info["flow_info"] = {
                                "src_ip": ip_to_str(ip_pkt.src),
                                "dst_ip": ip_to_str(ip_pkt.dst),
                                "src_port": udp_pkt.sport,
                                "dst_port": udp_pkt.dport,
                            }
                            rtp_info["chopped_bytes"] = i
                            rtp_info["packet_index"] = packet_index
                            message_info_list.append(rtp_info)
                    # then deal with stun
                    if protocol == "stun":
                        stun_info = detect_stun(udp_payload_slice)
                        if stun_info:
                            packet_indices.append(packet_index)
                            # apppend flow information to stun_info
                            stun_info["flow_info"] = {
                                "src_ip": ip_to_str(ip_pkt.src),
                                "dst_ip": ip_to_str(ip_pkt.dst),
                                "src_port": udp_pkt.sport,
                                "dst_port": udp_pkt.dport,
                            }
                            stun_info["chopped_bytes"] = i
                            stun_info["packet_index"] = packet_index
                            message_info_list.append(stun_info)
                    # then deal with rtcp
                    if protocol == "rtcp":
                        rtcp_info = detect_rtcp(udp_payload_slice)
                        if rtcp_info:
                            # print udp_payload_slice in hex
                            # print(f"udp_payload_slice: {udp_payload_slice.hex()}")
                            packet_indices.append(packet_index)
                            # apppend flow information to rtcp_info
                            rtcp_info["flow_info"] = {
                                "src_ip": ip_to_str(ip_pkt.src),
                                "dst_ip": ip_to_str(ip_pkt.dst),
                                "src_port": udp_pkt.sport,
                                "dst_port": udp_pkt.dport,
                            }
                            rtcp_info["chopped_bytes"] = i
                            rtcp_info["packet_index"] = packet_index
                            message_info_list.append(rtcp_info)

    print(f"{file_path}")
    # validate rtp
    if protocol == "rtp":
        filtered_message_info_list = validate_rtp_info_list(message_info_list, len(packet_indices))
        packet_index_set = set(message_info["packet_index"] for message_info in filtered_message_info_list)
        print(f"Total RTP packets found: {len(packet_index_set)}")
        print(f"Total RTP messages found: {len(filtered_message_info_list)}")
    # validate stun
    if protocol == "stun":
        filtered_message_info_list = validate_stun_info_list(message_info_list, len(packet_indices))
        packet_index_set = set(message_info["packet_index"] for message_info in filtered_message_info_list)
        print(f"Total STUN packets found: {len(packet_index_set)}")
        print(f"Total STUN messages found: {len(filtered_message_info_list)}")
    # validate rtcp
    if protocol == "rtcp":
        filtered_message_info_list = validate_rtcp_info_list(message_info_list, len(packet_indices))
        packet_index_set = set(message_info["packet_index"] for message_info in filtered_message_info_list)
        print(f"Total RTCP packets found: {len(packet_index_set)}")
        print(f"Total RTCP messages found: {len(filtered_message_info_list)}")


def process_pcap_folder(folder_path):
    """遍历文件夹中的所有 pcap/pcapng 文件并生成报告"""
    global protocol
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".pcap") or file.endswith(".pcapng"):
                file_path = f"{root}/{file}"
                print(f"processing file: {file_path}")

                # 设置输出报告文件名
                if not os.path.exists("./dpi_found"):
                    os.makedirs("./dpi_found")
                report_path = "./dpi_found/" + os.path.splitext(file_path)[0].split("/")[-1] + "_dpi_detection.txt"
                if os.path.exists(report_path):
                    os.remove(report_path)
                with open(report_path, "w", encoding="utf-8") as f:
                    with redirect_stdout(f):
                        protocol = "stun"
                        read_pcapng(file_path)
                        protocol = "rtp"
                        read_pcapng(file_path)
                        protocol = "rtcp"
                        read_pcapng(file_path)


def process_pcap_file(file_path):
    # 设置输出报告文件名
    global protocol
    if not os.path.exists("./dpi_found"):
        os.makedirs("./dpi_found")
    report_path = "./dpi_found/" + os.path.splitext(file_path)[0].split("/")[-1] + "_dpi_detection.txt"
    if os.path.exists(report_path):
        os.remove(report_path)
    # print(f"processing file: {file_path}")
    with open(report_path, "w", encoding="utf-8") as f:
        with redirect_stdout(f):
            if debug:
                protocol = "rtp"
                read_pcapng(file_path)
            else:
                protocol = "stun"
                read_pcapng(file_path)
                protocol = "rtp"
                read_pcapng(file_path)
                protocol = "rtcp"
                read_pcapng(file_path)


def load_config(config_path="config.json"):
    """
    Load configuration from JSON file

    Args:
        config_path: Path to the config file

    Returns:
        dict: Configuration dictionary
    """

    def read_from_json(file_path):
        with open(file_path, "r") as file:
            dict = json.load(file)
        return dict

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


if __name__ == "__main__":
    # python check_dpi.py --config ../config.json --multiprocess
    
    # if len(sys.argv) < 2:
    #     print("Usage: python script.py <folder_path> or <file_path>")
    #     sys.exit(1)

    # path = sys.argv[1]
    # if path.endswith(".pcap") or path.endswith(".pcapng"):
    #     process_pcap_file(path)
    # else:
    #     process_pcap_folder(path)

    parser = argparse.ArgumentParser(description="Filter out background traffic from pcap files.")
    parser.add_argument("--multiprocess", action="store_true", help="Use multiprocessing for extraction.")
    parser.add_argument("--config", type=str, default="config.json", help="Path to the configuration file.")
    args = parser.parse_args()
    config_path = args.config
    multiprocess = args.multiprocess
    pcap_main_folder, save_main_folder, apps, tests, rounds, client_types, precall_noise, postcall_noise, plugin_target_folder, plugin_source_folder = load_config(config_path)

    for app_name in apps:
        for test_name in tests:
            tasks = []
            task_names = []
            if "noise" in test_name:
                continue
            for test_round in rounds:
                for client_type in client_types:
                    for i in range(1, tests[test_name] + 1):
                        pcap_subfolder = f"{pcap_main_folder}/{app_name}"
                        pcap_file_name = f"{app_name}_{test_name}_{test_round}_{client_type}.pcapng"
                        pcap_file = f"{pcap_subfolder}/{pcap_file_name}"
                        tasks.append((pcap_file,))
                        task_names.append(f"{app_name}_{test_name}_{test_round}_{client_type}")

            processes = []
            process_start_times = []
            for i, task_args in enumerate(tasks):
                if multiprocess:
                    p = multiprocessing.Process(target=process_pcap_file, args=task_args)
                    process_start_times.append(time.time())
                    processes.append(p)
                    p.start()
                else:
                    print(f"Processing {task_args}")
                    process_pcap_file(*task_args)

            if multiprocess:
                if len(processes) == 0:
                    print(f"Skip {app_name} tasks.")
                    continue

                print(f"\n{app_name} tasks started.\n")

                lines = len(processes)
                elapsed_times = [0] * len(processes)
                print("\n" * lines, end="")
                while True:
                    all_finished = True
                    status = ""
                    for i, p in enumerate(processes):
                        if p.is_alive():
                            elapsed_time = int(time.time() - process_start_times[i])
                            elapsed_times[i] = elapsed_time
                            all_finished = False
                            status += f"Running\t|{elapsed_time}s\t|{task_names[i]}\n"
                        else:
                            elapsed_time = elapsed_times[i]
                            if p.exitcode is None:
                                status += f"Unknown\t|{elapsed_time}s\t|{task_names[i]}\n"
                            elif p.exitcode == 0:
                                status += f"Done\t|{elapsed_time}s\t|{task_names[i]}\n"
                            else:
                                status += f"Code {p.exitcode}\t|{elapsed_time}s\t|{task_names[i]}\n"

                    if status[-1] == "\n":
                        status = status[:-1]
                    print("\033[F" * lines, end="")  # Move cursor up
                    for _ in range(lines):
                        print("\033[K\n", end="")  # Clear the line
                    print("\033[F" * lines, end="")  # Move cursor up
                    print(status)

                    if all_finished:
                        print(f"\nAll {app_name} tasks are finished. (Average Runtime: {sum(elapsed_times) / len(elapsed_times):.2f}s)")
                        break
                    time.sleep(1)

                for p in processes:
                    p.join()
