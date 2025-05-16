import pyshark
import matplotlib.pyplot as plt
from datetime import datetime
import numpy as np
from scapy.all import *
from scipy.stats import gaussian_kde

def extract_info(pcap_file, filter_code=""):
    print(f"Processing {pcap_file}")
    cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True, display_filter=filter_code)
    stream_filters = []
    ports = {"TCP": {"src": [], "dst": []}, "UDP": {"src": [], "dst": []}}
    first_bytes = []
    packet_times = []
    packet_lengths = []
    
    for packet in cap:
        if "TCP" in packet:
            filter = "tcp.stream eq " + packet.tcp.stream
            if packet.tcp.srcport not in ports["TCP"]["src"]:
                ports["TCP"]["src"].append(packet.tcp.srcport)
            if packet.tcp.dstport not in ports["TCP"]["dst"]:
                ports["TCP"]["dst"].append(packet.tcp.dstport)
            packet_lengths.append(int(packet.tcp.len))
        elif "UDP" in packet:
            filter = "udp.stream eq " + packet.udp.stream
            if packet.udp.srcport not in ports["UDP"]["src"]:
                ports["UDP"]["src"].append(packet.udp.srcport)
            if packet.udp.dstport not in ports["UDP"]["dst"]:
                ports["UDP"]["dst"].append(packet.udp.dstport)
            packet_lengths.append(int(packet.udp.length))
        if filter not in stream_filters:
            stream_filters.append(filter)

        raw_packet = bytes(packet.get_raw_packet())
        if "ETH" in packet:
            scapy_pkt = Ether(raw_packet)
        else:
            if "IP" in packet:
                scapy_pkt = IP(raw_packet)
            elif "IPv6" in packet:
                scapy_pkt = IPv6(raw_packet)
        payload = scapy_pkt[Raw].load
        first_byte = payload[0]
        first_bytes.append(first_byte)

        packet_times.append(datetime.fromtimestamp(float(packet.sniff_timestamp)))

    print(f"Number of streams: {len(stream_filters)}")
    cap.close()
    return stream_filters, ports, first_bytes, packet_times, packet_lengths

def get_interpacket_time_dist(pcap_file, filters):
    inter_packet_time = []
    for filter in filters:
        cap = pyshark.FileCapture(pcap_file, display_filter=filter)
        for packet in cap:
            try:
                inter_packet_time.append(float(packet.frame_info.time_delta_displayed))
            except AttributeError:
                pass
        cap.close()

    # remove outliers
    inter_packet_time = [time for time in inter_packet_time if time < 30]
    return inter_packet_time

# def plot_packet_length_dist(packet_lengths):
#     plt.hist(packet_lengths, bins=50, edgecolor="black")
#     plt.title("Distribution of Packet Lengths")
#     plt.xlabel("Packet Length")
#     # plt.yscale("log")
#     # plt.ylabel("Frequency (log scale)")
#     plt.ylabel("Frequency")
#     plt.show()


def plot_dist(data, title, xlabel, fig_name, log_scale=False):
    fig, axs = plt.subplots(2, 2, figsize=(15, 10))
    axs = axs.ravel()
    fig.suptitle(f"{fig_name} Distribution of {title}")

    # Histogram
    axs[0].hist(data, bins=50, edgecolor="black", density=True)
    axs[0].set_title(f"Histogram of {title}")
    axs[0].set_xlabel(xlabel)
    axs[0].set_ylabel("Frequency")
    axs[0].grid()
    if log_scale:
        axs[0].set_yscale("log")
        axs[0].set_ylabel("Frequency (log scale)")

    # CDF
    sorted_lengths = np.sort(data)
    cdf = np.arange(1, len(sorted_lengths) + 1) / len(sorted_lengths)
    axs[1].plot(sorted_lengths, cdf, marker=".", linestyle="none")
    axs[1].set_title(f"Cumulative Distribution Function (CDF) of {title}")
    axs[1].set_xlabel(xlabel)
    axs[1].set_ylabel("CDF")
    axs[1].grid()

    # Box plot
    boxplot = axs[2].boxplot(data, vert=False, showmeans=True, meanprops={"marker":"o", "markerfacecolor":"red", "markeredgecolor":"black"})
    axs[2].set_title(f"Box Plot of {title}")
    axs[2].set_xlabel(xlabel)
    axs[2].set_yticklabels([""])
    mean_value = np.mean(data)
    median_value = np.median(data)
    min_value = np.min(data)
    max_value = np.max(data)
    whisker_min = boxplot["whiskers"][0].get_xdata()[1]
    whisker_max = boxplot["whiskers"][1].get_xdata()[1]
    levels = [1.2, 1.3, 1.4, 1.5]
    axs[2].annotate(f'Mean: {mean_value:.2f}', xy=(mean_value, 1), xytext=(mean_value, levels[0]),
                    arrowprops=dict(facecolor='red', shrink=0.05),
                    horizontalalignment='center')
    axs[2].annotate(f'Median: {median_value:.2f}', xy=(median_value, 1), xytext=(median_value, levels[1]),
                    arrowprops=dict(facecolor='red', shrink=0.05),
                    horizontalalignment='center')
    # axs[2].annotate(f'Min: {min_value:.2f}', xy=(min_value, 1), xytext=(min_value, levels[2]),
    #                 arrowprops=dict(facecolor='green', shrink=0.05),
    #                 horizontalalignment='center')
    # axs[2].annotate(f'Max: {max_value:.2f}', xy=(max_value, 1), xytext=(max_value, levels[3]),
    #                 arrowprops=dict(facecolor='red', shrink=0.05),
    #                 horizontalalignment='center')
    axs[2].annotate(f'Min: {whisker_min:.2f}', xy=(whisker_min, 1), xytext=(whisker_min, levels[2]),
                    arrowprops=dict(facecolor='black', shrink=0.05),
                    horizontalalignment='center')
    axs[2].annotate(f'Max: {whisker_max:.2f}', xy=(whisker_max, 1), xytext=(whisker_max, levels[2]),
                    arrowprops=dict(facecolor='black', shrink=0.05),
                    horizontalalignment='center')

    # PDF
    kde = gaussian_kde(data)
    pdf = kde.evaluate(sorted_lengths)
    axs[3].plot(sorted_lengths, pdf)
    axs[3].set_title(f"Probability Density Function (PDF) of {title}")
    axs[3].set_xlabel(xlabel)
    axs[3].set_ylabel("Density")
    axs[3].grid()

    # plt.tight_layout()
    plt.show()


def main(pcap, name, filter_code=""):
    stream_filters, ports, first_bytes, packet_times, packet_lengths = extract_info(pcap, filter_code=filter_code)

    # print(f"{name} ports: {ports}")

    # # Plotting the distribution of first byte
    # plot_dist(first_bytes, "First Byte", "First Byte", name)

    # Plotting the distribution of packet lengths
    # plot_dist(packet_lengths, "Packet Lengths", "Packet Length", name)

    # # Plotting the distribution of inter-packet times with log scale
    caller_inter_packet_time = get_interpacket_time_dist(pcap, stream_filters)
    plot_dist(caller_inter_packet_time, "Inter-Packet Time", "Inter-Packet Time (s)", name)


if __name__ == "__main__":
    # caller_pcap = "/Users/sam/Desktop/Research Files/code/Apps/FaceTime_oh_600s_av_t1_caller_QUIC.pcapng"
    # callee_pcap = "/Users/sam/Desktop/Research Files/code/Apps/FaceTime_oh_600s_av_t1_callee_QUIC.pcapng"
    # main(caller_pcap, "Caller")
    # main(callee_pcap, "Callee")

    # single_pcap = "/Users/sam/Desktop/Research Files/code/Apps/google_QUIC.pcapng"
    # single_pcap = "/Users/sam/Desktop/Research Files/code/metrics/Discord/multicall_2ip_av_wifi_w/Discord_multicall_2ip_av_wifi_w_t1_caller_part_3_QUIC.pcap"
    # single_pcap = "./Apps/http3_cnn_QUIC.pcapng"
    # single_pcap = "./Apps/http3_medium_QUIC.pcapng"

    app = "FaceTime"
    test = "t1"
    single_pcap = f"/Users/sam/Desktop/rtc_code/testbench/data/{app}/{app}_2ip_av_wifi_ww_{test}_caller_QUIC.pcap"
    # single_pcap = f"/Users/sam/Desktop/rtc_code/testbench/data/{app}/{app}_2ip_av_wifi_ww_{test}_callee_QUIC.pcap"
    filter_code = "quic and (udp.srcport != 443 and udp.dstport != 443)"
    # filter_code = "quic and (ip.src == 162.159.0.0/16 or ip.dst == 162.159.0.0/16)"

    # single_pcap = f"./tests/http3_cnn_QUIC.pcapng"
    # single_pcap = f"./tests/http3_medium_QUIC.pcapng"
    # filter_code = "quic"

    main(single_pcap, single_pcap.split("/")[-1].split(".")[0], filter_code=filter_code)
