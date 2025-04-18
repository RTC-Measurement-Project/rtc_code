import pyshark
from scapy.all import Ether, IP, IPv6, UDP, TCP, Raw, wrpcap


def extract_protocol(
    input_pcap, output_pcap, protocol, filter_code="", decode_as={}, remove_header=True
):
    # Read the original pcap using PyShark
    filter_code = (
        filter_code + f" and ({protocol})" if len(filter_code) != 0 else protocol
    )
    cap = pyshark.FileCapture(
        input_pcap,
        use_json=True,
        include_raw=True,
        display_filter=filter_code,
        decode_as=decode_as,
    )  # Use JSON for better parsing accuracy

    extracted_packets = []

    # Iterate through each packet
    for packet in cap:
        try:
            # Convert PyShark packet to Scapy packet
            raw_packet = bytes(packet.get_raw_packet())
            if "ETH" in packet:
                scapy_pkt = Ether(raw_packet)
            else:
                if "IP" in packet:
                    scapy_pkt = IP(raw_packet)
                elif "IPv6" in packet:
                    scapy_pkt = IPv6(raw_packet)

            content_start = 0  # Default value for RTP content start
            if remove_header and (protocol == "rtp" or protocol == "rtcp"):
                if "ZOOM" in packet:
                    # Extract the Zoom encapsulation portion using PyShark's analysis
                    content_start += int(packet.zoom.headlen)
                    if "ZOOM_O" in packet:
                        content_start += int(packet.zoom_o.headlen)
                elif "FACETIME" in packet:
                    content_start += int(packet.facetime.headlen)

            if scapy_pkt.haslayer(Raw):
                payload = scapy_pkt[Raw].load
                content = payload[content_start:]
                scapy_pkt[Raw].load = content
            if "IP" in packet:
                scapy_pkt[IP].len = len(scapy_pkt[IP]) - content_start
            elif "IPv6" in packet:
                scapy_pkt[IPv6].len = len(scapy_pkt[IPv6]) - content_start
            if "UDP" in packet:
                scapy_pkt[UDP].len = len(scapy_pkt[UDP]) - content_start
            elif "TCP" in packet:
                scapy_pkt[TCP].len = len(scapy_pkt[TCP]) - content_start

            scapy_pkt.time = float(packet.sniff_timestamp)
            extracted_packets.append(scapy_pkt)

        except Exception as e:
            print(f"Error processing packet {packet.number}: {e}")

    if len(extracted_packets) == 0:
        print(f"No packets extracted for protocol '{protocol}'")
    else:
        counter = len(extracted_packets)
        print(f"Extracted {counter} packets for protocol '{protocol}' --- ", end="")
        wrpcap(output_pcap, extracted_packets)
        print(f"saved to {output_pcap}")

    cap.close()
    return len(extracted_packets)


if __name__ == "__main__":
    protocol = "quic"
    filter_code = ""
    tag = "QUIC"

    app = "FaceTime"
    name="normal_"
    test = "t1"
    client = "callee"
    input_pcap_file = f"/Users/sam/Desktop/rtc_code/testbench/data/{app}/{app}_{name}2ip_av_wifi_ww_{test}_{client}.pcapng"
    output_pcap_file = input_pcap_file.split(".")[0] + "_" + tag + ".pcap"

    extract_protocol(
        input_pcap_file,
        output_pcap_file,
        protocol,
        filter_code=filter_code,
        remove_header=False,
    )
