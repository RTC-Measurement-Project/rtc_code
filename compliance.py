from collections import defaultdict
import binascii
import tempfile
import scapy.all as scapy
import pyshark
import os
import multiprocessing

packet_number = 0
prev_packet_number = -1
connection_id = set()
ssrc = set()


def initialize_protocol(proto_dict, actual_protocol):
    """Initialize compliance metrics for a protocol if not already initialized."""
    if proto_dict.get(actual_protocol) is None:
        proto_dict[actual_protocol] = {
            "Undefined Message Messages": 0,
            "Invalid Header Messages": 0,
            "Undefined Attributes Messages": 0,
            "Invalid Attributes Messages": 0,
            "Invalid Semantics Messages": 0,
            "Undefined Message Packets": set(),
            "Invalid Header Packets": set(),
            "Undefined Attributes Packets": set(),
            "Invalid Attributes Packets": set(),
            "Invalid Semantics Packets": set(),
            "Proprietary Header Packets": set(),
            "Message Types": {},
            "Non-Compliant Types": {},
        }


def process_packet(packet, protocol_compliance, log, target_protocols, decode_as={}):
    protocols = []
    for protocol in target_protocols:
        if protocol in packet:
            if protocol in ["WASP", "CLASSICSTUN"]:
                actual_protocol = "STUN"
            else:
                actual_protocol = protocol
            validity_checks, additional_protocols = check_compliance(
                protocol_compliance,
                packet,
                protocol,
                actual_protocol,
                log,
                target_protocols,
                decode_as=decode_as,
            )
            protocols += additional_protocols
            for check in validity_checks:
                if check:
                    protocols.append(actual_protocol)
    return protocols


def parse_datagram(packet, hex_payload, protocol_compliance, log, target_protocols, decode_as={}):
    protocols = []
    packet_number_str = packet.number

    if "IP" in packet:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        ip_layer = scapy.IP(src=src_ip, dst=dst_ip)
    elif "IPv6" in packet:
        src_ip = packet.ipv6.src
        dst_ip = packet.ipv6.dst
        ip_layer = scapy.IPv6(src=src_ip, dst=dst_ip)

    if "UDP" in packet:
        src_port = int(packet.udp.srcport)
        dst_port = int(packet.udp.dstport)
        transport_layer = scapy.UDP(sport=src_port, dport=dst_port)
    elif "TCP" in packet:
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
        transport_layer = scapy.TCP(sport=src_port, dport=dst_port)

    try:
        payload_bytes = binascii.unhexlify(hex_payload)
    except binascii.Error as e:
        raise ValueError("Invalid hex string provided.") from e

    raw_payload = scapy.Raw(load=payload_bytes)
    new_packet = ip_layer / transport_layer / raw_payload

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_pcap:
        scapy.wrpcap(temp_pcap.name, new_packet)
        temp_pcap_path = temp_pcap.name

    try:
        capture = pyshark.FileCapture(temp_pcap_path, decode_as=decode_as)
        try:
            parsed_packet = next(iter(capture))
            parsed_packet.number = packet_number_str
            protocols = process_packet(parsed_packet, protocol_compliance, log, target_protocols)
        except StopIteration:
            raise ValueError("No packets found in the PCAP file.")
    finally:
        capture.close()
        os.remove(temp_pcap_path)

    return protocols


def add_message_type(proto_dict, actual_protocol, message_type_str):
    """Add message type to protocol dictionary."""
    if message_type_str not in proto_dict[actual_protocol]["Message Types"]:
        proto_dict[actual_protocol]["Message Types"][message_type_str] = {
            "Total Messages": 0,
            "Compliant Messages": 0,
            "Non-Compliant Messages": 0,
        }
    proto_dict[actual_protocol]["Message Types"][message_type_str]["Total Messages"] += 1
    proto_dict[actual_protocol]["Message Types"][message_type_str]["Compliant Messages"] = (
        proto_dict[actual_protocol]["Message Types"][message_type_str]["Total Messages"] - proto_dict[actual_protocol]["Message Types"][message_type_str]["Non-Compliant Messages"]
    )


def mark_non_compliance(proto_dict, actual_protocol, message_type_str, error_type, field, value):
    """Mark non-compliance and update counters for the given protocol."""
    proto_dict[actual_protocol]["Message Types"][message_type_str]["Non-Compliant Messages"] += 1
    proto_dict[actual_protocol]["Message Types"][message_type_str]["Compliant Messages"] = (
        proto_dict[actual_protocol]["Message Types"][message_type_str]["Total Messages"] - proto_dict[actual_protocol]["Message Types"][message_type_str]["Non-Compliant Messages"]
    )
    error_detail = f"Protocol [{actual_protocol}], Message [{message_type_str}], Criterion [{error_type}], Field [{field}], Value [{value}]"
    global packet_number
    proto_dict[actual_protocol][error_type + " Messages"] += 1
    proto_dict[actual_protocol][error_type + " Packets"].add((packet_number, error_detail))
    if message_type_str not in proto_dict[actual_protocol]["Non-Compliant Types"]:
        #     proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str] = defaultdict(set)
        # proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str][error_type].add(error_detail)
        proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str] = {}
    if error_type not in proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str]:
        proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str][error_type] = defaultdict(set)
    proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str][error_type][field].add(value)


def check_undefined_msg_type(
    proto_dict,
    actual_protocol,
    message_type_str,
    field,
    message_type,
    invalid_range=(0xFFFF, 0xFFFF),
    invalid_values=[],
):
    """Check if message type falls inside invalid range or is in the list of invalid values."""
    if invalid_range[0] <= message_type <= invalid_range[1] or message_type in invalid_values:
        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Message", field, message_type_str)
        return True
    return False


def check_undefined_attributes(
    proto_dict,
    actual_protocol,
    message_type_str,
    field,
    attributes,
    invalid_range=(0xFFFF, 0xFFFF),
    invalid_values=[],
):
    """Check if attributes fall inside invalid range or are in the list of invalid values."""
    for attr_type in attributes:
        attr_type_int = int(attr_type, 16)
        if invalid_range[0] <= attr_type_int <= invalid_range[1] or attr_type_int in invalid_values:
            mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Attributes", field, attr_type)
            return True
    return False


def check_invalid_stun_attributes(
    proto_dict,
    actual_protocol,
    message_type_str,
    layer,
    attributes,
    attr_lengths,
):
    """Check if attributes are invalid based on their values."""

    check = False
    for i in range(len(attributes)):
        attr = attributes[i]
        length = attr_lengths[i]
        match attr:
            case 0x8023:
                field = "stun.att.family"
                proto_family = layer.att_family.all_fields
                for family in proto_family:
                    if family.hex_value == 0:
                        value = family
                        check = True
                        break
                if check:
                    break
            # case 0x802b:
            #     pass
            case 0x0024:
                if message_type_str == "0x0101":
                    field = "stun.att.type"
                    value = "0x0024"
                    check = True
                    break
            case 0x0022:
                if length != 8:
                    field = "stun.att.length"
                    value = length
                    check = True
                    break
            case 0x000C:
                channel_number = layer.att_channelnum.all_fields
                for cnum in channel_number:
                    if not (0x4000 <= cnum.hex_value <= 0x4FFF):
                        field = "stun.att.channelnum"
                        value = cnum
                        check = True
                        break
                if check:
                    break
            case _:
                pass

    if check:
        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Attributes", field, value)
        return True
    return False


def check_compliance(protocol_compliance, packet, target_protocol, actual_protocol, log, target_protocols, decode_as={}):
    global packet_number, prev_packet_number, connection_id, ssrc
    packet_number = int(packet.number)
    if prev_packet_number > packet_number:
        connection_id = set()
        ssrc = set()

    if "TCP" in packet:
        transport_protocol = "TCP"
        payload_length = int(packet.tcp.len)
    elif "UDP" in packet:
        transport_protocol = "UDP"
        payload_length = int(packet.udp.length)

    proto_dict = protocol_compliance[transport_protocol]
    initialize_protocol(proto_dict, actual_protocol)

    layers = [layer for layer in packet.layers if layer.layer_name == target_protocol.lower()]
    validity_checks = [True] * len(layers)
    additional_protocols = []
    for i in range(len(layers)):
        layer = layers[i]
        try:
            if target_protocol in ["WASP", "STUN", "CLASSICSTUN"]:
                if layer.length.hex_value > payload_length:
                    raise Exception(f"STUN message length exceeds payload length")

                # this cannot detect the content inside DATA attribute (e.g., cascaded STUN)
                if hasattr(layer, "channel"):
                    add_message_type(proto_dict, actual_protocol, "channel")
                    channel_number = layer.channel.hex_value
                    if not (0x4000 <= channel_number <= 0x4FFF):
                        mark_non_compliance(proto_dict, actual_protocol, "channel", "Invalid Header", "stun.channel", layer.channel)
                    continue
                else:
                    message_type_str = layer.type
                    add_message_type(proto_dict, actual_protocol, message_type_str)
                    message_type = int(message_type_str, 16)
                    if check_undefined_msg_type(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        "stun.type",
                        message_type,
                        (0x0020, 0x007F),
                    ):
                        continue
                    if check_undefined_msg_type(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        "stun.type",
                        message_type,
                        (0x0200, 0xFFFF),
                    ):
                        continue

                if hasattr(layer, "cookie"):  # if not, this is a CLASSICSTUN packet
                    if layer.cookie.hex_value != 0x2112A442:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header", "stun.cookie", layer.cookie)
                        continue

                if layer.id.hex_value == 0:
                    mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header", "stun.id", layer.id)
                    continue

                if hasattr(layer, "unknown_attribute"):
                    # mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Attributes", "stun.unknown_attribute", layer.unknown_attribute)
                    mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Attributes", "stun.att.type", layer.unknown_attribute.split(" ")[-1])
                    continue

                if hasattr(layer, "att_type"):
                    # attributes = [int("0x" + p.raw_value, 16) for p in layer.att_type.all_fields]
                    attributes = ["0x" + p.raw_value for p in layer.att_type.all_fields]
                    attr_lengths = [int("0x" + p.raw_value, 16) for p in layer.att_length.all_fields]

                    if "0x0013" in attributes:  # if DATA attribute is present, we need to parse the content inside
                        hex_payload = layer.value.raw_value
                        additional_protocols += parse_datagram(packet, hex_payload, protocol_compliance, log, target_protocols, decode_as=decode_as)
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        "stun.att.type",
                        attributes,
                        (0x0031, 0x7FFF),  # [0xdaba, 0x8008, 0x8007, 0x8024, 0xdabe, 0x0101, 0x0103]
                        [0, 2, 3, 4, 5, 7, 11, 14, 15, 16, 17, 31, 33, 35, 40, 41, 43, 44, 45, 46, 47, 48],
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        "stun.att.type",
                        attributes,
                        (0x8005, 0x8021),
                        [0x8024, 0x8026, 0x802F],
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        "stun.att.type",
                        attributes,
                        (0x8031, 0xBFFF),
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        "stun.att.type",
                        attributes,
                        (0xC004, 0xC055),
                        [0xC05F],  # 0xc057 is documented
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        "stun.att.type",
                        attributes,
                        (0xC061, 0xC06F),
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        "stun.att.type",
                        attributes,
                        (0xC072, 0xFFFF),
                    ):
                        continue
                    if check_invalid_stun_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        layer,
                        attributes,
                        attr_lengths,
                    ):
                        continue

            if target_protocol == "RTP":
                if "ZOOM" in packet and hasattr(packet.zoom, "twortps") and packet.zoom.twortps == "1" and len(layers) < 2:
                    rtp2_ssrc = packet.zoom.rtp2ssrc.hex_value
                    if rtp2_ssrc not in ssrc:
                        ssrc.add(rtp2_ssrc)
                        raise Exception("New SSRC found in Zoom 2nd RTP")

                    rtp2_pt_str = packet.zoom.rtp2pt
                    add_message_type(proto_dict, actual_protocol, rtp2_pt_str)
                    rtp2_pt = int(rtp2_pt_str)

                    if check_undefined_msg_type(
                        proto_dict,
                        actual_protocol,
                        rtp2_pt_str,
                        "rtp.p_type",
                        rtp2_pt,
                        invalid_values=[2, 72],  # Type 1, 19, 73, 74, 75 76 (Reserved) are considered as compliant in Zoom 2nd rtp message
                    ):
                        continue
                    additional_protocols.append("RTP")

                if hasattr(layer, "ssrc") and layer.ssrc.hex_value not in ssrc:
                    ssrc.add(layer.ssrc.hex_value)
                    raise Exception("New SSRC found in RTP")

                if int(layer.version) != 2:
                    raise Exception(f"Incorrect RTP version ({int(layer.version)})")
                if not hasattr(layer, "p_type"):
                    raise Exception("No PT field found in RTP")
                # if hasattr(layer, "ext_profile") and layer.ext_len.hex_value > payload_length:
                #     raise Exception(f"RTP extension length exceeds payload length")
                if hasattr(layer, "payload") and layer.payload.raw_value[:18] == "0" * 18:  # for FaceTime
                    raise Exception("Invalid RTP payload bytes")

                message_type_str = layer.p_type
                add_message_type(proto_dict, actual_protocol, message_type_str)
                message_type = int(message_type_str)

                if check_undefined_msg_type(
                    proto_dict,
                    actual_protocol,
                    message_type_str,
                    "rtp.p_type",
                    message_type,
                    # (72, 76),
                    # [1, 2, 19],
                    invalid_values=[2, 72],  # Type 1, 19, 73, 74, 75, 76 (Reserved) are considered as compliant in Zoom 2nd rtp message
                ):
                    continue

                if layer.ssrc.hex_value == 0:  # sequence number and timestamp can be zero
                    mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header", "rtp.ssrc", layer.ssrc)
                    continue

                if hasattr(layer, "ext_profile"):
                    profile = layer.ext_profile
                    if profile[2:5] not in ["deb", "bed", "100"]:  #  "deb" is now considered as compliant
                        mark_non_compliance(
                            proto_dict,
                            actual_protocol,
                            message_type_str,
                            "Undefined Attributes",
                            "rtp.ext.profile",
                            profile,
                        )
                        continue
                    if layer.ext_len.hex_value > payload_length:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Attributes", "rtp.ext.len", layer.ext_len)
                        continue

                if hasattr(layer, "ext_rfc5285_id"):
                    ext_ids = [int(p.showname_value) for p in layer.ext_rfc5285_id.all_fields]
                    check = False
                    for ext_id in ext_ids:
                        if not (1 <= ext_id <= 14):
                            mark_non_compliance(
                                proto_dict,
                                actual_protocol,
                                message_type_str,
                                "Invalid Attributes",
                                "rtp.ext.rfc5285.id",
                                ext_id,
                            )
                            check = True
                            break
                    if check:
                        continue

            if target_protocol == "RTCP":
                if hasattr(layer, "senderssrc"):
                    if layer.senderssrc.hex_value not in ssrc:
                        ssrc.add(layer.senderssrc.hex_value)
                        raise Exception("New SSRC found in RTCP header")
                elif hasattr(layer, "ssrc_identifier"):
                    identifiers = [int(p.hex_value) for p in layer.ssrc_identifier.all_fields]
                    new_ssrc = False
                    ssrc_check = False
                    for identifier in identifiers:
                        if identifier not in ssrc:
                            ssrc.add(identifier)
                            new_ssrc = True
                        else:
                            ssrc_check = True
                    if new_ssrc and not ssrc_check:
                        raise Exception("New SSRC(s) found in RTCP payload")

                if int(layer.version) != 2:
                    raise Exception(f"Incorrect RTCP version ({int(layer.version)})")
                if not hasattr(layer, "pt"):
                    raise Exception("No PT field found in RTCP")
                # if (int(layer.length) + 1) * 4 > payload_length:
                #     raise Exception(f"RTCP message length exceeds payload length")
                # if hasattr(layer, "length_check_bad"):
                #     raise Exception("Invalid RTCP length field")
                if hasattr(packet, "zoom") and hasattr(packet.zoom, "twortps") and packet.zoom.twortps == "1":
                    raise Exception("Invalid RTCP in Zoom compound RTP packet")

                message_type_str = layer.pt
                add_message_type(proto_dict, actual_protocol, message_type_str)
                message_type = int(message_type_str)

                if check_undefined_msg_type(proto_dict, actual_protocol, message_type_str, "rtcp.pt", message_type, invalid_values=[0, 192, 193, 255]):
                    continue

                # if message_type == 205 and int(layer.rtpfb_fmt) in [17]:  # https://datatracker.ietf.org/doc/html/rfc4585#section-6.2
                #     mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header", "rtcp.rtpfb.fmt", layer.rtpfb_fmt)
                #     continue

                # if message_type == 206 and int(layer.psfb_fmt) in [14, 19]:  # https://datatracker.ietf.org/doc/html/rfc4585#section-6.3
                #     mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header", "rtcp.psfb.fmt", layer.psfb_fmt)
                #     continue

                if (int(layer.length) + 1) * 4 > payload_length or hasattr(layer, "length_check_bad"):
                    mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Attributes", "rtcp.length", layer.length)
                    continue

            if target_protocol == "QUIC":
                if not hasattr(layer, "header_form"):
                    raise Exception(f"QUIC header form not found")
                if packet.udp.payload.raw_value[: (7 * 2)].lower() == "53706f74556470":
                    raise Exception(f"Invalid QUIC with SpotUdp")

                if layer.header_form.hex_value == 1:  # check long header form
                    if int(layer.length) > payload_length:
                        raise Exception(f"QUIC long-header message length exceeds payload length")

                    message_type_str = layer.long_packet_type
                    add_message_type(proto_dict, actual_protocol, message_type_str)
                    message_type = int(message_type_str)

                    if message_type not in [0x00, 0x01, 0x02, 0x03]:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Message", "quic.long.packet_type", message_type)
                        continue

                    if layer.dcid.hex_value == 0:
                        connection_id.add(0)
                    else:
                        connection_id.add(layer.dcid.hex_value)
                    if layer.scid.hex_value == 0:
                        connection_id.add(0)
                    else:
                        connection_id.add(layer.scid.hex_value)

                    if layer.version.hex_value not in [
                        0x00000000,
                        0x00000001,
                        0x51303433,
                        0x51303436,
                        0x51303530,
                        0x6B3343CF,
                        0x709A50C4,
                    ]:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header", "quic.version", layer.version)
                        continue

                    if message_type == 0x00 and layer.token_length.hex_value != 0:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header", "quic.token_length", layer.token_length)
                        continue

                    if hasattr(layer, "frame_type"):
                        frame_types = [int(p.hex_value) for p in layer.frame_type.all_fields]
                        valid_type_range = [0, 17]
                        valid_type_values = [0x20, 0x173E, 0x26AB, 0x2AB2, 0x3127, 0x3128, 0x3129, 0x4752, 0xFF04DE1B, 0x0F739BBC1B666D05, 0x0F739BBC1B666D06, 0x4143414213370002]

                        check = False
                        for t in frame_types:
                            if not (valid_type_range[0] <= t <= valid_type_range[1] or t in valid_type_values):
                                mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Attributes", "quic.frame_type", t)
                                check = True
                                break
                        if check:
                            continue

                else:  # check short header form
                    message_type_str = "short"
                    add_message_type(proto_dict, actual_protocol, message_type_str)

                    if hasattr(layer, "dcid") and layer.dcid.hex_value not in connection_id:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header", "quic.dcid", layer.dcid)
                    if (not hasattr(layer, "dcid")) and 0 not in connection_id:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header", "quic.dcid", 0)

        except Exception as e:
            error_line_number = e.__traceback__.tb_lineno
            # msg = f"Error in parsing {target_protocol} layer in packet {packet.number}: {e} (line {error_line_number})"
            # log.append(msg)
            # print(msg)
            e_str = str(e)
            if e_str == "":
                e_str = type(e).__name__
            error = [target_protocol, e_str, int(packet.number), error_line_number]
            log.append(error)
            validity_checks[i] = False
    prev_packet_number = packet_number
    return validity_checks, additional_protocols
