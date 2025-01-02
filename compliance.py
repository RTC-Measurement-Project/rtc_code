from collections import defaultdict

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
            "Message Types": set(),
            "Non-Compliant Types": {},
        }


def parse_datagram(hex_payload: str):
    pass


def add_message_type(proto_dict, actual_protocol, message_type_str):
    """Add message type to protocol dictionary."""
    proto_dict[actual_protocol]["Message Types"].add(message_type_str)


def mark_non_compliance(proto_dict, actual_protocol, message_type_str, error_type):
    """Mark non-compliance and update counters for the given protocol."""
    global packet_number
    proto_dict[actual_protocol][error_type + " Messages"] += 1
    proto_dict[actual_protocol][error_type + " Packets"].add(packet_number)
    if message_type_str not in proto_dict[actual_protocol]["Non-Compliant Types"]:
        proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str] = set()
    proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str].add(error_type)


# def mark_non_compliance(proto_dict, actual_protocol, message_type_str, error_type, error_details):
#     """Mark non-compliance and update counters for the given protocol."""
#     global packet_number
#     proto_dict[actual_protocol][error_type + " Messages"] += 1
#     proto_dict[actual_protocol][error_type + " Packets"].add((packet_number, error_details))
#     if message_type_str not in proto_dict[actual_protocol]["Non-Compliant Types"]:
#         proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str] = defaultdict(set)
#     proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str][error_type].add(error_details)


def check_undefined_msg_type(
    proto_dict,
    actual_protocol,
    message_type_str,
    message_type,
    invalid_range=(0xFFFF, 0xFFFF),
    invalid_values=[],
):
    """Check if message type falls inside invalid range or is in the list of invalid values."""
    if invalid_range[0] <= message_type <= invalid_range[1] or message_type in invalid_values:
        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Message")
        return True
    return False


def check_undefined_attributes(
    proto_dict,
    actual_protocol,
    message_type_str,
    attributes,
    invalid_range=(0xFFFF, 0xFFFF),
    invalid_values=[],
):
    """Check if attributes fall inside invalid range or are in the list of invalid values."""
    if any(invalid_range[0] <= attr_type <= invalid_range[1] or attr_type in invalid_values for attr_type in attributes):
        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Attributes")
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
                proto_family = layer.att_family.all_fields
                for family in proto_family:
                    if family.hex_value == 0:
                        check = True
                        break
                if check:
                    break
            # case 0x802b:
            #     pass
            case 0x0024:
                if message_type_str == "0x0101":
                    check = True
                    break
            case 0x0022:
                if length != 8:
                    check = True
                    break
            case 0x000C:
                channel_number = layer.att_channelnum.all_fields
                for cnum in channel_number:
                    if not (0x4000 <= cnum.hex_value <= 0x4FFF):
                        check = True
                        break
                if check:
                    break
            case _:
                pass

    if check:
        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Attributes")
        return True
    return False


def check_compliance(proto_dict, packet, target_protocol, actual_protocol, log):
    global packet_number, prev_packet_number, connection_id, ssrc
    packet_number = int(packet.number)
    if prev_packet_number > packet_number:
        connection_id = set()
        ssrc = set()

    initialize_protocol(proto_dict, actual_protocol)

    if "TCP" in packet:
        payload_length = int(packet.tcp.len)
    elif "UDP" in packet:
        payload_length = int(packet.udp.length)

    layers = [layer for layer in packet.layers if layer.layer_name == target_protocol.lower()]
    validity_checks = [True] * len(layers)
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
                        mark_non_compliance(proto_dict, actual_protocol, "channel", "Invalid Header")
                    continue
                else:
                    message_type_str = layer.type
                    add_message_type(proto_dict, actual_protocol, message_type_str)
                    message_type = int(message_type_str, 16)
                    if check_undefined_msg_type(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        message_type,
                        (0x0020, 0x007F),
                    ):
                        continue
                    if check_undefined_msg_type(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        message_type,
                        (0x0200, 0xFFFF),
                    ):
                        continue

                if hasattr(layer, "cookie"):  # if not, this is a CLASSICSTUN packet
                    if layer.cookie.hex_value != 0x2112A442:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header")
                        continue

                if layer.id.hex_value == 0:
                    mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header")
                    continue

                if hasattr(layer, "unknown_attribute"):
                    mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Attributes")
                    continue

                if hasattr(layer, "att_type"):
                    attributes = [int("0x" + p.raw_value, 16) for p in layer.att_type.all_fields]
                    attr_lengths = [int("0x" + p.raw_value, 16) for p in layer.att_length.all_fields]
                    if 0x0013 in attributes:  # if DATA attribute is present, we need to parse the content inside
                        pass
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        attributes,
                        (0x0031, 0x7FFF),  # [0xdaba, 0x8008, 0x8007, 0x8024, 0xdabe, 0x0101, 0x0103]
                        [0, 2, 3, 4, 5, 7, 11, 14, 15, 16, 17, 31, 33, 35, 40, 41, 43, 44, 45, 46, 47, 48],
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        attributes,
                        (0x8005, 0x8021),
                        [0x8024, 0x8026, 0x802F],
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        attributes,
                        (0x8031, 0xBFFF),
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        attributes,
                        (0xC004, 0xC055),
                        [0xC05F],  # 0xc057 is documented
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        attributes,
                        (0xC061, 0xC06F),
                    ):
                        continue
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
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
                if hasattr(layer, "ssrc") and layer.ssrc.hex_value not in ssrc:
                    ssrc.add(layer.ssrc.hex_value)
                    raise Exception("New SSRC found in RTP")

                if int(layer.version) != 2:
                    raise Exception(f"Incorrect RTP version ({int(layer.version)})")
                if not hasattr(layer, "p_type"):
                    raise Exception("No PT field found in RTP")
                # if hasattr(layer, "ext_profile") and layer.ext_len.hex_value > payload_length:
                #     raise Exception(f"RTP extension length exceeds payload length")
                if layer.payload.raw_value[:18] == "0" * 18:
                    raise Exception("Invalid RTP payload bytes")

                message_type_str = layer.p_type
                add_message_type(proto_dict, actual_protocol, message_type_str)
                message_type = int(message_type_str)

                if check_undefined_msg_type(
                    proto_dict,
                    actual_protocol,
                    message_type_str,
                    message_type,
                    (72, 76),
                    [1, 2],  # Type 19 (Reserved) is considered as compliant
                ):
                    continue

                if layer.ssrc.hex_value == 0:  # sequence number and timestamp can be zero
                    mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header")
                    continue

                if hasattr(layer, "ext_profile"):
                    profile = layer.ext_profile
                    if profile[2:5] not in ["deb", "bed", "100"]:  #  "deb" is now considered as compliant
                        mark_non_compliance(
                            proto_dict,
                            actual_protocol,
                            message_type_str,
                            "Undefined Attributes",
                        )
                        continue
                    if layer.ext_len.hex_value > payload_length:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Attributes")
                        continue

                if hasattr(layer, "ext_rfc5285_id"):
                    ext_ids = [int(p.showname_value) for p in layer.ext_rfc5285_id.all_fields]
                    if not all(1 <= ext_id <= 14 for ext_id in ext_ids):
                        mark_non_compliance(
                            proto_dict,
                            actual_protocol,
                            message_type_str,
                            "Invalid Attributes",
                        )
                        continue

            if target_protocol == "RTCP":
                if hasattr(layer, "senderssrc") and layer.senderssrc.hex_value not in ssrc:
                    ssrc.add(layer.senderssrc.hex_value)
                    raise Exception("New SSRC found in RTCP")

                if int(layer.version) != 2:
                    raise Exception(f"Incorrect RTCP version ({int(layer.version)})")
                if not hasattr(layer, "pt"):
                    raise Exception("No PT field found in RTCP")
                # if (int(layer.length) + 1) * 4 > payload_length:
                #     raise Exception(f"RTCP message length exceeds payload length")
                # if hasattr(layer, "length_check_bad"):
                #     raise Exception("Invalid RTCP length field")

                message_type_str = layer.pt
                add_message_type(proto_dict, actual_protocol, message_type_str)
                message_type = int(message_type_str)

                if check_undefined_msg_type(proto_dict, actual_protocol, message_type_str, message_type, invalid_values=[0, 192, 193, 255]):
                    continue

                # if message_type == 205 and int(layer.rtpfb_fmt) in [17]:  # https://datatracker.ietf.org/doc/html/rfc4585#section-6.2
                #     mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header")
                #     continue

                # if message_type == 206 and int(layer.psfb_fmt) in [14, 19]:  # https://datatracker.ietf.org/doc/html/rfc4585#section-6.3
                #     mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header")
                #     continue

                if (int(layer.length) + 1) * 4 > payload_length or hasattr(layer, "length_check_bad"):
                    mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Attributes")
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
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Message")
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
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header")
                        continue

                    if message_type == 0x00 and layer.token_length.hex_value != 0:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header")
                        continue

                    if hasattr(layer, "frame_type"):
                        frame_types = [int(p.hex_value) for p in layer.frame_type.all_fields]
                        valid_type_range = [0, 17]
                        valid_type_values = [0x20, 0x173E, 0x26AB, 0x2AB2, 0x3127, 0x3128, 0x3129, 0x4752, 0xFF04DE1B, 0x0F739BBC1B666D05, 0x0F739BBC1B666D06, 0x4143414213370002]
                        if not all(valid_type_range[0] <= t <= valid_type_range[1] or t in valid_type_values for t in frame_types):
                            mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Undefined Attributes")
                            continue
                else:  # check short header form
                    message_type_str = "short"
                    add_message_type(proto_dict, actual_protocol, message_type_str)

                    if hasattr(layer, "dcid") and layer.dcid.hex_value not in connection_id:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header")
                    if (not hasattr(layer, "dcid")) and 0 not in connection_id:
                        mark_non_compliance(proto_dict, actual_protocol, message_type_str, "Invalid Header")

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
    return validity_checks
