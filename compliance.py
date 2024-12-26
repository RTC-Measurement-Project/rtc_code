packet_number = 0

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
        mark_non_compliance(
            proto_dict, actual_protocol, message_type_str, "Undefined Message"
        )
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
    if any(
        invalid_range[0] <= attr_type <= invalid_range[1] or attr_type in invalid_values
        for attr_type in attributes
    ):
        mark_non_compliance(
            proto_dict, actual_protocol, message_type_str, "Undefined Attributes"
        )
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
                if check: break
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
            case 0x000c:
                channel_number = layer.att_channelnum.all_fields
                for cnum in channel_number:
                    if not (0x4000 <= cnum.hex_value <= 0x4fff):
                        check = True
                        break
                if check: 
                    break
            case _:
                pass

    if check:
        mark_non_compliance(
            proto_dict, actual_protocol, message_type_str, "Invalid Attributes"
        )
        return True
    return False


def check_compliance(proto_dict, packet, target_protocol, actual_protocol, log):
    global packet_number
    packet_number = packet.number
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
                    raise Exception(f"STUN Message length exceeds payload length")

                # this cannot detect the content inside DATA attribute (e.g., cascaded STUN)
                if hasattr(layer, "channel"):
                    add_message_type(proto_dict, actual_protocol, "channel")
                    channel_number = layer.channel.hex_value
                    if not (0x4000 <= channel_number <= 0x4fff):
                        mark_non_compliance(
                            proto_dict, actual_protocol, "channel", "Invalid Header"
                        )
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

                if hasattr(layer, "cookie"): # if not, this is a CLASSICSTUN packet
                    if layer.cookie.hex_value != 0x2112A442:
                        mark_non_compliance(
                            proto_dict, actual_protocol, message_type_str, "Invalid Header"
                        )
                        continue

                if layer.id.hex_value == 0:
                    mark_non_compliance(
                        proto_dict, actual_protocol, message_type_str, "Invalid Header"
                    )
                    continue

                if hasattr(layer, "unknown_attribute"):
                    mark_non_compliance(
                        proto_dict, actual_protocol, message_type_str, "Undefined Attributes"
                    )
                    continue

                if hasattr(layer, "att_type"):
                    attributes = [
                        int("0x" + p.raw_value, 16) for p in layer.att_type.all_fields
                    ]
                    attr_lengths = [
                        int("0x" + p.raw_value, 16)
                        for p in layer.att_length.all_fields
                    ]
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        attributes,
                        (0x0031, 0x7FFF), # [0xdaba, 0x8008, 0x8007, 0x8024, 0xdabe, 0x0101, 0x0103]
                        [0, 2, 3, 4, 5, 7, 11, 14, 15, 16, 17, 31, 33, 35, 40, 41, 43, 44, 45, 46, 47, 48] ,
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
                if int(layer.version) != 2:
                    raise Exception(f"Incorrect RTP version ({int(layer.version)})")
                if not hasattr(layer, "p_type"):
                    raise Exception("No PT field found in RTP")
                if hasattr(layer, "ext_profile") and layer.ext_len.hex_value > payload_length:
                    raise Exception(f"RTP extension length exceeds payload length")

                message_type_str = layer.p_type
                add_message_type(proto_dict, actual_protocol, message_type_str)
                message_type = int(message_type_str)

                if check_undefined_msg_type(
                    proto_dict,
                    actual_protocol,
                    message_type_str,
                    message_type,
                    (72, 76),
                    [1, 2, 19]
                ):
                    continue

                if layer.timestamp.hex_value == 0 or layer.ssrc.hex_value == 0:
                    mark_non_compliance(
                        proto_dict, actual_protocol, message_type_str, "Invalid Header"
                    )
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

            if target_protocol == "RTCP":
                if int(layer.version) != 2:
                    raise Exception(f"Incorrect RTCP version ({int(layer.version)})")
                if not hasattr(layer, "pt"):
                    raise Exception("No PT field found in RTCP")
                if (int(layer.length)+1)*4 > payload_length:
                    raise Exception(f"RTCP message length exceeds payload length")
                if hasattr(layer, "length_check_bad"):
                    raise Exception("Invalid RTCP length field")

                message_type_str = layer.pt
                add_message_type(proto_dict, actual_protocol, message_type_str)
                message_type = int(message_type_str)

                if check_undefined_msg_type(
                    proto_dict,
                    actual_protocol,
                    message_type_str,
                    message_type,
                    invalid_values=[0, 192, 193, 255]
                ):
                    continue

                if message_type == 205 and int(layer.rtpfb_fmt) in [17]:
                    mark_non_compliance(
                        proto_dict, actual_protocol, message_type_str, "Invalid Header"
                    )
                    continue

                if message_type == 206 and int(layer.psfb_fmt) in [14, 19]:
                    mark_non_compliance(
                        proto_dict, actual_protocol, message_type_str, "Invalid Header"
                    )
        except Exception as e:
            error_line_number = e.__traceback__.tb_lineno
            # msg = f"Error in parsing {target_protocol} layer in packet {packet.number}: {e} (line {error_line_number})"
            # log.append(msg)
            # print(msg)
            e_str = str(e)
            if e_str == "":
                e_str = type(e).__name__
            error = [target_protocol, e_str, packet.number, error_line_number]
            log.append(error)
            validity_checks[i] = False
    return validity_checks
