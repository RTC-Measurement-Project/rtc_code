def initialize_protocol(proto_dict, actual_protocol):
    """Initialize compliance metrics for a protocol if not already initialized."""
    if proto_dict.get(actual_protocol) is None:
        proto_dict[actual_protocol] = {
            "Undefined Message": 0,
            "Invalid Header": 0,
            "Undefined Attributes": 0,
            "Invalid Attributes": 0,
            "Invalid Semantics": 0,
            "Message Types": set(),
            "Non-Compliant Types": {},
        }


def add_message_type(proto_dict, actual_protocol, message_type_str):
    """Add message type to protocol dictionary."""
    proto_dict[actual_protocol]["Message Types"].add(message_type_str)


def mark_non_compliance(proto_dict, actual_protocol, message_type_str, error_type):
    """Mark non-compliance and update counters for the given protocol."""
    proto_dict[actual_protocol][error_type] += 1
    if message_type_str not in proto_dict[actual_protocol]["Non-Compliant Types"]:
        proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str] = set()
    proto_dict[actual_protocol]["Non-Compliant Types"][message_type_str].add(error_type)


def check_undefined_attributes(
    proto_dict,
    actual_protocol,
    message_type_str,
    attributes,
    allowed_range=(0xFFFF, 0xFFFF),
    allowed_values=[],
):
    """Check if attributes fall outside allowed range or are in the list of allowed values."""
    if any(
        allowed_range[0] <= attr_type <= allowed_range[1] or attr_type in allowed_values
        for attr_type in attributes
    ):
        mark_non_compliance(
            proto_dict, actual_protocol, message_type_str, "Undefined Attributes"
        )
        return True
    return False

def check_invalid_attributes(
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
    initialize_protocol(proto_dict, actual_protocol)

    if "TCP" in packet:
        payload_length = int(packet.tcp.len)
    elif "UDP" in packet:
        payload_length = int(packet.udp.length)

    layers = [layer for layer in packet.layers if layer.layer_name == target_protocol.lower()]
    for layer in layers:
        try:
            if target_protocol == "WASP":
                if int(layer.message_length) > payload_length:
                    raise Exception(f"Message length {int(layer.message_length)} exceeds payload length {payload_length}")

                message_type_str = layer.message_type
                add_message_type(proto_dict, actual_protocol, message_type_str)
                message_type = int(message_type_str, 16)

                if message_type >= 0x0800:
                    mark_non_compliance(
                        proto_dict, actual_protocol, message_type_str, "Undefined Message"
                    )
                    return

                if hasattr(layer, "attribute_type"):
                    attributes = [
                        int("0x" + p.raw_value, 16)
                        for p in layer.attribute_type.all_fields
                    ]
                    check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        attributes,
                        (0x4000, 0x4100),
                    )
                    return

            if target_protocol in ["STUN", "CLASSICSTUN"]:
                if "0x" in layer.length:
                    if int(layer.length, 16) > payload_length:
                        raise Exception(f"Message length {int(layer.length, 16)} exceeds payload length {payload_length}")
                elif int(layer.length) > payload_length:
                    raise Exception(f"Message length {int(layer.length)} exceeds payload length {payload_length}")

                # this cannot detect the content instead DATA attribute (e.g., cascaded STUN)
                stun_protocol = layer
                if hasattr(stun_protocol, "channel"):
                    add_message_type(proto_dict, actual_protocol, "channel")
                else:
                    message_type_str = stun_protocol.type
                    add_message_type(proto_dict, actual_protocol, message_type_str)

                return_flag = True
                if "RTP"  in packet or "RTCP" in packet:
                    return_flag = False

                if hasattr(stun_protocol, "unknown_attribute"):
                    mark_non_compliance(
                        proto_dict, actual_protocol, message_type_str, "Undefined Attributes"
                    )
                    if return_flag: return

                if hasattr(stun_protocol, "att_type"):
                    attributes = [
                        int("0x" + p.raw_value, 16) for p in stun_protocol.att_type.all_fields
                    ]
                    attr_lengths = [
                        int("0x" + p.raw_value, 16)
                        for p in stun_protocol.att_length.all_fields
                    ]
                    if check_undefined_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        attributes,
                        (0x4000, 0x4100),
                        [0xdaba, 0x8008, 0x8007, 0x8024, 0xdabe, 0x0101, 0x0103], # 0xc057 is documented
                    ):
                        pass
                    elif check_invalid_attributes(
                        proto_dict,
                        actual_protocol,
                        message_type_str,
                        stun_protocol,
                        attributes,
                        attr_lengths,
                    ):
                        pass
                    if return_flag: return

            if target_protocol == "RTP":
                message_type_str = layer.p_type
                add_message_type(proto_dict, actual_protocol, message_type_str)

                if hasattr(layer, "ext_profile"):
                    if int(layer.ext_len) > payload_length:
                        raise Exception(f"RTP extension length {int(layer.ext_len)} exceeds payload length {payload_length}")
                    profile = layer.ext_profile
                    if profile[2:5] not in ["deb", "bed", "100"]:  #  "deb" is now considered as compliant
                        mark_non_compliance(
                            proto_dict,
                            actual_protocol,
                            message_type_str,
                            "Undefined Attributes",
                        )
                        return

            if target_protocol == "RTCP":
                if int(layer.version) != 2:
                    raise Exception(f"Incorrect RTCP version ({int(layer.version)})")
                if not hasattr(layer, "pt"):
                    raise Exception("No PT field found in RTCP")
                if (int(layer.length)+1)*4 > payload_length:
                    raise Exception(f"Message length {(int(layer.length)+1)*4} exceeds payload length {payload_length}")
                message_type_str = layer.pt
                add_message_type(proto_dict, actual_protocol, message_type_str)
                payload_type = int(message_type_str)

                if payload_type == 205 and int(layer.rtpfb_fmt) in [17]:
                    mark_non_compliance(
                        proto_dict, actual_protocol, message_type_str, "Invalid Header"
                    )
                    return

                if payload_type == 206 and int(layer.psfb_fmt) in [14, 19]:
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
    return
