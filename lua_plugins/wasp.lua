-- Create a new dissector
local wasp_proto = Proto("wasp", "WhatsApp STUN Protocol")

-- Define the fields of the protocol
local f = wasp_proto.fields
f.message_type = ProtoField.uint16("wasp.type", "Message Type", base.HEX)
f.message_length = ProtoField.uint16("wasp.length", "Message Length", base.DEC)
f.magic_cookie = ProtoField.uint32("wasp.cookie", "Magic Cookie (0x2112A442)", base.HEX)
f.transaction_id = ProtoField.bytes("wasp.id", "Transaction ID")
f.attribute_type = ProtoField.uint16("wasp.att_type", "Attribute Type", base.HEX)
f.attribute_length = ProtoField.uint16("wasp.att_length", "Attribute Length", base.DEC)
f.attribute_value = ProtoField.bytes("wasp.value", "Attribute Value")
f.attribute_padding = ProtoField.bytes("wasp.att_padding", "Attribute Padding")

local wa_rtcp_proto = Proto("wa_rtcp", "WhatsApp RTCP Protocol")
local f2 = wa_rtcp_proto.fields
f2.rem_len = ProtoField.uint32("wa_rtcp.rem_len", "Remaining Length", base.DEC)
f2.rtcp_len = ProtoField.uint32("wa_rtcp.rtcp_len", "RTCP Length", base.DEC)
f2.e_flag = ProtoField.uint8("wa_rtcp.e_flag", "Encrypt Flag", base.DEC)
f2.srtcp_idx = ProtoField.uint16("wa_rtcp.srtcp_idx", "SRTCP Index", base.DEC)
f2.auth_tag = ProtoField.bytes("wa_rtcp.auth_tag", "Authentication Tag")

-- Main dissector function for the WASP protocol
function wasp_proto.dissector(buffer, pinfo, tree)
    -- Read the first byte to determine the type of message.
    -- "0" is the starting index.
    -- "1" is the length of reading bytes including starting index.
    -- ":uint()" converts bytes in buffer segment to unsigned integer value.
    local msg_type = buffer(0,1):uint()

    local channel_number = buffer(0,2):uint()
    if (channel_number >= 0x4000 and channel_number <= 0x4FFF) then
        Dissector.get("stun-udp"):call(buffer, pinfo, tree)
        payload_type = buffer(4,1):uint()
        -- Dissector.get("rtp"):call(buffer(4):tvb(), pinfo, tree)
        -- return
        if (payload_type >= 0x80) then
            if (payload_type == 0x90) then
                Dissector.get("rtp"):call(buffer(4):tvb(), pinfo, tree)
            else
                local t = tree:add(wa_rtcp_proto, buffer(), "WhatsApp RTCP Protocol")
                pinfo.cols.protocol = "wa_rtcp"
                buf_len = buffer:len()
                flag_idx = buffer(buf_len - 14, 4)
                first_bit = (flag_idx:uint() & 0x80000000) >> 31
                remaining = flag_idx:uint() & 0x7FFFFFFF
                rtcp_length = (buffer(4 + 2, 2):uint() + 1) * 4
                remaining_length = buf_len - 4 - rtcp_length
                t:add(f2.e_flag, first_bit)
                t:add(f2.srtcp_idx, remaining)
                t:add(f2.auth_tag, buffer(buf_len - 10, 10))
                t:add(f2.rtcp_len, rtcp_length)
                t:add(f2.rem_len, remaining_length):append_text(" (Over 14 bytes means 2+ RTCP messages)")
                Dissector.get("srtcp"):call(buffer(4):tvb(), pinfo, tree)

                -- raw_length = (buffer(4 + 2, 2):uint() + 1) * 4
                -- check = buffer(buffer:len() - 14, 2):uint()
                -- content = buffer(4, buffer:len() - 14 - 4) -- last 14 bytes are proprietary extension
                -- if check == 0x8000 then -- SRTCP: Encrypt flag + first part of Index
                --     -- print(check .. " " .. raw_length .. " " .. content:len())
                --     Dissector.get("srtcp"):call(content:tvb(), pinfo, tree)
                -- else
                --     Dissector.get("data"):call(buffer(4):tvb(), pinfo, tree)
                -- end
            end
        elseif (payload_type >= 0x10) then
            Dissector.get("data"):call(buffer(4):tvb(), pinfo, tree)
        elseif (payload_type <= 0x03) then
            Dissector.get("stun-udp"):call(buffer(4):tvb(), pinfo, tree)
        end
        return
    end

    -- Check if the type indicates an RTP packet.
    if (msg_type >= 0x80) then
        -- Dissector.get("rtp"):call(buffer(4):tvb(), pinfo, tree)
        -- return
        if (msg_type == 0x90) then
            Dissector.get("rtp"):call(buffer, pinfo, tree)
        else
            local t = tree:add(wa_rtcp_proto, buffer(), "WhatsApp RTCP Protocol")
            pinfo.cols.protocol = "wa_rtcp"
            buf_len = buffer:len()
            flag_idx = buffer(buf_len - 14, 4)
            first_bit = (flag_idx:uint() & 0x80000000) >> 31
            remaining = flag_idx:uint() & 0x7FFFFFFF
            rtcp_length = (buffer(2, 2):uint() + 1) * 4
            remaining_length = buf_len - rtcp_length
            t:add(f2.e_flag, first_bit)
            t:add(f2.srtcp_idx, remaining)
            t:add(f2.auth_tag, buffer(buf_len - 10, 10))
            t:add(f2.rtcp_len, rtcp_length)
            t:add(f2.rem_len, remaining_length):append_text(" (Over 14 bytes means 2+ RTCP messages)")
            Dissector.get("srtcp"):call(buffer, pinfo, tree)

            -- raw_length = (buffer(2, 2):uint() + 1) * 4
            -- check = buffer(buffer:len() - 14, 2):uint()
            -- content = buffer(0, buffer:len() - 14) -- last 14 bytes are proprietary extension
            -- if check == 0x8000 then -- SRTCP: Encrypt flag + first part of Index
            --     print(check .. " " .. raw_length .. " " .. content:len())
            --     Dissector.get("srtcp"):call(content:tvb(), pinfo, tree)
            -- else
            --     Dissector.get("data"):call(buffer, pinfo, tree)
            -- end
        end
        return
    end

    -- Check if the type indicates a DATA packet (>0x10).
    if (msg_type >= 0x10) then
        -- Hand over the packet to the DATA dissector and stop processing.
        Dissector.get("data"):call(buffer, pinfo, tree)
        return
    end

    -- Check if the type indicates a STUN packet.
    if (msg_type < 0x03) then
        -- Hand over the packet to the STUN dissector and stop processing.
        Dissector.get("stun-udp"):call(buffer, pinfo, tree)
        return
    end

    -- Set the protocol column to display WASP.
    pinfo.cols.protocol = "wasp"

    -- Read the message type from the first two bytes.
    local msg_type = buffer(0,2):uint()
    -- Add a subtree for WASP protocol data, including the message name.
    local subtree = tree:add(wasp_proto, buffer(), "WASP: " .. get_message_name(msg_type))
    -- Add various fields to the subtree.
    -- Each field is parsed from a specific section of the buffer.
    -- e.g. "buffer(8,12)" is to read 12 bytes starting from index 8.
    subtree:add(f.message_type, buffer(0,2))
    subtree:add(f.message_length, buffer(2,2))
    subtree:add(f.magic_cookie, buffer(4,4))
    subtree:add(f.transaction_id, buffer(8,12))

    -- Initialize offset for attribute parsing
    local offset = 20 -- Start of the first attribute
    -- Loop through all attributes in the packet
    while offset < buffer:len() do
        local attr_type = buffer(offset, 2):uint()
        -- Skip processing if attribute type is 0x0000 (commonly used as padding or end marker)
        if (attr_type == 0x0000) then
            offset = offset + 2
            goto continue_position
        end

        -- Read attribute length and value
        local attr_length = buffer(offset + 2, 2):uint()
        local attr_value = buffer(offset + 4, attr_length)

        -- Calculate padding to align attributes on 4-byte boundaries
        local correct_length = math.ceil(attr_length / 4) * 4
        local padding_length = correct_length - attr_length
        local attr_padding = buffer(offset + 4 + attr_length, padding_length)

        -- Add attribute data to the subtree, including type, length, value, and padding
        local attr_tree = subtree:add(buffer(offset, 4 + correct_length), "Attribute: " .. get_attribute_name(attr_type))
        attr_tree:add(f.attribute_type, buffer(offset, 2))
        attr_tree:add(f.attribute_length, buffer(offset + 2, 2))
        attr_tree:add(f.attribute_value, attr_value)
        attr_tree:add(f.attribute_padding, attr_padding)

        -- Update offset to the next attribute
        offset = offset + 4 + correct_length
        ::continue_position::
    end
end


-- Helper function to get attribute names based on their numeric type
function get_attribute_name(attr_type)
    -- Define a table mapping attribute types to their names
    local attribute_names = {
        -- Followings are documented attributes from IETF/Expert review
        [0x0001] = "MAPPED-ADDRESS",
        [0x0006] = "USERNAME",
        [0x0008] = "MESSAGE-INTEGRITY",
        [0x0009] = "ERROR-CODE",
        [0x000A] = "UNKNOWN-ATTRIBUTES",
        [0x000C] = "CHANNEL-NUMBER",
        [0x000D] = "LIFETIME",
        [0x0012] = "XOR-PEER-ADDRESS",
        [0x0013] = "DATA",
        [0x0015] = "NONCE",
        [0x0016] = "XOR-RELAYED-ADDRESS",
        [0x0017] = "REQUESTED-ADDRESS-FAMILY",
        [0x0018] = "EVEN-PORT",
        [0x0019] = "REQUESTED-TRANSPORT",
        [0x001A] = "DONT-FRAGMENT",
        [0x001B] = "ACCESS-TOKEN",
        [0x001C] = "MESSAGE-INTEGRITY-SHA256",
        [0x001D] = "PASSWORD-ALGORITHM",
        [0x001E] = "USERHASH",
        [0x0020] = "XOR-MAPPED-ADDRESS",
        -- [0x0022] = "RESERVATION-TOKEN",
        [0x0022] = "(FB Modify) Stream Subscription",
        [0x0024] = "PRIORITY",
        [0x0025] = "USE-CANDIDATE",
        [0x0026] = "PADDING",
        [0x0027] = "RESPONSE-PORT",
        [0x002A] = "CONNECTION-ID",
        [0x8000] = "ADDITIONAL-ADDRESS-FAMILY",
        [0x8001] = "ADDRESS-ERROR-CODE",
        [0x8002] = "PASSWORD-ALGORITHMS",
        [0x8003] = "ALTERNATE-DOMAIN",
        [0x8004] = "ICMP",
        [0x8022] = "SOFTWARE",
        [0x8023] = "ALTERNATE-SERVER",
        [0x8025] = "TRANSACTION_TRANSMIT_COUNTER",
        [0x8027] = "CACHE-TIMEOUT",
        [0x8028] = "FINGERPRINT",
        [0x8029] = "ICE-CONTROLLED",
        [0x802A] = "ICE-CONTROLLING",
        -- [0x802B] = "RESPONSE-ORIGIN",
        [0x802B] = "(FB Modify) Client Stats",
        [0x802C] = "OTHER-ADDRESS",
        [0x802D] = "ECN-CHECK-STUN",
        [0x802E] = "THIRD-PARTY-AUTHORIZATION",
        [0x8030] = "MOBILITY-TICKET",
        [0xC000] = "(Extra) CISCO-STUN-FLOWDATA",
        [0xC001] = "(Extra) ENF-FLOW-DESCRIPTION",
        [0xC002] = "(Extra) ENF-NETWORK-STATUS",
        [0xC003] = "(Extra) CISCO-WEBEX-FLOW-INFO",
        [0xC056] = "(Extra) CITRIX-TRANSACTION-ID",
        [0xC057] = "(Extra) GOOG-NETWORK-INFO",
        [0xC058] = "(Extra) GOOG-LAST-ICE-CHECK-RECEIVED",
        [0xC059] = "(Extra) GOOG-MISC-INFO",
        [0xC05A] = "(Extra) GOOG-OBSOLETE-1",
        [0xC05B] = "(Extra) GOOG-CONNECTION-ID",
        [0xC05C] = "(Extra) GOOG-DELTA",
        [0xC05D] = "(Extra) GOOG-DELTA-ACK",
        [0xC05E] = "(Extra) GOOG-DELTA-SYNC-REQ",
        [0xC060] = "(Extra) GOOG-MESSAGE-INTEGRITY-32",

        -- Followings are proprietary attributes
        [0x4000] = "(FB) Relay Token",
        [0x4002] = "(FB) Server Timestamp",
        [0x4003] = "(FB) Reflexive Payload",
        [0x4004] = "(FB) Padding",
        [0x4005] = "(FB) RTP packet",
        [0x4006] = "(FB) E2E Time Info",
        [0x4007] = "(FB) Response Payload Size",
        [0x4021] = "(FB) Receiver Subscription",
        [0x4023] = "(FB) Sender Subscription",
        [0x4024] = "(FB) Stream Descriptor",
        [0xCAFE] = "(FB) FB Reason Code / Client Signal",
        [0xFF00] = "(FB) Retransmit-count",
    }

    -- Return the attribute name or "Unknown" if not found
    return attribute_names[attr_type] or "Unknown"
end

-- Helper function to get message names based on their numeric type
function get_message_name(msg_type)
    -- Define a table mapping message types to their names
    local message_names = {
        -- Followings are documented type from standards/WebRTC
        [0x0001] = "Binding Request",
        [0x0101] = "Binding Response",
        [0x0111] = "Binding Error Response",
        [0x0003] = "Allocate Request",
        [0x0103] = "Allocate Response",
        [0x0113] = "Allocate Error Response",
        [0x0004] = "Refresh Request",
        [0x0104] = "Refresh Response",
        [0x0114] = "Refresh Error Response",
        [0x0006] = "Send Indication",
        [0x0007] = "Data Indication",
        [0x0008] = "CreatePermission Request",
        [0x0108] = "CreatePermission Response",
        [0x0118] = "CreatePermission Error Response",
        [0x0009] = "ChannelBind Request",
        [0x0109] = "ChannelBind Response",
        [0x0119] = "ChannelBind Error Response",
        [0x000A] = "Connect",
        [0x000B] = "ConnectionBind",
        [0x000C] = "ConnectionAttempt",
        [0x0080] = "(Extra) GOOG-PING Request",

        -- Followings are proprietary attributes
        [0x0800] = "(FB) Call End Request",
        [0x0801] = "(FB) Ping Request",
        [0x0802] = "(FB) Pong Response",
        [0x0803] = "(FB) Probing Allocate Request",
        [0x0804] = "(FB) Stateful Ping Request",
        [0x0805] = "(FB) Stateful Ping Response",
    }

    -- Return the message name or "Unknown" if not found
    return message_names[msg_type] or "Unknown"
end

-- Register the dissector to handle UDP port 3478
DissectorTable.get("udp.port"):add(3478, wasp_proto)
DissectorTable.get("udp.port"):add(40003, wasp_proto)
DissectorTable.get("udp.port"):add_for_decode_as(wasp_proto)
