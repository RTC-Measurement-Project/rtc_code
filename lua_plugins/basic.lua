-- Create a new dissector
local basic_proto = Proto("basic", "STUN Protocol")

local bs_rtcp_proto = Proto("bs_rtcp", "RTCP Protocol")
local f2 = bs_rtcp_proto.fields
f2.rem_len = ProtoField.uint32("bs_rtcp.rem_len", "Remaining Length", base.DEC)
f2.rtcp_len = ProtoField.uint32("bs_rtcp.rtcp_len", "RTCP Length", base.DEC)
f2.e_flag = ProtoField.uint8("bs_rtcp.e_flag", "Encrypt Flag", base.DEC)
f2.srtcp_idx = ProtoField.uint16("bs_rtcp.srtcp_idx", "SRTCP Index", base.DEC)
f2.auth_tag = ProtoField.bytes("bs_rtcp.auth_tag", "Authentication Tag")

-- Main dissector function for the basic protocol
function basic_proto.dissector(buffer, pinfo, tree)
    -- Read the first byte to determine the type of message.
    -- "0" is the starting index.
    -- "1" is the length of reading bytes including starting index.
    -- ":uint()" converts bytes in buffer segment to unsigned integer value.
    local msg_type = buffer(0,1):uint()

    local channel_number = buffer(0,2):uint()
    if (channel_number >= 0x4000 and channel_number <= 0x4FFF) then
        Dissector.get("stun-udp"):call(buffer, pinfo, tree)
        payload_type = buffer(4,1):uint()
        if (payload_type == 0x90) then
            Dissector.get("rtp"):call(buffer(4):tvb(), pinfo, tree)
        else
            local t = tree:add(bs_rtcp_proto, buffer(), "RTCP Protocol")
            pinfo.cols.protocol = "bs_rtcp"
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
        end
        return
    end

    -- Check if the type indicates an RTP packet.
    if (msg_type >= 0x80) then
        if (msg_type == 0x90) then
            Dissector.get("rtp"):call(buffer, pinfo, tree)
        else
            local t = tree:add(bs_rtcp_proto, buffer(), "RTCP Protocol")
            pinfo.cols.protocol = "bs_rtcp"
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
    if (msg_type <= 0x0310) then
        -- Hand over the packet to the STUN dissector and stop processing.
        Dissector.get("stun-udp"):call(buffer, pinfo, tree)
        return
    end
end

-- Register the dissector to handle UDP port 3478
DissectorTable.get("udp.port"):add(3478, basic_proto)
DissectorTable.get("udp.port"):add(40003, basic_proto)
DissectorTable.get("udp.port"):add_for_decode_as(basic_proto)
