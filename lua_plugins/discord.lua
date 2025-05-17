local discord_proto = Proto("discord", "Discord Protocol")
local f = discord_proto.fields
f.type = ProtoField.new("Type", "discord.type", ftypes.BYTES)
f.length = ProtoField.new("Length", "discord.length", ftypes.UINT16)
f.number = ProtoField.new("Number", "discord.number", ftypes.UINT32)
f.addr = ProtoField.new("Address", "discord.addr", ftypes.BYTES)
f.port = ProtoField.new("Port", "discord.port", ftypes.UINT16)
f.count = ProtoField.new("Counter", "discord.count", ftypes.UINT32)
f.unknown = ProtoField.new("Unknown", "discord.unknown", ftypes.BYTES)

local dc_rtcp_proto = Proto("dc_rtcp", "Discord RTCP Protocol")
local f2 = dc_rtcp_proto.fields
f2.rem_len = ProtoField.new("Remaining Length", "dc_rtcp.rem_len", ftypes.UINT32)
f2.rtcp_len = ProtoField.new("RTCP Length", "dc_rtcp.rtcp_len", ftypes.UINT32)
f2.seq = ProtoField.new("Sequence Number", "dc_rtcp.seq", ftypes.UINT16)
f2.dir = ProtoField.new("Direction", "dc_rtcp.dir", ftypes.UINT8, nil, base.HEX)

local function remove_trailing_zeros(buf)
    local length = buf:len()
    local end_index = length
    while end_index > 0 and buf(end_index - 1, 1):uint() == 0 do
        end_index = end_index - 1
    end
    if end_index == 0 then
        return buf(0, 1)
    end
    return buf(0, end_index)
end

local function flip_bytes(buf)
    local length = buf:len()
    local flipped_buf = ByteArray.new()
    for i = length - 1, 0, -1 do
        flipped_buf:append(buf(i, 1):bytes())
    end
    return flipped_buf
end

function discord_proto.dissector(buf, pkt, tree)
    local msg_type = buf(0,2):uint()
    local first_byte = buf(0,1):uint()

    if (first_byte >= 128 and first_byte <= 191) then
        if first_byte == 0x90 then
            Dissector.get("rtp"):call(buf, pkt, tree)
        else
            local t = tree:add(dc_rtcp_proto, buf(), "Discord RTCP Protocol")
            pkt.cols.protocol = "dc_rtcp"
            buf_len = buf:len()
            direction = buf(buf_len-1,1)
            -- seq_num = remove_trailing_zeros(buf(buf_len-3,2))
            seq_num = flip_bytes(buf(buf_len-3,2)):uint()
            rtcp_length = (buf(2, 2):uint() + 1) * 4
            remaining_length = buf_len - rtcp_length
            if direction:uint() == 0x80 then
                t:add(f2.dir, direction):append_text(" (from client to server)")
            elseif direction:uint() == 0x00 then
                t:add(f2.dir, direction):append_text(" (from server to client)")
            else
                t:add(f2.dir, direction):append_text(" (unknown direction)")
            end
            t:add(f2.seq, seq_num)
            t:add(f2.rtcp_len, rtcp_length)
            t:add(f2.rem_len, remaining_length)

            Dissector.get("rtcp"):call(buf, pkt, tree)
        end
        return
    end

    local t = tree:add(discord_proto, buf(), "Discord Protocol")
    pkt.cols.protocol = "discord"
    if msg_type == 0x0001 or msg_type == 0x0002 then
        t:add(f.type, buf(0,2))
        t:add(f.length, buf(2,2))
        local payload_len = buf(2,2):uint()
        local payload = buf(4, payload_len)
        t:add(f.number, payload(0,4))
        t:add(f.addr, payload(4,64))
        t:add(f.port, payload(68,2))
    elseif msg_type == 0x1337 then
        t:add(f.type, buf(0,2))
        t:add(f.unknown, buf(2,2))
        -- counter = remove_trailing_zeros(buf(4,4))
        counter = flip_bytes(buf(4,4)):uint()
        t:add(f.count, counter)
    else
        Dissector.get("data"):call(buf, pkt, tree)
    end
end

for i = 50000, 50100 do
    DissectorTable.get("udp.port"):add(i, discord_proto)
end
DissectorTable.get("udp.port"):add_for_decode_as(discord_proto)
