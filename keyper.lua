-- script-name: keyper.lua
-- Version: 0.9

local p_keyper = Proto("keyper","KeyperPlus HSM")

local pf_length     = ProtoField.uint32 ("keyper.length", "Length", base.DEC)
local pf_call_count = ProtoField.uint8  ("keyper.call_count", "Call Count", base.DEC)
local pf_call_offset   = ProtoField.uint32 ("keyper.call_offset", "Call Offset", base.HEX)

p_keyper.fields = {
  pf_length,
  pf_call_count,
  pf_call_offset,
  }


function p_keyper.dissector(tvbuf,pktinfo,root)

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("Keyper")

    local pktlen = tvbuf:reported_length_remaining()

    -- TODO: can't assume this frame is a whole message
    local tree = root:add(p_keyper, tvbuf:range(0,pktlen))

    tree:add(pf_length, tvbuf:range(0,4))
    -- TODO: read this value; we need it to find the offsets..
    tree:add(pf_call_count, tvbuf:range(4,1))

    -- TODO: this should be a loop for i = 0; i < call_count
    tree:add(pf_call_offset, tvbuf:range(0x14,4))

    return pktlen
end

DissectorTable.get("tcp.port"):add(5000, p_keyper)
