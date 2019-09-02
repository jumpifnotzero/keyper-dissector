-- script-name: keyper.lua
-- Version: 0.9

local p_keyper = Proto("keyper", "KeyperPlus HSM")

local pf_length = ProtoField.uint32 ("keyper.length", "Length", base.DEC)
local pf_call_count = ProtoField.uint8 ("keyper.call_count", "Call Count", base.DEC)
local pf_call_id = ProtoField.uint32 ("keyper.call_id", "Call ID", base.HEX)
local pf_param_count = ProtoField.uint32 ("keyper.param_count", "Parameter Count", base.DEC)

p_keyper.fields = {
  pf_length,
  pf_call_count,
  pf_call_id,
  pf_param_count,
}


function p_keyper.dissector(tvbuf, pktinfo, root)

  -- set the protocol column to show our protocol name
  pktinfo.cols.protocol:set("Keyper")

  local pktlen = tvbuf:reported_length_remaining()

  -- TODO: can't assume this frame is a whole message
  local tree = root:add(p_keyper, tvbuf:range(0, pktlen))

  tree:add(pf_length, tvbuf:range(0, 4))

  -- the number of calls in this frame
  tree:add(pf_call_count, tvbuf:range(4, 1))
  local call_count = tvbuf:range(4, 1):uint()

  -- extract the offsets of each call
  call_offsets = {}
  for i=1, call_count do
    call_offsets[i] = tvbuf:range(0x10 + (i * 4), 4):uint()
  end

  -- loop over each call
  for i=1, call_count do
    call_tree = tree:add("Call")
    call_tree:add(pf_call_id, tvbuf:range(call_offsets[i], 4))
    call_tree:add(pf_param_count, tvbuf:range(call_offsets[i] + 4, 4))
  end

  return pktlen
end

DissectorTable.get("tcp.port"):add(5000, p_keyper)
