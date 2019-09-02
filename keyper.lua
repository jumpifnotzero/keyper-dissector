-- script-name: keyper.lua
-- Version: 0.9

local p_keyper = Proto("keyper", "KeyperPlus HSM")

local pf_length = ProtoField.uint32("keyper.length", "Length", base.DEC)
local pf_call_count = ProtoField.uint8("keyper.call_count", "Call Count", base.DEC)
local pf_call_id = ProtoField.uint32("keyper.call_id", "Call ID", base.HEX)
local pf_param_count = ProtoField.uint32("keyper.param_count", "Parameter Count", base.DEC)
local pf_param = ProtoField.bytes("keyper.param", "Parameter")

p_keyper.fields = {
  pf_length,
  pf_call_count,
  pf_call_id,
  pf_param_count,
  pf_param,
}

function get_len_func(tvb, pktinfo, root)
  return tvb:range(0, 4):uint()
end

function dissect_func(tvbuf, pktinfo, root)
  pktinfo.cols.protocol:set("Keyper")

  local pktlen = tvbuf:reported_length_remaining()

  local tree = root:add(p_keyper, tvbuf:range(0, pktlen))

  tree:add(pf_length, tvbuf:range(0, 4))
  -- TODO: unable to set reassembled length?
  pktinfo.cols.packet_len:set(tvbuf:range(0, 4):uint())

  -- the number of calls in this frame
  tree:add(pf_call_count, tvbuf:range(4, 1))
  local call_count = tvbuf:range(4, 1):uint()

  -- extract the offset of each call
  call_offset = {}
  for i = 1, call_count do
    call_offset[i] = tvbuf:range(0x10 + (i * 4), 4):uint()
  end

  -- loop over each call
  for i = 1, call_count do
    call_tree = tree:add("Call")
    call_tree:add(pf_call_id, tvbuf:range(call_offset[i], 4))
    call_tree:add(pf_param_count, tvbuf:range(call_offset[i] + 4, 4))
    local param_count = tvbuf:range(call_offset[i] + 4, 4):uint()

    -- extract the position of each parameter
    param_offset = {}
    for j = 1, param_count do
      param_offset[j] = tvbuf:range(call_offset[i] + 4 + (j * 4), 4):uint()
    end

    -- loop over each parameter
    for j = 1, param_count do

      -- work out the length of the parameter

      -- this parameter ends at the end of the packet, or the end of the call,
      -- or at the start of the next parameter
      local param_length = pktlen - (call_offset[i] + param_offset[j])
      if i < call_count then
        param_length = call_offset[i + 1] - (call_offset[i] + param_offset[j])
      end
      if j < param_count then
        param_length = param_offset[j + 1] - param_offset[j]
      end

      -- add the parameter to the tree
      call_tree:add(pf_param, tvbuf:range(call_offset[i] + param_offset[j], param_length))
    end

  end

  return pktlen
end

function p_keyper.dissector(tvbuf, pktinfo, root)
  -- TODO: appropriate value for minimum header size?
  dissect_tcp_pdus(tvbuf, root, 4, get_len_func, dissect_func)
end

DissectorTable.get("tcp.port"):add(5000, p_keyper)
