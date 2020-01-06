# KeyperPlus HSM Dissector
Dissector for the wire-protocol between the KeyperPlus HSM and its PKCS#11 library. This dissector does not support the Keyper's load-balancing features.

## Installation
Copy keyper.lua into one of the Wireshark Lua plugin directories. Locations of the plugin directories are described within Wireshark at About -> Folders.

Remove port 5000 from GSM over IP at Preferences -> Protocols -> GSM over IP if Wireshark shows malformed packets for the RSL protocol.
