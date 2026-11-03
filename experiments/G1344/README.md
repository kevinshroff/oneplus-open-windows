# G1344: omit optional 6 GHz scan hints

This source-only experiment tests whether optional 6 GHz hints trigger the observed WMI stall. It does not claim that the existing scan command is malformed or that the change fixes Wi-Fi.

A retained host command journal contains 126 records. Scan 40965 uniquely includes three short-SSID hints and three BSSID hints for a 6 GHz frequency while its explicit channel list contains only 2.4 GHz channels. Earlier and later scan records have empty hint arrays. All retained TLV boundaries and common count/length relationships are coherent. The journal records commands before HTC credit admission, so it does not prove which commands reached firmware. Separate earlier transport evidence identifies scan 40965 as the final posted command before credit starvation.

The isolated [patch recipe](wifi-scan-no-hints-G1344/patch.py) derives from the G1342 unsigned candidate. It replaces eight count loads in the native scan serializer with zero. Both allocation counts, both TLV lengths, and both copy-loop controls therefore agree. It retains the two empty trailing array TLVs and does not alter the caller's hint cache or request object. Channel list, scan priority, IDs, IE bytes, transport, NC policy, native CE getter, and unwind metadata remain unchanged.

The recipe defaults to inert and requires an exact input hash and a new output directory. It performs no signing, installation, firmware calls, or device access. The unsigned candidate has not been exercised on hardware.

See [validation](VALIDATION.md) for the compiled source basis and limitations.
