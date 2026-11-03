# G1344 validation

The original ARM64 constructor at RVA `0x1d7618` reads short-SSID and BSSID hint counts from request offsets `0x248` and `0x260`. Full-function assembly review identifies eight count reads. The patch replaces each `LDR W8,[X20,#count]` with `MOV W8,#0` at RVAs:

- `0x1d76bc`, `0x1d76cc`: allocation sizing.
- `0x1d7bfc`, `0x1d7c10`, `0x1d7c78`: short-SSID array length and loop control.
- `0x1d7c8c`, `0x1d7ca0`, `0x1d7d84`: BSSID array length and loop control.

No request-object stores are added. Both loops become unreachable through the original zero-count branches. The original empty-array format and final send path remain in place. The last count load in each loop is also replaced although unreachable in this profile.

The primary Linux comparison uses [ath12k wmi.h](https://github.com/torvalds/linux/blob/e2f57c576f14f96449cfee840860cb9707501d23/drivers/net/wireless/ath/ath12k/wmi.h) and [wmi.c](https://github.com/torvalds/linux/blob/e2f57c576f14f96449cfee840860cb9707501d23/drivers/net/wireless/ath/ath12k/wmi.c): short-SSID hints occupy 8 bytes and BSSID hints 12 bytes. This supports structural interpretation; it does not establish that the target firmware rejects hints outside the explicit channel list. Windows has additional fixed scan fields, so fixed-structure size differences are not treated as defects.

Offline checks confirm exactly 32 changed bytes and complete parity elsewhere against G1342. The recipe rejects a wrong base or candidate replay. Modeling the retained hint-bearing command removes exactly 60 payload bytes, reducing 372 to 312 bytes while preserving its first 304 bytes and emitting two empty fixed-structure array headers. This is a serialization check, not target execution.

Unsigned candidate: `c5b543e6881e0e484caa8655444c6967c9864f6f64f18e2bfa319958866eaf21`, 3,841,536 bytes. Independent actual-candidate REA review passed: all eight instructions decode as zero moves; both hint arrays have tag19/length0; both copy loops are unreachable; send and unwind are unchanged. Evidence was exported and the session closed. Compiled receipt SHA256: `141f874e3218142b201e7765e6b0e2d9bc03e7ae79c69a13aef7ee4b8f30c830`. The candidate was subsequently signed using the existing project certificate: `ec65b6425ac14e4a90a85c61d1590ff2093ac7c925309932fa4c9bcbb27b9c86` (3,843,000 bytes). Independent PE payload, SPC digest, CMS SHA256/RSA and signer-identity verification passed, with no trust-store change. This does not establish platform trust or hardware success.

A successful experiment should show both absence of these hints and renewed firmware responses/credit progress beyond scan 40965. Continued failure with confirmed empty hints would argue against this specific hypothesis. The change intentionally removes optional hint functionality for all scans in this experimental profile.
