# Legacy mode capability exclusion candidate

The reviewed original ARM64 driver1.0.4458.2600, SHA256 `802b1f7c5325c312b710312ced0864f813beaf30ff0fceceeefd9f48b2f25d56`, recognizes **StaWirelessMode REG_SZ "7"**. Its INF labels value7 as11b/g. The trial below confirms its runtime effect, but usable networking remains unfinished.

Compiled observations (RVAs for that image): descriptor333068 uses decimal-string parser03cc60; registry normalization03d568 case7 selects mask2c. Regulatory helper1e8fc0 intersects the selected mask with hardware/band configuration;1e5860 passes it to channel collector1e5980, whose branch1e5ee8 skips excluded modes. Per-band HT capability builder087740 checks the selected channel's HT mode flag through05c840/05e960. Legacy modes have no HT flag; a false result leaves body length0 and1753a8 skips the HT capability SET_IE.

This path makes legacy mode a source-backed way to test whether the recurring scan boundary depends on HT-family capability construction. The first four successful scan preparations and the fifth stalled preparation have the same printed HT body and credit-request/debit1→0 behavior. Compiled WMI transport also resynchronizes DMA after serializing the final credit-request header. Neither observation proves device-visible bytes or target execution; neither supports a blind credit or cache patch.

Resolve the actual Driver software key afresh, preserve prior presence/type/value, and change only StaWirelessMode to the exact string7. Preserve other selected settings and the original driver/firmware. Use a fresh admitted boot and one initialization/scan. Do not reuse a consumed boot or infer the selected GPU owner's path/hash from a historical artifact.

Acceptance first requires actual runtime legacy-only modeSelect, HT body length0 and no transmitted HT capability SET_IE. Registry normalization can override a selected mask under other policies, so reading value7 is insufficient. Then require firmware scan/channel/BSS and returned RX-credit progress beyond the former boundary, followed separately by association, DHCP and traffic. This option changes advertised modes, channels and other capability construction; success would not uniquely prove an HT command-body defect.

## Observed legacy trial

One original initialization and one explicit scan returned successfully without a reboot request. P2P exclusion remained selected. Windows still reported zero visible networks and no association. The retained CPU host log was unwrapped, with stable copy metadata, 7,360 ASCII-coherent records and no parser gaps.

Runtime `modeSelect` was `0x2c`. All six logged 2G HT and VHT capability builds had length0; no `WMI_VDEV_SET_IE_CMDID` submission appeared in the retained log. Earlier firmware scan/channel and management receive events still occurred. The final endpoint2 debit1→0 followed `WMI_START_SCAN_CMDID`; no later WMI receive or returned credit appeared before capture. Later scan cancellation/requests queued without credit. The last logged WMI receive was `WMI_UPDATE_STATS_EVENTID`.

This removes the HT capability command as a necessary trigger for the observed stall. It does not identify the firmware fault, prove device-visible command bytes, or establish a general credit/cache defect. The successful scan API/notification also does not establish successful radio scanning or networking. Do not repeat this consumed epoch or patch valid HT IEs based on the earlier command boundary.
