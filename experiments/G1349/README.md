# G1349: scan-priority discriminator

The preceding [G1346 trial](../G1346/HARDWARE-RESULT.md) completed an initial scan, then admitted another scan which consumed the last HTC credit without a later firmware WMI event or credit return. This experiment tests one remaining scan-field correlation. It is not a diagnosed firmware fix.

A retained complete host command journal shows the successful scan40964 and unanswered scan40965 differ in fixed fields only by scan ID and priority2→1. Their channels, wildcard SSID/BSSID arrays, IE, flags, dwell/rest values, notification mask and21 extension words match. The optional hints differed separately; G1344 removed them, and subsequent trials retained the failure. The journal is a host serialization before HTC admission, not device-visible payload proof.

Earlier matched-package trials completed scan40965 at priority2, including real firmware STARTED, channel and COMPLETED(reason0) events. Thus neither that scan ID nor the common requestor/channel fields are intrinsically rejected in the observed configuration. In the G1346 trial the previous scan completed normally, its host state returned SCAN→INIT, and about2seconds elapsed before the unanswered scan. No STOP was needed after that normal completion. The later local cancellation notification has no corresponding firmware RX and cannot establish that the second scan ran.

Priority1 is LOW and2 is MEDIUM in the [primary ath12k ABI enum](https://github.com/torvalds/linux/blob/e2f57c576f14f96449cfee840860cb9707501d23/drivers/net/wireless/ath/ath12k/wmi.h). [ath11k](https://github.com/torvalds/linux/blob/e2f57c576f14f96449cfee840860cb9707501d23/drivers/net/wireless/ath/ath11k/wmi.c) intentionally selects LOW for ordinary scans and MEDIUM while preparing regulatory discovery. LOW is valid protocol input. A Windows/firmware scheduling defect remains a hypothesis, not a protocol violation. Other retained trials also stalled on statistics commands, so scan priority cannot yet explain every failure.

The [offline recipe](patch.py) derives only from the exact unsigned G1346 image. At the scan serializer's original priority/notification pair store, it routes through six instructions in a hint-copy block already made unreachable by G1344. The code maps only priority1→2; initial2 and every other32-bit value remain unchanged. No extra scan, echo, credit, statistics query, association or timing change is added.

Run with an independently obtained exact input and an exclusive new output directory:

```sh
python3 patch.py --build-offline --base BASE.sys --out NEW-OUTPUT
```

Default invocation is inert. No OEM image, signing material or runtime identifiers are supplied. The NC/getter/no-hint/wake baseline, generic priority helpers, DMA path, other packet fields and exception metadata remain unchanged.

A meaningful positive requires actual loaded-code qualification, a real firmware event/credit progression after the substituted automatic scan, and separately observed connection behavior. Cache visibility, a local completion indication or HTC completion alone is insufficient. A negative would weaken this priority-specific hypothesis without proving firmware death. The [Boot177 hardware result](HARDWARE-RESULT.md) records initial scan completion followed by the same last-credit/RX-silence boundary. The candidate did not restore transport progression as exercised; see [validation](VALIDATION.md).
