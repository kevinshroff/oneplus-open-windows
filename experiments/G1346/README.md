# G1346: retain native WLAN and MHI wake assertions

G1346 is a per-boot power-retention experiment. The preceding no-hint trial confirmed that hint suppression took effect while the admitted-command/credit/RX-silence boundary remained. Across retained trials the final command varies, making a common wake/transport-progress seam more useful than another isolated command-field change. This does not diagnose a power-state fault.

The [offline recipe](wifi-sustained-wake-G1346/patch.py) takes the exact G1344 unsigned input and changes two instruction words:

| Site | Change | Intended boundary |
|---|---|---|
| `0x1b334c` | `BL 0x1aa3c8` → `NOP` | Skip this WLAN release caller’s BAR+`0x3004` zero write. |
| `0x228548` | `B.EQ 0x22857c` → `B 0x22857c` | After the existing final decrement, skip the MHI sleep-doorbell-zero path. |

The MHI release call, reference arithmetic, counters, synchronization, wake assertion, transfer doorbells, generic write helpers and unwind bytes remain unchanged. G1344’s NC/getter/no-hint changes remain in the baseline. Exactly six bytes differ within the two reviewed words; every other file byte is identical.

Static compiled review confirms the two intended branches and preserved release bookkeeping. It does not prove electrical wake state, correct retention across another power path, or a networking repair. No wake assertion is created before a successful native request. Teardown/reset can still change state; production suspend/resume is unqualified.

The intended functional comparison reuses one initialization, the minimum15-second callsite-to-cache interval, one cached query and at most one exact saved-profile connection/DHCP observation. No repeated scan or force-wake API is part of this recipe. Any trial combined with a changed QTB firmware image must report that configuration and cannot attribute success to this driver change alone.

The recipe defaults to inert, requires an exact base hash and an exclusive output directory, and performs no signing, installation or device access. See [validation](VALIDATION.md). No G1346 hardware result is established here.
