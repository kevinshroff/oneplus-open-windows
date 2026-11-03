# G1342 — native CE3 TX delivery discriminator

G1342 asks whether the WMI TX source ring is reaching and being consumed by CE3. It follows G1340's Boot172 observation that native CE2 hardware indices agreed with CPU/RRI state while WMI endpoint2 had exhausted its credits and stopped receiving replies. That result did not identify a persistent RX visibility gap.

The isolated candidate changes only two fixed entries in G1340's native getter table: index4 reads CE3 source HP at0x01b86400 and index5 reads TP at0x01b86404. Every instruction and native wake/window/error/ownership gate remains unchanged. The client requests4 then5 once each, stopping on the first refusal. Zero remains an explicit refusal, not an empty-ring result.

- [Patch recipe and route interpretation](wifi-native-ce3-getter-G1342/README.md)
- [Native and signed validation](NATIVE-SIGNED-VALIDATION.md)
- [Validation receipt summary](VALIDATION.md)
- [Actual hardware result](HARDWARE-RESULT.md)

A paired CPU snapshot compared local HP, cached TP, DMA RRI TP, the completion cursor and ownership-context values. Hardware queries and the CPU snapshot are sequential, not atomic. A drained ring would support descriptor consumption; it would not prove correct device-visible WMI bytes or firmware command processing.

Status: hardware getter and CPU comparison completed. HP/TP20/20 matched local/cached/RRI state; all32 ownership slots were zero, while endpoint2 had queue7/credits0. This is a credit-blocked snapshot without an observed persistent source TX backlog. Target command execution, complete coherency and firmware health remain unresolved; no repair is claimed.
