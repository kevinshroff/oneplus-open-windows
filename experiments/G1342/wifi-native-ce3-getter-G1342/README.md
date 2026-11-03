# G1342: bounded native CE3 TX indices

G1342 replaces only getter table slots4/5 with CE3 source HP `0x01b86400` and TP `0x01b86404`. Slots0–3 and6–7, every executable instruction, native wake/window/error handling, NC policy, ownership gates and unwind data remain byte-identical to the reviewed unsigned G1340 image. The patch defaults inert and requires the exact G1340 unsigned SHA256. It produces an unsigned local derivative; it does not sign, install, boot or query hardware.

The existing conservative getter refuses zero, `0xc000000d`, `0xffffffff` and a changed HAL error counter. A zero refusal is **not** evidence that the ring is empty. The client queries only4 then5, once each, stopping on the first refusal. No arbitrary address or diagnostic DMA route is introduced.

The source closure identifies service0x0100 uplink pipe3/downlink pipe2 in the exact OEM service table, corroborated by Boot172 initialization logs. HIF send selects CE3. The selected targettype0x1f HAL source-ring table starts HP at0x01b80400 with0x2000 stride; source HP/TP offsets are0/4, yielding the fixed pair above. CE3 uses32 entries of4 DWORDs: source SRNG ID35, HAL+0x1830, localHP+0x68, reap+0x6c, RRI pointer+0x70 and cachedTP+0x78. Its CPU RRI slot is shadow+0x8c. A separately guarded CPU capture compares these indices and context values; it does not dereference packet pointers.

Boot172's CE2 hardware and CPU observations agreed despite the continuing WMI credit stall. This shifts the next discriminator to TX delivery. If CE3 hardware HP differs from software HP, publication needs investigation. If HP differs from TP, hardware consumption is incomplete. If indices and completion state have drained, that supports descriptor consumption, **not** correct device-visible WMI bytes or firmware command processing. The hardware queries and CPU capture are sequential, not atomic.

The source-ring reap cursor is one entry behind the next completion: compare `(reap + entry_DWORDs) % ring_DWORDs` with TP. Do not compare reap directly with TP. Context pointers may be retained marker values, including gather markers; they are ownership metadata, not permission to inspect freed packets.

The existing Windows TX route already maps/flushes after final HTC header writes. Static inspection therefore does not justify another blind cache-policy or missing-flush patch. Device-visible payload correctness remains unproven.

Offline build:

```
python3 patch.py --build-offline --base <exact-G1340-unsigned.sys> --out <new-directory>
```

Actual unsigned candidate SHA256: `a98840b66a8598ddb4ef2aa59300e36b4f1a6d626156b4f9aa68c1b6ec1961db` (3841536 bytes). Only four bytes differ, all inside the approved8-byte table span RVA0x14e194..0x14e19c. Actual candidate REA table read and getter decompilation passed; unchanged behavior inherits G1340's exact-byte closure. This is not a hardware result or a claim that the TX stall is repaired.
