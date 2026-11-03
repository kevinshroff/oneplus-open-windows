# G1343: terminal SQE zero-write control

Source variant of the [matched G1341 pair](../G1341-cb0-stall-containment/README.md). It replaces the sole initial SQE control write1 with write0, then terminates before CP packet construction or submission. It is a discriminator, not a diagnosed repair. **Cold A740 zero-write idempotence is unknown.** The [Boot173 zero-write control returned](HARDWARE-RESULT.md); no GPU execution or first fence was attempted or demonstrated.

Earlier zero readbacks did not establish a completed zero store. A returned zero store/readback would weaken the hypothesis that every CPU write to this address is fatal under the tested state. With prestate0, it would not prove an effective bus strobe, exclude value-dependent protection, or prove a healthy SQE fetch. A fatal result would remain ambiguous. Neither outcome establishes a retired store or fault PC.

## Source preparation

```
python3 experiments/G1343-zero-write-control/prepare.py --prepare --out <fresh-external-source-directory>
```

The recipe defaults inert. Explicit preparation invokes the existing G1341 source recipe and replaces exactly two hash-pinned source files. It performs no compilation, signing or device action. G1341's authoritative files remain unchanged.

- Native `GpuWrite` accepts only zero for the stage3 SQE branch; original first-use, generation/thread, GX/OOB, base/prestate, AHB, retain and barrier guards remain. After a returned write and original post-AHB qualification, one readback records actual status/value. A nonzero result refuses.
- Actual `g433_cp_begin` invokes `writereg(c,0x808,0)`. A failed callback terminates with G433_IO; a successful callback immediately terminates with G433_STATE. Packet construction, stage4, nonzero WPTR, polling, secure exit and retry are unreachable. Conservative may-run/poisoned ownership is retained because zero effects are unknown.

The original owner propagates failure through software-scope leave and retains hardware/resources. It does not stop, free, reset or roll back uncertain hardware. An intentional diagnostic return is not a successful CP fence. Value3 is never substituted.

Build the isolated owner with the existing genuine-header compiler and flags:

```
--layout nonsecure64 --secvid-zero-stores --gpu-low-physical --gpu-cb0-stall-on-fault
```

Keep WC, low-SQE and witness options off. The owner refuses compilation without the G1341 stall profile. Reuse the exact matched G1341 broker; CB0 remains c001e7 and GMU CB2 remains c00067. Do not substitute an older broker expecting c00067 for CB0. Translation/BO/IOVA policy, firmware, other MMIO mapping attributes and barriers are unchanged. Native linking, independent compiled review and any later signing/activation are separate explicit operations.

## Focused validation

```
python3 experiments/G1343-zero-write-control/test.py --source-tree <prepared-source> --out <fresh-external-host-output>
```

The test executes the actual overlay G433 core with host mock IO under ASan/UBSan. Both successful and failed zero writes must terminate at stage3 after one zero attempt, with no release1, packet, nonzero doorbell, fence polling, wait or retry. Secure/poll/reentry calls must refuse. This proves host control flow, not native ABI, MMIO behavior or zero-write safety. See [validation scope](VALIDATION.md).

## Primary-source limits

The pinned [G1341 primary source contract](../G1341-cb0-stall-containment/README.md#primary-source-applicability) supports the selected stall policy. Linux A7xx, OnePlus Gen7 and UniXNU A740 paths support cold start1 and recovery halt3; they do not establish cold0 as side-effect-free. A610 stop0 precedent is insufficient to establish A740 safety.

This control preserves the original pre/post-store barriers. Polling and fenced-write retries require a returned transaction and do not explain a missing write-call return. The failed WC mapping, VA, low-physical, low-SQE and SECVID trials are not repeated; early PAS13 or guessed security/clock bit changes are not added.
