# Boot173: zero-write control returned

**The zero-write diagnostic returned while Windows remained reachable. No GPU execution or first fence was attempted or demonstrated.** This is a positive diagnostic result, not acceleration.

The actual trace records the stage3 SQE control write with value0, native write-call return status0, successful post-AHB check with value0/valid1, and readback0/accepted1. The actual G433 core then returned its intentional terminal state3; the owner reported NTSTATUS `c0000483`, stage3, issued0/completed0 and retained ownership. No release1, CP packet submission, secure exit or first-fence path followed.

The independent SYSTEM task finished Ready/last-result0. Both native PnP commands returned0, while the owner reported PnP problem10 and SCM Running with retained resources. Those command/task results are not a successful GPU device start: the diagnostic intentionally returned a driver failure. The task verified future owner/broker Starts4 and owner once flags0; this was a registry fence, not cancellation, unloading or rollback of retained ownership. USB and the normal controller remained available; the retained host observation was correctly nonterminal, with no900E observed.

The selected signed owner was `1c49da65fe83077cd5f2ff756a49ac4e24da1d46807927e28eb5b43bf134c2e1`, using the unchanged matched G1341 broker. Its [native and signed-content qualification](VALIDATION.md) precedes this result.

## What this distinguishes

The same-address CPU zero-write path can return through the original store/barriers, post-AHB check and readback under this admitted state. That weakens a hypothesis that every write transaction to this register is generically fatal. The earlier fatal value1 boundary is now more specifically value-dependent or release-dependent.

Prestate was already0. Readback0 and AHB0 do not prove an effective bus strobe, rule out a dropped write, exclude value-dependent access protection, or establish a successful first SQE fetch. This trial does not rule out all coherency, SMMU, security or interconnect faults. Do not repeat zero, VA, low-physical, low-SQE, SECVID or the unchanged stall-bit trial on the strength of this result.

## Retained cleanup fields

The trace's CGH state5/error0/gx3 are stored cold-hold report fields. The source retention path poisons/retains hardware authority and releases the owning software mutex/thread scope; it does not take a fresh GX/reset/fault snapshot or power the GPU down. Thus gx3 does not prove that GX was off after the zero store, and error0 is not a claim that no hardware fault existed. The actual CP pre-release report separately recorded GX before3/after0 and OOB held.

Likewise, G810's raw SCTLR belongs to the earlier GMU activation report; it is not a new GPU CB0 readback. The repeated REMOVE log preserves retained state and does not establish safe resource disposal.

The next evidence target is the first fetch activated by value1: stream/security classification, actual device-visible translation/permissions and transaction acceptance. A source-backed repair or a precise observation of that boundary is still required; no new live operation is selected here.

[Structured observations and evidence hashes](HARDWARE-RESULT.json). Raw trace, runtime identities and network/device identifiers remain private.
