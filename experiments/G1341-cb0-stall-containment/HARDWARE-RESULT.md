# Boot172: containment trial result

The matched G1341 pair reached the same SQE start-call boundary and was followed by confirmed Qualcomm 900E. No store return, first fence or containment benefit was demonstrated. The attempt is consumed; repeating the unchanged profile is not the next experiment.

The selected signed owner was `a0997a15e1ba2b366f5310188499917d27d33f195965727aafd8d342cb985603`; the matched broker was `144a5746ce85095cef3239cd2c3a88533c70cc90a870f06207510c412602d64a`. Their [native, compiled and signed-content qualification](NATIVE-SIGNED-VALIDATION.md) preceded the trial. Activation guarded their disk hashes and service paths, started the broker, and required Running/PnP problem0 before starting the owner. These facts are not an independent postload measurement of the mapped PE images.

The actual owner trace records one aperture entry/return with raw x0/x1=0/0, successful GMU/HFI initialization with 15 startup acknowledgements, successful CP Configure, and two successful post-Configure lease checks. The last marker is `STORE_CALL_BEGIN`; neither a store return nor a G1339 first-fault line follows in the retained trace. A later USB observation confirmed900E. One Sahara HELLO and the acknowledgement of one software reset were retained; completed Windows/WinPE recovery is not claimed by this result.

## SCTLR evidence and its limit

The reviewed owner writes CB0 SCTLR `0x00c001e7` and requires an exact readback. The matched broker's commit and active-currentness checks require that same value. The GMU CB2 policy remains `0x00c00067`. Progression to CP Configure is therefore consistent with successful source gates **conditional on the selected compiled pair being the executing pair**. The trace contains no direct SCTLR programming/readback line, and no independent postload mapped-image identity measurement was captured. Do not label the policy a directly measured register value for this attempt.

Missing first-fault output does not establish that no SMMU fault occurred, that an IRQ was delivered, or that firmware logging remained available. The final marker does not establish a retired store, first SQE fetch, exception PC or fault cause. This trial weakens the proposed benefit of this particular fault-containment profile; it does not rule out all SMMU, secure-world or interconnect failures.

## Source assessment after the result

No new source-supported first-fence repair was identified in the retained Linux/OnePlus/UniXNU comparison. The A740 sequences release SQE, submit CP initialization and only then perform PAS13/secure exit; moving PAS13 earlier is not justified. UniXNU's ACTLR `0x301` differs from the retained vendor-derived `0x32b`, but that known difference has contrary chip-specific policy and no captured causal fault. It is not a diagnosed fix.

The remaining useful distinction is a same-failure exception/interconnect/SMMU record separating CPU MMIO/barrier failure from an initial target fetch failure. Direct selected-image and SCTLR evidence should accompany any separately justified future activation. This result selects no new live operation and does not repeat low-physical, low-SQE, VA or SECVID variants.

The source comparison and pinned references are retained in the [experiment description](README.md#primary-source-applicability) and [earlier low-physical analysis](../G1335-low-physical-cp/README.md). [Structured result](HARDWARE-RESULT.json) records evidence hashes. Raw host logs, runtime identities and captured addresses remain private.
