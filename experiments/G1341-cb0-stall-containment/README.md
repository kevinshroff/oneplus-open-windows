# G1341: matched CB0 stall containment

Source-only variant of the G1335 low-physical owner and G1339 first-fault broker.
It changes the owned GPU CB0 fault response, not its translations. No successful
GPU execution, runtime qualification, installation or activation is claimed.

The matched pair has since passed native linking, compiled review and independent
signed-content verification: [scoped validation](NATIVE-SIGNED-VALIDATION.md).
Those results do not establish hardware execution or containment benefit.

`prepare.py --out <fresh-external-directory>` reuses G1335's source-copy recipe
and adds the shared `g1341_cb0_policy.h`. The authoritative baseline files are
not edited. `OGO_GPU_CB0_STALL_ON_FAULT` defaults to zero and accepts only 0/1.
When enabled, the exact CB0 SCTLR becomes `0x00c001e7` rather than `0x00c00067`:
only CFCFG bit 7 and HUPCF bit 8 change. The owner programming allowlist and
store, broker active/commit comparisons, and optional witness all use the same
constant. Mismatched owner/broker profiles refuse; there is no permissive mask.

Both new images are required. The previously signed G1339 broker must not be
paired with the enabled G1341 owner: its exact CB0 checks expect the old value.
GMU CB2 activation, table descriptors, stream routing, ACTLR, address widths,
MAIR, physical-allocation cap, original IOVAs and SQE payload remain unchanged.

Build the isolated owner using its existing 35-object compiler with
`--layout nonsecure64 --secvid-zero-stores --gpu-low-physical
--gpu-cb0-stall-on-fault`. Keep WC, low-SQE and pre-release-witness options off.
Use the existing 15-object broker closure with both
`OGO_GPU_FIRST_FAULT_TUPLE=1` and `OGO_GPU_CB0_STALL_ON_FAULT=1`.
Existing genuine-header/native-link recipes apply. Default-off comparison
builds use the same inputs without the new flag. No new linker or test framework
is introduced.

The expected benefit is containment if an initial GPU context fault currently
returns an error that escalates before Windows handles it. This causal mechanism
is unproven. Stalling does not repair an invalid translation or guarantee a
first fence. A CPU MMIO, secure-world or unrelated interconnect failure can
remain fatal. A stalled GPU can still require controlled recovery.

Existing fatal/retention behavior remains. G1339 captures the first tuple before
the original W1C acknowledgement; SS is read-only and excluded from that mask.
This variant adds no RESUME write, retry, descriptor repair or recovery loop.
The fault is terminal for this attempt. It is not a logging-only trial.

Run `test.py --source-tree <prepared-copy> --out <fresh-external-directory>`.
It reuses the actual G1339 ISR shim and adds the combined stalled translation
fault `0x40000402`: tuple before ACK, only TF bit 1 acknowledged, SS/Format
retained, Fatal set, and no RESUME. Both profile modes use ASan/UBSan; invalid
flag values are rejected and GMU/fault implementation bytes must match baseline.

## Primary source applicability

`PRIMARY-PINS.json` pins four Linux files to commit
`e2f57c576f14f96449cfee840860cb9707501d23`:

* `sm8550.dtsi:3012` identifies the SMMU at `0x03da0000` with
  `qcom,sm8550-smmu-500` and `qcom,adreno-smmu` compatibility.
* `arm-smmu-qcom.c:675` selects the Adreno implementation. Its
  `qcom_adreno_smmu_write_sctlr` at line 108 sets HUPCF and conditionally CFCFG;
  the implementation tables include this callback.
* `msm_iommu.c:820` explicitly enables stall-on-fault for the GPU domain.
* `arm-smmu.h:147` defines CFCFG at bit 7 and HUPCF at bit 8.

These are a chip-applicable driver path and bit contract, not proof that this
Windows failure is an SMMU fault. Sheng's successful A740 implementation uses
continue-after-fault but does not require stall; it must not be cited as proof
that stalling is necessary for healthy execution. The reason to test this
profile is to preserve an actionable first fault rather than repeat blind
address placement or register-policy changes.
