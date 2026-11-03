# Register access authority

The [official Arm IHI0062D.c specification](https://documentation-service.arm.com/static/5f900d34f86e16515cdc08fb) identifies all selected locations:

| Register | Offset | Architecture reference |
|---|---|---|
|CB0 FAR low/high|60/64|Table16-1 pp16-286–287; §16.5.8 p16-298|
|CB0 FSYNR0|68|Table16-1; §16.5.11 pp16-301–303|
|CB0 FSYNR1|6c|Same table/section; register present, field meanings implementation-defined|
|GR0 GFSYNR0|50|Table9-1 p9-170; §9.6.17 pp9-211–212|
|GR0 GFSYNR1|54|Table9-1; §9.6.18 p9-213|
|GR0 GFSYNR2|58|Table9-1; §9.6.19 p9-214; implementation-defined meanings/usage|

These are RW reporting registers, not read-only registers or W1C acknowledgements. No read-clear operation is specified. Section16.1 permits32-bit access across the context register space, including FAR halves. This supports the access widths, not hardware-atomic tuple consistency. Syndromes may be stale or overwritten; FAR low bits can be unknown.

The target-family qualification is additional: pinned [SM8550 Qualcomm arm-smmu.h](https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550/blob/c87f74901db572a762241d6dfcacc42dbdd9f798/drivers/iommu/arm/arm-smmu/arm-smmu.h#L244) defines FAR/FSYNR0/**FSYNR1** and the three global syndromes. FSYNR1 is not inferred from an unassigned slot. Its BID/PID/MID masks are vendor definitions; G1339 preserves raw bits without applying those meanings. The [matching implementation](https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550/blob/c87f74901db572a762241d6dfcacc42dbdd9f798/drivers/iommu/arm/arm-smmu/arm-smmu.c#L650) reads both context syndromes and FAR for diagnostics. Its global handler at985–1026 reads all three global syndromes before a separate GFSR ACK. This supplies primary vendor usage for GFSYNR2 despite its architecture-level implementation-defined constraints.

The retained target DT places `qcom,qsmmu-v500`/`qcom,adreno-smmu` at3da0000/40000 and binds gfx3d_user SID0. The existing broker admits the exact SMMU profile, validates IORT/grants and owns mappings at global3da0000 and CB03dc0000; G1339 inherits those guards and adds no register probing. A mapped page by itself is never the register justification.

Source authority does not replace a reviewed future compiled closure or establish present clock/power access. Only the already-registered ISR, existing D0/generation owner and committed CB0/held-NS relation admit the diagnostic reads. No unknown physical aperture is touched. An unqualified/refused context produces metadata only (or global-only data where separately qualified), followed by the unchanged original ACK policy.
