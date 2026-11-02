# A740 start sequence and MMIO parity

Source review, 2026-11-02. This establishes comparison behavior, not a missing
write's causal role. The nonsecure64 trial still failed at the outer SQE-start
call boundary; it did not localize the helper's barriers or STR.

## Start and security sequence

[Linux a6xx_gpu.c](https://github.com/torvalds/linux/blob/e2f57c576f14f96449cfee840860cb9707501d23/drivers/gpu/drm/msm/adreno/a6xx_gpu.c#L1179)
holds GPU_SET through setup, programs ring/SQE bases and BR/BV shadows, writes
SQE_CNTL=1, initializes CP, then loads ZAP and exits secure mode. The start uses
plain `gpu_write`; the dropped-write retry helper is a different call path.
Recovery halt3 is not cold start1. The A740 table-based HWCG path skips existing
0x8aa8aa82 state; the newer no-table P2S/TXDONE poll is not that path. The
[catalog](https://github.com/torvalds/linux/blob/e2f57c576f14f96449cfee840860cb9707501d23/drivers/gpu/drm/msm/adreno/a6xx_catalog.c#L1541)
selects a740_hwcg for the a740_sqe/gmu7020100 profile.

[OnePlus Gen7](https://github.com/OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8550/blob/oneplus/sm8550_v_15.0.0_oneplus11/vendor/qcom/opensource/graphics-kernel/adreno_gen7.c#L846)
also starts SQE, submits CP initialization and waits idle before ZAP. Its abstract
CP_ME_CNTL maps to GEN7_CP_SQE_CNTL: there is no additional ME-enable store to
infer. Its Android trusted-range values are allocator policy, not Windows values.

[Sheng's actual board path](https://github.com/UniXNU/UniXNU-sheng/blob/5eb3c704f9cbb61481537cc617ed381c6eaa41f1/package/GpuPowerProbe.cpp#L1655)
starts SQE, submits/waits CP initialization and a scratch command, then invokes
ZAP/secure exit. Its GPU_SET acknowledgement poll follows the HFI frequency/BW
acknowledgement. The separate
[NativeAdreno CP builder](https://github.com/UniXNU/Adreno740/blob/a9a2cbb43b89d672e2921e19721a6438b738b17f/NativeAdrenoCpInit.cpp)
constructs initialization packets, not a second engine-enable operation.

The clear remaining store-parity gap is four SECVID/TSB zero stores: Linux/Sheng
write TSB control, trusted base low/high and size; current G456 qualifies zeros
without those stores. Zero readback does not prove a write occurred, but no
source or observed result demonstrates that a write strobe is required. Any
such trial must remain separate from instruction-boundary localization. A
pre-start PAS/ZAP change, repeated SQE start, guessed clock value or separate
ME write is not justified by these sequences.

## CPU mapping and access ordering

Current `g482_resources.c` maps the exact assigned register banks with
`MmMapIoSpaceEx(PAGE_NOCACHE|PAGE_READWRITE)` and uses register accessors. GPU BOs'
MDL/noncached-data mappings are a separate path. The reviewed compiled owner
helper contains pre-store DSB SY, the register STR and post-store DSB OSH;
plain MMIO does not mean barrier-free access.

Linux's source chain is `msm_ioremap` → `devm_ioremap` → ARM64 `ioremap`, whose
[default protection](https://github.com/torvalds/linux/blob/e2f57c576f14f96449cfee840860cb9707501d23/arch/arm64/include/asm/io.h#L292)
is Device-nGnRE. Normal-NC is explicitly `ioremap_wc`. `gpu_write` uses `writel`;
its source expansion supplies a pre-store `dma_wmb`/DMB OSHST and 32-bit STR.
This source comparison is not a Linux compiled-image attestation.

[Microsoft's API contract](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmapiospaceex)
describes PAGE_NOCACHE and translated-register mappings but does not identify
the exact ARM64 PTE/MAIR subtype. Current Windows mapping flags alone therefore
do not prove Device-nGnRE, Device-nGnRnE or Normal-NC. There is no established
mapping defect here. A future exact CPU PTE/MAIR observation could resolve that
question; changing attributes or removing barriers would change the experiment.

## Reproducible source pins

Commit-qualified links above identify the examined revisions. The OnePlus link
is a branch: only the retrieved bytes are pinned, not an inferred commit.
SHA256 values below and all supporting MMIO source URLs/hashes are recorded in
[SOURCE-PARITY-PINS.json](SOURCE-PARITY-PINS.json). No captured binary or runtime
address is included.

| Primary file | Retrieved SHA256 |
|---|---|
| Linux a6xx_gpu.c, e2f57c576f14f96449cfee840860cb9707501d23 | `9b725c1c56a9b6b804de0daa899fa03f51ddb6c8253904c77814540d5142f4cd` |
| Linux a6xx_catalog.c, same commit | `e1a2aba9a9ba6f753d8130525542e93d20373fc927d066663d749d2a6cb7a746` |
| OnePlus adreno_gen7.c, linked branch | `fe83b9244175ecfcf7cd363ca502b900ade5c7bea69b10bfef9c5d26fbf8a94c` |
| Sheng GpuPowerProbe.cpp, 5eb3c704f9cbb61481537cc617ed381c6eaa41f1 | `34ee6d336c734a3b5d00a8fb810ae63cfa27169a869b94b16fd263dca063098c` |
| NativeAdrenoCpInit.cpp, a9a2cbb43b89d672e2921e19721a6438b738b17f | `58a7a2d1aa83ffa7eb7131351a694d45272586a0abbb5f24916ea2105538a2d6` |
