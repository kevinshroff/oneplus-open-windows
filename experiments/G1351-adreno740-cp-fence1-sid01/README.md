# G1351: First Real Adreno 740 CP Execution and Fence1 Completion on Native Windows 11 ARM64

## Breakthrough Summary

On live OnePlus Open (SM8550, Adreno 740) hardware running native Windows 11 ARM64 (`26100`/`26300`) on `boot-G1345-QTB-CP-IRQ709-combined.img`, the Adreno 740 Command Processor (SQE) executed its first real PM4 ringbuffer submission (`CP_ME_INIT` + `CP_EVENT_WRITE` / fence1) and completed cleanly with zero SMMU faults, zero hardware faults, and zero 900E resets.

## Root Cause of Prior 900E Crash at `CP_SQE_CNTL = 1`

Prior `G1350` builds triggered a Qualcomm 900E crash immediately upon writing `CP_SQE_CNTL = 1` (`0x2020`). Diffing against SM8550 device-tree (`iommus = <&gpu_smmu 0 0>, <&gpu_smmu 1 0>;`) and UniXNU `Adreno740` (`NativeAdrenoGpuContext.cpp`, `NativeAdrenoSmmuContext.cpp`, `NativeAdrenoCpInit.cpp`) identified four exact fixes required together:

1. **Route BOTH GPU Stream IDs (`SID 0` and `SID 1`) to CB0**:
   - `OpenGpuStart` (`gpu_cp_translate.c`): program `SMR[1] = 0x80000000`, `S2CR[1] = 0x300` (SID 0 -> CB0) **and** `SMR[2] = 0x80000001`, `S2CR[2] = 0x300` (SID 1 -> CB0).
   - `OpenSmmuD0` (`gpu_user_native.inc`): accept both `SMR[1]`/`S2CR[1]` and `SMR[2]`/`S2CR[2]` in `GpuUserCommitApi`.
   - Without SID 1 routed, SQE/CP DMA on SID 1 hit an unidentified-stream fault (`NSCR0.USFCFG=1`) immediately on `CP_SQE_CNTL = 1`.
2. **Non-stalling CB0 (`OGO_GPU_CB0_STALL_ON_FAULT = 0`, `CB0_SCTLR = 0x00c00067`)** in both broker and owner, matching UniXNU `stall_on_fault = 0`.
3. **Low 32-bit kernel IOVAs** (`gpu_va_layout.h`): `ring = 0x200000`, `fence = 0x300000`, `sqe = 0x100000`, `pwrup = 0x301000`.
4. **`CP_ME_INIT` mask (`g433_cp.c`)**: `0x94b` -> `0x14b` (matching Linux `a7xx_cp_init` and UniXNU `NativeAdrenoCpInit.cpp`).

## Live Hardware Verification (`run41005382`)

```
ACPI\OPEN0D01\1 : ProblemCode=0
ACPI\OPEN0515\0 : ProblemCode=0

POINT g433 return ph4 stg6 st00000000 iss1 cmp1
DIAG_GPU rbbmInt0=00000000 rbbmStat=00000001 rptr=00000011 wptr=00000011 sqeCntl=00000001 hwFault=00000000 cpInt=deafbead sqeBase=00000000_00100000
DIAG_SMMU gfsr=00000000 sctlr=00c00067 fsr=00000400
DIAG_MEM fence=00000011 rptrMem=00000001 bvMem=00000000
CP fence1 status00000000 phase6 stage6 observed1 completed1 issued1 gxBefore3 gxAfter0 sqeBefore0 sqeAfter0 smmuW20 smmuR763 powerSt6 powerErr0 freqAck1 oob1 gmuPhase6 gmuErr0
bootstrap-result run41005382 gen1 phase11 status00000000
```

- `rptr = 0x11 == wptr = 0x11` (all 17 PM4 words consumed by SQE).
- `m1[0] = 0x11` (hardware RPTR shadow written by CP) and `m1[1] = 1` (fence1 completed in DRAM).
- `gfsr = 0`, `fsr = 0x400` (AArch64 format only, zero fault bits), `hwFault = 0`, `rbbmInt0 = 0`, `rbbmStat = 1` (clean idle).

## Next Step

Integrate this proven Adreno 740 GMU + SID0/SID1 SMMU + CP bring-up into the 21-TU WDDM 1.3 KMD (`drivers/gpu/gpu-wddm-bridge-G779` / `G1330` `topazgpu.sys`) and bring up userspace rendering (`Mesa/Turnip`).
