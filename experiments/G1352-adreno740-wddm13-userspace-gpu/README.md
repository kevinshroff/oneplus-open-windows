# G1352: Adreno 740 WDDM 1.3 KMD (`topazgpu_v12.sys`) & Userspace Hardware GPU Execution

## Summary

Native Windows 11 ARM64 WDDM 1.3 kernel-mode display/compute driver (`topazgpu_v12.sys`) for the **Qualcomm Adreno 740 (SM8550)** on the **OnePlus Open**, exposing a live `D3DKMT` / `msm` DRM-style escape interface (`version 1.9.0`) backed by real Adreno 740 GMU/HFI/CP hardware execution and dynamic ARM64 SMMU CB0 4-level page-table mapping.

## Architecture & Key Fixes

1. **Hardware Backend (`OpenSmmuD0` + `G1350` SID0+SID1 Bootstrap):**
   - Links the 33 proven Adreno 740 GMU/HFI/CP + SMMU CB0 bootstrap objects (`G1350-sid01`, `SID0+SID1` -> CB0, `STALL_ON_FAULT=0`, low 32-bit IOVAs `0x00100000`-`0x00110000`, `0x14b` CP_ME_INIT) with the 6 WDDM 1.3 frontend objects (`ddi.c`, `msm.c`, `eng.c`, `disp.c`, `log.c`, `a740_wddm_bridge.c`).
   - Keeps `OgoBootstrapThread` parked on `g_KeepAlive` after `OgoBootstrap` succeeds so the system thread never exits with an active `KeEnterGuardedRegion` (`BugCheck 0x20: KERNEL_APC_PENDING_DURING_EXIT`).
   - Direct MMIO `Cb0TlbSync` (`CB0_TLBIVA` + `CB0_TLBSYNC` + `CB0_TLBSTATUS`) for dynamic user BO page-table updates from arbitrary `D3DKMTEscape` threads.
2. **ARM64 Cache Attribute Coherency:**
   - Allocates user BO pages with `MmWriteCombined` in `TgAllocPages` to match `msm.c:Mmap`'s `MmWriteCombined` userspace mapping on ARM64.
3. **WDDM 1.3 `dxgkrnl` Adapter Start (Code 43 Fixes):**
   - `FeatureScore = 0xD0` + `UserModeDriverName = ("d3d10warp.dll")` on `ACPI\OPEN0515\0` display class key (resolves `StartAdapter_AddAdapterFailed`).
   - `*NumSources = 1; *NumChildren = 1;` with 1 disconnected `TypeVideoOutput` child (`ChildUid = 1`, `Connected = FALSE`) so `dxgkrnl` starts the WDDM 1.3 adapter cleanly without disturbing UEFI GOP `BasicDisplay` (resolves `StartAdapter_PostDeviceIsRenderOnly`).
   - `CghNativeObserveStarted` accepts `DxgkDdiStartDevice` before `dxgkrnl` updates `DEVPKEY_Device_PowerData` to `PowerDeviceD0`.

## Live Hardware Verification (OnePlus Open, Windows 11 ARM64)

Verified on cold boot with `OpenSmmuD0` + `topazgpu_v12.sys` (`ACPI\OPEN0515\0 DEVPKEY_Device_ProblemCode = 0`) across two consecutive runs of `test_wddm_a740_v2.exe` (allocating user GEM BOs, mapping into SMMU CB0 IOVA `0x2000000+`, mapping to userspace VA, writing a PM4 `CP_MEM_WRITE` packet (`0xcafebabe`, `0x12345678`), submitting via `D3DKMTEscape`, waiting for real CP hardware fence completion, and verifying zero BO leaks on device close):

```text
=== RUN 1 ===
D3DKMTEnumAdapters2: st=0x00000000 count=2
  Adapter[0]: hAdp=0x40000000 LUID=00000000:000c001b Sources=0 CreateDevice=0x00000000 hDev=0x40000080
  -> FOUND TOPAZGPU WDDM ADAPTER! version=1.9.0 name="msm" hDev=0x40000080
GET_PARAM GPU_ID    : st=0x00000000 ret=0 val=0x2e4
GET_PARAM CHIP_ID   : st=0x00000000 ret=0 val=0x43050a01
GET_PARAM GMEM_SIZE : st=0x00000000 ret=0 val=0x300000
GET_PARAM VA_START  : st=0x00000000 ret=0 val=0x2000000
GEM_NEW: cmd=(h=1 ret=0) dst=(h=2 ret=0)
IOVA: cmd=0x2000000 dst=0x2002000
MMAP: cmd=0x1c20f790000(ret=0) dst=0x1c20f7a0000(ret=0)
GEM_SUBMIT: ret=0 fence=2
WAIT_FENCE: ret=0 dst[0]=0xcafebabe dst[1]=0x12345678
PASS: REAL ADRENO 740 WDDM 1.3 USERSPACE HARDWARE GPU EXECUTION VERIFIED!

=== RUN 2 ===
GEM_NEW: cmd=(h=3 ret=0) dst=(h=4 ret=0)
IOVA: cmd=0x2004000 dst=0x2006000
GEM_SUBMIT: ret=0 fence=3
WAIT_FENCE: ret=0 dst[0]=0xcafebabe dst[1]=0x12345678
PASS: REAL ADRENO 740 WDDM 1.3 USERSPACE HARDWARE GPU EXECUTION VERIFIED!
```

Driver log confirmed clean teardown after each run:
`2 BO references dropped, 2 BOs freed, 0 BOs / 0 KB left`.

## Files

- `a740_wddm_bridge.c` - WDDM 1.3 hardware bridge (GMU/HFI/CP bootstrap thread, direct MMIO CB0 4-level page-table mapper + TLB sync, ringbuffer submission, fence tracking).
- `test_wddm_a740_v2.c` - Userspace `D3DKMTEnumAdapters2` / `D3DKMTCreateDevice` / `D3DKMTEscape` hardware GPU verification tool.
