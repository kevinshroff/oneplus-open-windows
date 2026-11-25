# Option 2 — Adreno 740 display + native D3D11 UMD (accelerated DWM path)

Goal: let Windows itself (DWM, Explorer, inbox `d3d11.dll`/`dxgi.dll` apps) render on the Adreno 740
instead of `BasicDisplay` + WARP.

| Step | Component | Status |
|---|---|---|
| 2A | `topazgpu_opt2.sys` WDDM 1.3 Display+Render KMD driving the inner panel via the UEFI GOP framebuffer (VidPN source/target, 60 Hz timer VSync, scanout copy) | **Works** — `AcquirePostDisplayOwnership 2440x2268 pitch 9760 pa b8000000`, `CommitVidPn`, `SetVidPnSourceAddress`, scanout; `dwm.exe`/`explorer.exe` stable |
| 2B | `ogpu_d3d10.dll` — Mesa 24.3 `d3d10umd` frontend + Gallium `freedreno` (FD740) over the Topaz `msm` escape, registered as `UserModeDriverName` | **Renders real pixels** through the *inbox* Windows D3D11 runtime (see below); DWM enablement in progress |

## Key fix: leave GPU secure mode (ZAP shader)

2D/3D IBs completed their fences but wrote nothing (raw `CP_MEM_WRITE` worked). `RBBM_SECVID_TRUST_CNTL`
was still `1`: the GPU stayed in trusted mode because the A740 ZAP shader was never authenticated. The bridge
now loads `a740_zap.mdt/.b01` (PAS 13, `PIL_INIT_IMAGE` → `PIL_MEM_SETUP(0x9b09a000, 0x2000)` →
`PIL_AUTH_RESET` via SCM, `a740_smc.S`) and submits `CP_SET_SECURE_MODE(0)`:

```
A740ExitSecureMode: RBBM_SECVID_TRUST_CNTL before=00000001
A740ZapLoad: PIL_INIT_IMAGE st=0 res=0
A740ZapLoad: PIL_MEM_SETUP(0x9b09a000, 0x2000) st=0 res=0
A740ZapLoad: PIL_AUTH_RESET st=0 res=0
A740ExitSecureMode: CP_SET_SECURE_MODE(0) fence=2 done=2 RBBM_SECVID_TRUST_CNTL after=00000000
```

The ZAP firmware is OEM-owned and is **not** in this repository; the driver reads it from `C:\topaz\fw\`.

## Live result (2026-11-25, OnePlus Open, Windows 11 26300 ARM64)

```
test_turnip_a740:  vkCmdFillBuffer READBACK ptr[0]=0xdeadbeef ptr[1023]=0xdeadbeef   TURNIP_RC=0
test_inbox_d3d11 (System32 dxgi.dll + d3d11.dll -> ogpu_d3d10.dll):
  Adapter[0]: Open A740 ... ; D3D11CreateDevice(HW) hr=0 fl=0xa000
  BLIT_PIXEL[0,0] = 0xdeadbeef   PIXEL[0,0] = 0xffcc8033 (ClearRenderTargetView)   PASS
DIAG submit#1..3: rbbm=00000001 hwf=0 cpint=0 prot=0 fsr=00000400 (no faults)
```

## Contents

- `kmd/` — Option 2 sources that differ from `drivers/gpu/gpu-wddm-bridge-G779` / G1352:
  `ddi.c`, `disp.c` (GOP VidPN display path adapted from Topaz `TopazGpuW/disp.c`), `a740_wddm_bridge.c`
  (A740 bring-up bridge + ZAP/secure-mode exit), `a740_smc.S`, `topazgpu_escape.h`.
  The remaining objects are the G1350/SID0+SID1 owner closure (`experiments/G1351…`, `G1352`).
- `mesa/` — full working-tree diff against Mesa `62f1e49` (24.3-devel) used for `vulkan_freedreno.dll`,
  Zink and `ogpu_d3d10.dll`, plus the new `fd_wddm.c` (freedreno DRM backend over the escape) and
  `topaz_wddm.cpp` (d3d10umd ↔ KMD glue).
- `tests/` — `test_inbox_d3d11.c` (inbox runtime blit + clear readback), `test_dxvk_pixel.c`.

## UMD opt-in gate

`ogpu_d3d10.dll` only claims the adapter when `TOPAZGPU_ENABLE` is set (per process) or
`C:\topaz\umd.enable` exists (global); `C:\topaz\umd.dwmonly` restricts it to `dwm.exe`. Without the gate,
the D3D runtime falls back to WARP, keeping the desktop recoverable.
