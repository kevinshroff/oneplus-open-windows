# OpenPanelBl — inner OLED brightness (DCS 0x51 over DSI0)

Stand-alone one-shot probe/test driver used to bring up brightness control. The production path is in the
Adreno display driver ([`topazgpu-opt2/kmd/disp.c`](../../gpu/topazgpu-opt2/kmd/disp.c)), which exposes the
Windows brightness interface (`DXGK_BRIGHTNESS_INTERFACE`), so the Settings slider and
`WmiMonitorBrightnessMethods.WmiSetBrightness` work.

## Hardware facts (stock device tree + live probe, 2026-11-25)

- Inner panel: `AC052 P 1 A0002` / `AC052 P 3 A0003` — 2440×2268 DSC **command-mode** AMOLED on **DSI0**
  (`0x0AE94000`, controller v2.7, `HW_VERSION 0x20070000`), 4 lanes, 30 bpp.
- Brightness: `bl_ctrl_dcs`, `qcom,mdss-dsi-bl-inverted-dbv` → DCS long write `0x51 <hi> <lo>`, range 1..0xFFE,
  normal max 0x700 (A0002) / 0xBF3 (A0003). 100 % in Windows maps to 0x700 (perceptual square curve).
- Command DMA: UEFI leaves `CMD_DMA_CTRL=0x14000000` (low-power transmission), SW trigger. The MDSS stream
  `0x1C00` matches apps-SMMU `SMR[4]` → context bank 4 with `SCTLR.M=0`, so DMA buffers use physical addresses.

## Measured effect (battery gauges, Lenovo USB attached)

| Brightness | Battery draw |
|---|---|
| 0x700 (100 %) | −1,431 … −1,637 mW |
| 0x010 / 0x001 (0 %) | −441 … −935 mW |

Usage: service `openpanelbl`, `Parameters\Mode` (0 probe, 1 write), `Parameters\Level`; log `C:\topaz\panelbl.log`.
