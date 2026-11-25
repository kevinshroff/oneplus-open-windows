# OpenChargerKeeper (OnePlus Open / SM8550)

Always-on KMDF 1.15 battery charging watchdog for **both WinPE and Windows 11**.

## Design
- **ADSP GLINK (`0x81e9f000` + `0x408000`):** Reuses the proven `G155`/`G177`/`G178` SMEM/IPCC charger router (`owner 0x800a`) already present in our `G991`/`G1345` boot firmware.
- **Real physical gauges (`0x880000` + `0x98c000`):** Reuses `G104Identify` to poll both ZY0602 I2C fuel gauges every 10 seconds (ADSP's cached GLINK battery fields return dummy values `50%/25C/4.0V` on this board).
- **Zero hardware conflict:** Does not touch `G379` touch SPI/PMIC, `G746` clock parent, `abi7` Wi-Fi, or GPU MMIO.
- **Safety & dev-tethered hysteresis:**
  - Charges on any online USB source (SDP/CDP/DCP) via `FV = 4470 mV`, `prop 24 = 0`, proven 5s gap, `prop 24 = 1`.
  - Pauses at `>= 85%` SOC or `>= 4300 mV`; resumes at `<= 75%` SOC and `<= 4150 mV`.
  - Hard cutoffs: temperature `< 5.0 C` or `> 43.0 C` (recovers inside `10..39 C`), cell voltage `> 4450 mV`, cell imbalance `> 300 mV`, or 3 consecutive gauge read errors.
- **Control device:** `\\.\OpenChargerKeeper` (`IOCTL_CK_STATUS`, `IOCTL_CK_PAUSE`, `IOCTL_CK_RESUME`).

## v4 (2026-11-25)

- **USB input telemetry:** four extra ADSP GETs on `USB_PROPERTY_GET` (opcode 0x32): input voltage (1), input
  current (3), max current (4), input current limit (5). They never fail a sample. `ck-status` shows them under
  `usb_in` (µV/µA). Measured on the Lenovo USB-C port: 5.0 V, 450 mA drawn, port max 900 mA, charger limit 1.5 A.
- **Gauge identity fix:** the first gauge word is the ZY0602 control-status word. Its low bits are live flags
  (seen 0x6002 and 0x6000), so only `0x600x` is required now. Before, a flag change on one gauge made every
  physical read fail and the keeper silently fell back to ADSP placeholder values (4000 mV / 50 % / 25 °C).
- **Diagnostics:** status now carries the last gauge attempt (code, stage, preflight masks, QUP clock snapshot,
  query mask, raw words) under `gauge_diag`.
- Status struct grew from 176 to 368 bytes. All fields are appended, so v3 offsets are unchanged.
