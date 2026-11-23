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
