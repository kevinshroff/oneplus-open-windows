# OpenWcnSleepClk — WCN7850 32.768 kHz Sleep Clock Fix (OnePlus Open / SM8550)

## Root Cause of the ~2.4s WCN7850 Firmware Stall
On the OnePlus Open (SM8550 / Kalama) running native Windows 11 ARM64 with Qualcomm's stock `qcwlanhmt8380.sys` driver (`PCI\VEN_17CB&DEV_1107`):
- WCN7850 booted, completed initial scan, and then stalled ~2.4–2.5s after start with WMI TX credits exhausted.
- Live BAR0 Window 1 register inspection (`wcn_ce.sys`) proved WCN7850 hit a firmware assertion:
  - `BHI_ERRCODE` (`+0x130`) = `0xCAFECACE` (`DEVICE_RDDM_COOKIE`)
  - `BHI_ERRDBG2` (`+0x138`) = `0x014FEEAB` → `"cmnos_thread_patch.c"` in `wlanfw20.mbn`
  - `BHI_ERRDBG3` (`+0x13C`) = `0x00000496` → line `1174`
- Firmware ETW logs (`FWLOG`) immediately preceding the assert showed:
  - `[whal_wmac_recipes_patch.c:2579] After sync attemp 0..3 aon_pmm_sync_success 0 GLOTIM_US_TIMER_H: 0 GLOTIM_US_TIMER_L ... SLP_TMR_VAL_HI 0 SLP_TMR_VAL_LO 0`
- Live SPMI PMIC Arbiter inspection of **PMK8550** (`SID=0`) proved **GPIO3 (`ppid=0xBA`, `apid=0x23F`, `owner=0` APSS)** — which routes the 32.768 kHz `pmk8550_sleep_clk` to WCN7850 on SM8550 — was left in input/pull-down mode (`[40..43]=00040000`, `[44..47]=00800100`) instead of `func1` output (`[40..43]=00050001`, `[44..47]=00800302`).

## Fix
`OpenWcnSleepClk` (`open_wcn_sleep_clk.c`) is a minimal System-Start (`Start=1`) WDM driver that locates PMK8550 GPIO3 (`SID=0, PPID=0xBA, EE=0`) in the SM8550 SPMI v7 PMIC Arbiter (`0x0C402000` / `0x0C42D000`) and configures it via the APSS write channel (`0x0C500000 + apid * 0x1000`) as `func1` 32.768 kHz `sleep_clk` output before `qcwlanhmt8380.sys` starts:
- `0x40 MODE_CTL = 0x01` (output)
- `0x41 DIG_VIN_CTL = 0x00` (power-source 0)
- `0x42 DIG_PULL_CTL = 0x05` (no pull)
- `0x44 DIG_OUT_SRC_CTL = 0x02` (`func1` = 32.768 kHz `sleep_clk`)
- `0x45 DIG_OUT_DRV_CTL = 0x03` (high drive)
- `0x46 EN_CTL = 0x80` (`PERPH_EN = 1`)

## Live Hardware Verification (OnePlus Open, Windows 11 26100 ARM64)
With `OpenWcnSleepClk` enabled and **stock unmodified `qcwlanhmt8380.sys`**:
- **Association:** Connected (`802.11ax`, `286.8 Mbps` TX/RX, `-64 dBm`, `78%` signal, WPA2-Personal CCMP), sustained 16+ minutes with zero stalls or firmware asserts.
- **DHCP IPv4:** Lease acquired (`192.168.70.41/24`, gateway `192.168.70.1`).
- **ICMP Ping (`1.1.1.1`):** `5/5` packets received, `0%` loss, `5–7 ms` RTT (`avg 6 ms`).
- **DNS (`nslookup google.com`):** Resolved IPv4 (`142.250.201.110`) and IPv6 (`2a00:1450:4019:810::200e`).
- **HTTPS (`curl.exe`):** `https://1.1.1.1` → `HTTP/1.1 301`, `https://github.com` → `HTTP/1.1 200 OK`.
