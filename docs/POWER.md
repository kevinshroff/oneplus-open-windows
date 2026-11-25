# Power, brightness and thermals (2026-11-25)

Measured live on the OnePlus Open (Windows 11 26300, Adreno 740 desktop path active), phone on the Lenovo's
USB-C port. Total power = USB input (ADSP, keeper v4 `usb_in`) + battery (two ZY0602 gauges).

## What was done

| Change | Component | Effect |
|---|---|---|
| Inner-panel brightness (DCS 0x51 over DSI0), Windows slider/WMI, backlight off on screen-off | `topazgpu-opt2/kmd/disp.c` | 100 % → 0 %: **−0.7 … −1.0 W** |
| Display auto-off (Windows timeout 2 min) | power plan | display off: **−0.36 W** |
| Vsync timer: 60 Hz on demand instead of a 1 ms timer + global 1 ms timer resolution | `disp.c` | 640 → 60 wake-ups/s (within meter noise at idle) |
| CPU governor (EPSS): idle 307/499/595 MHz instead of UEFI's 1.7/2.8/3.2 GHz requests | `drivers/power/OpenCpuPerf/open_cpu_gov.c` | within noise at idle (cores mostly power-collapsed); lowers voltage/heat under load |
| Wi-Fi power-save defaults restored (debug overrides removed) | registry + boot guard | within noise |
| Charger keeper v4: real gauge data again, USB input telemetry | `OpenChargerKeeper` | correct safety telemetry |
| Brightness default 0 % (power plan) | power plan | dev sessions start dim |

## Where the power goes now (idle, display off)

- Total ≈ **2.7 W**: USB 2.25 W (5.0 V × 450 mA) + battery ≈ 0.45 W.
- The Lenovo port supplies USB default power (the ADSP reports 900 mA max, the charger draws ~450 mA), so on that
  port the phone still drains slowly; the 65 W charger is net-positive.
- GPU path costs ≈ 0.1 W at idle; it already runs at its lowest DCVS level (124.8 MHz, HFI 30 `{1,1,1}`).
  Inter-frame GPU power collapse (IFPC) is deferred: ≤ 0.1 W to gain, high risk to the accelerated desktop.
- CPU deep idle: Windows shows C1/C2 residency but **no C3 (cluster/system power collapse)**. Platform low-power
  idle (ACPI `_LPI` cluster states, RPMh/CX/DDR scaling, S0ix) is the largest remaining opportunity and needs
  UEFI/ACPI table work.

## Tools

- `C:\OpenG17\ck-status.exe` — battery, charger, USB input, gauge diagnostics.
- `meter.ps1` sampling (battery mW, USB mW, temps, CPU %) → `C:\topaz\power.log`.
- `C:\topaz\cpugov.log` — governor frequency residency every 30 s.
- Brightness: Settings slider, or `WmiMonitorBrightnessMethods.WmiSetBrightness`.
