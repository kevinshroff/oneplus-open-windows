# OpenCpuPerf — SM8550 CPU frequency domains (EPSS)

One-shot probe/test driver for the EPSS CPU frequency hardware (`qcom,cpufreq-epss`, stock DT):
domain 0 `0x17D91000` (CPU0-3), domain 1 `0x17D92000` (CPU4-6), domain 2 `0x17D93000` (CPU7).
Register layout follows Linux `qcom-cpufreq-hw` (`epss_soc_data`). `Parameters\Mode` 0 = probe,
1 = write `PerfState0..2` (LUT index). Log: `C:\topaz\cpuperf.log`.

## OpenCpuGov — load-based governor (installed, `start= auto`)

`open_cpu_gov.c` replaces UEFI's fixed request (CPU4-6 ~2.7 GHz, CPU7 ~3.0 GHz, regardless of load).
Every 40 ms it reads per-processor busy time and requests, per cluster, the lowest LUT step
≥ 1.25 × current frequency × busiest-CPU load; ≥ 85 % busy jumps straight to the cap; it steps down only
after three consecutive lower targets. Unloading hands every domain back its cap.

Live (2026-11-25): idle → 307 / 499 / 595 MHz; 8-core load → 1228 / 2707 / 2956 MHz within 3 s; back to the
bottom steps after the load. Parameters: `Disable`, `MaxIdx0..2` (per-domain cap), `PeriodMs`; log
`C:\topaz\cpugov.log` (30 s residency averages).

Frequency tables (MHz): CPU0-3 307…2016 (16 steps), CPU4-6 499…2803 (20), CPU7 595…3187 (21).
At idle the measured battery-draw difference between bottom and UEFI frequencies is within noise (cores are
power-collapsed/WFI most of the time); the governor matters under load and for heat during activity.
