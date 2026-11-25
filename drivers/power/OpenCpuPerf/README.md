# OpenCpuPerf — SM8550 CPU frequency domains (EPSS)

One-shot probe/test driver for the EPSS CPU frequency hardware (`qcom,cpufreq-epss`, stock DT):
domain 0 `0x17D91000` (CPU0-3), domain 1 `0x17D92000` (CPU4-6), domain 2 `0x17D93000` (CPU7).
Register layout follows Linux `qcom-cpufreq-hw` (`epss_soc_data`). `Parameters\Mode` 0 = probe,
1 = write `PerfState0..2` (LUT index). Log: `C:\topaz\cpuperf.log`.
