# Display pipeline and smoothness (OnePlus Open, SM8550)

Goal: OS-wide smooth UI (Explorer drag, Start animations, Edge scroll). This page tracks the display path in
`topazgpu_opt2.sys` (`drivers/gpu/topazgpu-opt2/kmd/disp.c`).

## Hardware as UEFI leaves it

| Block | Address | State at hand-off |
|---|---|---|
| MDSS / MDP | `0x0AE00000` (hw 0x90000001) | command-mode panel, autorefresh, CTL0 |
| VIG0 / VIG1 source pipes | MDP `+0x5000` / `+0x7000` | each fetches half the 2440x2268 panel (1220 px), `SRC0_ADDR` = `0xB8000000`, stride 9760 |
| CTL0 | MDP `+0x16000`, flush `+0x18` | flush bits VIG0 (0), VIG1 (1), CTL (17) |
| MDSS stream `0x1C00` | apps SMMU `0x15000000`, SMR4 -> CB4 | CB4 `SCTLR=0xE0` (translation **off**, bypass) |

Found with the read-only probe `drivers/display/OpenPanelBl/mdp_probe.c`.

## Why it stuttered

DWM rendered on the GPU in 1-2 ms, but every flip was copied by one CPU core from write-combined memory into the
GOP framebuffer: 22 MB per frame, 20.6 ms average (43 ms worst), unsynchronised with the GPU and the panel. That
capped the desktop near 45 fps with visible hitches.

## Step 0/1 - measurement and a better copy (fallback path)

* `FRAME` / `HB` lines in `C:\TopazGpuW.log` every 5 s: flips requested/done, copies, copy time, GPU fence waits.
* A flip is reported done only after its copy finished (no torn or early frames); the copy waits for the
  buffer's GPU fence first.
* The copy runs on 4 pinned worker threads (CPUs 4-7): 14.8 ms average instead of 20.6 ms.

## Step 3 - zero-copy direct scanout (default)

Physically contiguous 24 MB buffers below 4 GiB are not available (`contig_probe`), so the display engine reads
DWM's scattered pages through the SMMU instead:

1. At `DispStart` the driver builds its own stage-1 tables for CB4: an identity map of 2-4 GiB with 1 GiB blocks
   (keeps the boot framebuffer and DSI command buffers working) and turns translation on. CB4 must be
   programmed the way Linux `arm-smmu` does it (`TCR2 = SEP_UPSTREAM | AS | PASize`, `TCR` with `SH0`, TTBR0 with
   ASID): with UEFI's `TCR2` every fetch translation-faults (`cb4_probe.c` shows both cases).
2. Each full-screen BO DWM creates is mapped page by page into a 32 MB slot at IOVA `0x10000000 + n*32 MB`
   (`DispAllocCreated`), and unmapped when destroyed (after the pipes have left it).
3. A flip writes the slot address and the buffer's pitch (9984) to VIG0 and VIG1 and flushes CTL0; the flip
   completes when the flush bits clear (bounded wait). Flips of buffers the GPU is still rendering are deferred
   to fence completion.

Safety: if CB4 reports a fault at enable or at any later 5 s check, the driver points the pipes back at the
framebuffer, turns direct mode off and continues with the copy path. `C:\topaz\gpuw.nodirect` disables direct
scanout at the next boot.

Result: per-frame CPU cost of presenting drops from ~15-20 ms of copying to a few register writes; no CB4 faults
observed.

## Step 2 - GPU clock scaling (DCVS)

The GMU firmware only changes the GPU/DDR operating point on an HFI 30 vote; startup voted index 1 (124.8 MHz,
lowest DDR) and nothing changed it afterwards. The bridge (`a740_wddm_bridge.c`) now runs a governor:

* a 2 ms high-resolution timer samples whether the GPU has unfinished submissions (only while the GPU is active;
  it parks after ~1 s idle at the floor and the next submit wakes it);
* every ~48 ms it picks the lowest level that would run the GPU about 65 % busy (>= 90 % busy jumps two levels),
  steps up at once and down one level after 3 quieter windows; range index 1..8 = 124.8..615 MHz, DDR index
  follows the GPU index;
* votes use HFI 30 `{ack, gpu, bw}` through the existing g190 queue code, but with an ops table owned by the
  driver (own mapping of the GMU core window `0x03D6A000`): the startup sequence's ops report "lease lost"
  once startup has finished. A self-test at start (220 MHz and back) must pass; the first failed vote turns the
  governor off. `C:\topaz\gpu.nodcvs` disables it. `HB` log lines show `dcvs idx/busy/votes`.

## Step 5 - CPU governor tuned for UI (OpenCpuGov v2)

`drivers/power/OpenCpuPerf/open_cpu_gov.c`:

* 20 ms high-resolution tick (the old 40 ms kernel wait really ran at ~47 ms), 1.4 x headroom, jump to the cap
  at >= 75 % busy (was 85 %), down-steps still need 3 quieter ticks;
* UI boost: `topazgpu_opt2` signals `\BaseNamedObjects\OpenUiActivity` (from its vsync DPC) whenever DWM flipped a
  frame; while frames are being produced and for 200 ms after, the performance clusters are held at >= 1.4 GHz
  and the efficiency cluster at >= 1.0 GHz. Idle behaviour is unchanged (all clusters at their lowest step).
  Registry `Parameters\UiBoost=0` turns it off; `cpugov.log` reports `ui-boost samples`.

## Still to do

* Step 4: 120 Hz. The inner panel is "AC052 P 3 A0003 dsc cmd mode panel" (stock `dtbo` overlay). Its 60 and
  120 Hz `timing-switch-command` sequences differ only in `6D 01` -> `6D 00` and the last parameter of the `35`
  packet, and all modes use the same DSI bit clock (1.636 Gbps), so the switch is a panel command sequence plus
  reporting 120 Hz to Windows. Not implemented yet.
* Caution for research probes: reading MDP blocks that are not in the stock DT (guessed ping-pong offsets) hard-hung
  the phone. Only read blocks the DT lists.
