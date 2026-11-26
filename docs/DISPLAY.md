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

* Step 4: 120 Hz - **works, opt-in** (`C:\topaz\panel.120hz`; then pick 120 Hz in Settings > Display >
  Advanced display, or any SetDisplayConfig caller).
  * The panel already runs at 120 Hz: the bootloader leaves the AC052 P panel in its 120 Hz mode and MDP
    autorefresh pushes a frame per panel TE (INTF1 frame counter `+0x0AC` vs the 19.2 MHz counter `+0x214`; logged
    as `refresh: panel measured ...` at start). No panel commands or link-clock changes are needed.
  * With the flag file the driver offers 60 Hz (preferred) and 120 Hz target/monitor modes, adds an EDID DisplayID
    1.3 extension with a Type I 120 Hz timing (a base-EDID DTD cannot exceed 655.35 MHz), and follows the refresh
    Windows commits (vsync timer, `GetScanLine`).
  * Root cause of the earlier DWM crash loop (`0xC00001AD`, ~400 x 24 MB swapchain buffers a minute):
    `DxgkDdiDescribeAllocation` reported every allocation as 60 Hz, so at 120 Hz Dxgkrnl saw each new DWM primary
    as belonging to another mode and DXGI rebuilt the swapchain in a loop. It now reports the committed refresh.
  * Shutdown at 120 Hz hung once: the vsync timer could be re-armed by the 1 ms flip-poll kick DPC or by
    `CommitVidPn` while `DispStop` deleted it. Teardown now sets a stop flag checked by every re-arm path, drains
    DPCs and deletes the timer under its lock; a reboot from 120 Hz then shut down cleanly and booted back at 120.
  * Recovery if a display build ever crash-loops: delete `C:\topaz\panel.120hz` (60 Hz only) and, if Windows
    insists on a saved mode, remove the subkeys of `HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\
    Configuration` and `...\Connectivity` (Windows rebuilds them).
* GPU governor fix: the DCVS sampler was woken from the one-time init submit instead of `HwSubmit`, so it never ran
  and the GPU sat at 124.8 MHz. It is now kicked per submit, and while DWM is flipping frames (+200 ms) the GPU is
  held at >= 615 MHz (index 8) because the sampler under-reads DWM's short bursts (only while frames are being
  flipped, +200 ms; continuous video playback therefore runs the GPU at 615 MHz).
* Benchmark (zero-copy, 60 Hz, window drag at 60 moves/s): no CPU copies, GPU 0.26 ms/frame, CPU 5 % total, but
  DWM still averaged 25.8 ms per frame - flips latch on the 120 Hz TE but are completed on the next 60 Hz software
  vsync tick, so DWM often misses a period.
* Pacing fix (v0.51): while a flip is pending or waiting for its GPU fence, the vsync timer polls every 1 ms, so the
  flip is reported done the moment the MDP latches it and the vsync phase locks to that latch; with nothing pending
  the timer returns to one tick per period. `PACE` lines in the log count the switches.

| Window drag, 10 s at 60 moves/s (zero-copy, 60 Hz) | DWM frame interval | flips completed |
|---|---|---|
| before pacing fix | 25.8 ms (~39 fps) | 341 |
| after pacing fix (v0.51) | 18.1-19.5 ms (~53 fps) | 592 |

120 Hz, window drag at 120 moves/s (zero-copy), per-flip `PACE` statistics:

| Build | DWM present interval | flips in the run | present -> flip done |
|---|---|---|---|
| 120 Hz, GPU governor not running | 17.4 ms (~57 fps) | 673 | 10.3 ms |
| + DCVS kicked per submit | 14.1 ms (~71 fps) | 800 | 8.1 ms |
| + 401 MHz GPU floor while flipping | 12.5-13.5 ms (~77 fps) | 903 | 5.9 ms |
| + 615 MHz GPU floor while flipping | 11.4-11.7 ms (~87 fps) | 980 | 5.5 ms |
| + 680 MHz GPU/DDR floor (idx 9), 500 us latch poll, CPU UI-boost 1.3/2.2/2.4 GHz, no UMD disk logging | **8.83-9.17 ms (~113 fps)** | **1228** | **4.04-4.13 ms** |

Key changes that moved 120 Hz window drag from ~87 fps to **~113 fps** (`8.83 ms/frame` steady state, `max present->done 8.54 ms`, zero hangs/faults):

* **`a740_wddm_bridge.c`**: raised `DCVS_MAX_IDX` / `DCVS_UI_IDX` from 8 (615 MHz) to **9 (680 MHz + DDR BW 9)** while flipping (parks back at 125 MHz idle).
* **`disp.c`**: tightened active-flip polling from 1 ms to **500 us** (still 0 ticks/s at idle), relaxed the post-latch hold-back guard from `VSYNC_PERIOD - VSYNC_PERIOD/8` to `VSYNC_PERIOD / 2`, and added a 100 ms `g_Deferred` safety timeout so a stalled fence cannot trigger a `0x116` TDR bugcheck.
* **`open_cpu_gov.c`**: raised active-flip UI-boost floor (+200 ms) from `{1.0, 1.4, 1.4}` GHz to **`{1.3, 2.2, 2.4}` GHz** (idle remains `307 / 499 / 595` MHz).
* **Production hygiene**: removed `C:\ProgramData\topaz\umd.log.enable` / `umd.env` (eliminating per-frame synchronous disk logging) and removed the diagnostic `WAITS` counters from `ddi.c`/`msm.c`.

Flip queueing (v0.53) is implemented but opt-in (`C:\topaz\flipq2`): with `MaxQueuedFlipOnVSync = 2` and
`FlipOnVSyncWithNoWait`, DWM still never submitted a frame before its previous one completed (queue counter stayed
0), so it changed nothing. Each frame is now ~5.5 ms from present to on-screen (waiting for the next panel TE) plus
~6 ms of DWM's own work, which includes ~1.4 CPU waits on the GPU per frame inside the UMD (Mesa waiting for buffers
the GPU still uses). Removing those waits in the UMD is the next lever for a steady 120 fps.

  The drag script itself caps this test at 60 updates/s; for comparison the original CPU-copy path needed 20.6 ms
  just to copy each frame.
* Caution for research probes: reading MDP blocks that are not in the stock DT (guessed ping-pong offsets) hard-hung
  the phone. Only read blocks the DT lists.
