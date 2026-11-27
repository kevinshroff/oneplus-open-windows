# Audio (speakers) - OnePlus Open, SM8550

**Status (2026-11-27): the internal speakers play PCM.** A 440 Hz test tone streamed from Windows through the ADSP
(AudioReach SPF) and the Secondary TDM port to the three NXP TFA9873 amplifiers is audible; all PCM buffers retire
with status 0. Not done yet: a Windows audio endpoint (WaveRT/port-class driver) and volume control - playback is
currently driven by a test harness through `OpenChargerKeeper` ioctls.

## Signal path

```
Windows (OpenChargerKeeper ioctls)
  -> shared PCM buffer (contiguous RAM, hyp-assigned to the ADSP, mapped in apps-SMMU CB11/CB12 at IOVA 0x1_10000000)
  -> GLINK adsp_apps -> AudioReach APM graph:
       WR_SHARED_MEM_EP (0x07001000) -> GAIN (0x07001002) -> TDM_SINK (0x0700100E)
  -> LPASS Secondary TDM (GPIO 121 BCLK, 123 FSYNC, 124 data out)
  -> 3 x TFA9873 (QUPv3 SE6 I2C 0x34/0x35/0x36, resets GPIO 50/173/56)
```

Working configuration (`drivers/audio/tools/speaker_tdm_tone.py`):

| Item | Value |
|---|---|
| Stock backend (from the device tree audio plan) | Secondary **TDM** RX0 (TDM enabled, MI2S disabled, up to 4 slots) |
| Sink module | `MODULE_ID_TDM_SINK 0x0700100E` (present in the ADSP image's built-in module table next to I2S `0x0700100A`) |
| Interface config | `PARAM_ID_TDM_INTF_CFG 0x0800101A`: `lpaif_type 0`, `intf_idx 1` (Secondary), internal frame sync, data out enabled, slot mask `0x3`, 2 slots x 32 bit, long frame sync, 1-cycle data delay (I2S-shaped framing) |
| HW endpoint media format | 48 kHz, 32-bit, 2 channels (`0x08001017`), frame-size factor 1 (`0x08001018`) |
| Bit clock | PRM `CLOCK_ID 0x202` (Secondary TDM/PCM IBIT) at 3.072 MHz, voted after the graph is open |
| PCM endpoint media format | 48 kHz, 32-bit (Q31), 2 channels |

## Why it was silent before

1. **Wrong backend type.** Earlier attempts used the I2S sink (`0x0700100A`); the speakers are wired to the Secondary
   **TDM** port.
2. **Wrong LPAIF type.** `lpaif_type 5` was never verified. A sweep of LPAIF type 0-5 x interface 0-3 while sampling the
   TLMM input levels showed only `type 0 / idx 1` drives the frame-sync pin (GPIO 123); with every other value the bit
   clock ran (it is voted independently) but no frame was produced, so the amps never locked.
3. **SMMU permission fault on the PCM buffer.** The Stage-1 page-table entries were `0x703` (AP=00, privileged-only).
   SMMU masters issue unprivileged accesses, so the ADSP's first read of IOVA `0x10000000` took a level-3 permission
   fault (`CB11 FSR 0x40000408`) and stalled (SCTLR stall-on-fault) - the endpoint accepted buffers but never retired
   them. `OpenChargerKeeper` v24 uses `0x743` (AP=01).

Also learned: every buffer the DSP holds consumes one of its GLINK receive intents for us; queuing more unconsumed
buffers than the intent budget wedges the `adsp_apps` channel until reboot. The harness keeps at most 3 in flight and
only streams when the amplifiers report a frame (TFA9873 reg `0x10` no longer `0x0016`/`0x0017`).

## Next

* Amplifier volume/mute and a sane default gain (the first full-scale tone was very loud).
* A Windows audio endpoint (WaveRT miniport) feeding this graph so apps and the volume slider work.
* Microphones (WCD938x over SoundWire) after that.
