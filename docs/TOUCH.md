# Inner touch (G98 / GT9966 over SPI) - reliability notes

## 2026-11-27: touch dying after a while / after lock-unlock

Live diagnosis (runtime ioctl `0x226414`, fault ioctl `0x22641C`, snapshot `0x226004` on `\\.\OpenG100Keys`):

1. **Trigger - a torn multi-finger frame ended the session.** Frames with more than two contacts are read in two SPI
   transfers (26-byte prefetch + tail); the controller can update its buffer in between, so the body checksum fails
   (captured: 3 contacts, sum `0x054F` vs stored `0x0460`). The poll loop treated that - and any unsupported event
   (gesture/pen/unknown flags) - as fatal (`G98_POLL_DECODE`), ending the touch session.
   **Fix (`g98_poll.c`):** acknowledge and drop the frame, keep polling. Releases are header-only frames without a
   body checksum, so a dropped move frame cannot leave a contact stuck.
2. **Why it never came back.** Restart admission (`g98_hardware.c`) was a one-way latch: a single failed PMIC/register
   observation set `G98ObserverFault` for the life of the driver image. The observation itself failed because the
   fixed-register baseline demanded the RSC `RESP_DATA` history word (`0x17A20D44`) be 0 or 7; after an aborted
   session it holds the last vote response (`0x80000001`) forever.
   **Fix:** every admission re-runs the read-only observation (no latch), `RESP_DATA` is treated as history (every
   other fixed register must still match exactly), and the worker retries once per second.
3. **Diagnostics.** The runtime ioctl now always reports the latest attempt's codes; for admission refusals
   (`hwCode 1011`) `PollCode` carries the `334xx` stage and `TouchCode` the guard bits, observed supply status
   (bits 8-15) and observer code (bits 16-31).

Remaining gap: if an aborted session leaves the touch supply's RPMh vote on (PMIC status `0xC7`), admission still
refuses (it requires the supply off) until reboot. An attempt to release that vote from the admission path
(`G98SupplyReclaim`) bugchecked (0x50 in `OpenG98.sys`) and was backed out; with fix 1 the trigger is gone.
