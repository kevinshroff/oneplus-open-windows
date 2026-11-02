# Focused upstream review — 2026-11-02

A fresh GitHub primary-source search found no independently demonstrated SM8550 Windows port with a published fix for this response/credit stall. This is a bounded negative finding, not proof none exists. The inspected [Project-Aloha](https://github.com/Project-Aloha/mu_aloha_platforms), [onereal7](https://github.com/onereal7/msmnilePkg) and [QQBFNext](https://github.com/QQBFNext/msmnilePkg) platform listings establish firmware/DSDT targets, not working Wi-Fi on this board. [UniXNU/Ath12kWifi](https://github.com/UniXNU/Ath12kWifi) advertises transport/HAL inputs, not verified Windows networking. Linux/Proton handheld results are not Windows-driver evidence.

Two upstream mechanisms are useful for choosing the next discriminator after the single G1295 interval. Neither justifies a blind Windows patch.

## 1. CE receive ordering and zero-length error recovery

Linux commit [6b67d2cf14ea — fix ring-buffer corruption](https://github.com/torvalds/linux/commit/6b67d2cf14ea997061f61e9c8afd4e1c0f22acb9), merged 2025-05-19, adds a DMA read barrier between destination head-pointer observation and descriptor reads. It also moves zero-length rejection after advancing/reclaiming the paired receive bookkeeping, avoiding an inconsistent ring on that error path. The commit says the initial failure was observed in ath11k; its ath12k fix was tested on WCN7850 hw2.0 with `WLAN.HMT.1.0.c5-00481-…-3`.

Follow-on [8157ce533a60](https://github.com/torvalds/linux/commit/8157ce533a60521f21d466eb4de45d9735b19484), merged 2025-06-26, places ordering in the shared destination-ring access helper; [ed32169be1cc](https://github.com/torvalds/linux/commit/ed32169be1ccb9b1a295275ba7746dc6bf103e80) adds ordering before returning destination ownership, including the ring-full case. Both report WCN7850 tests.

**Applicability inference:** same chip family and ARM64 ordering make this a concrete Windows CE RX audit question. A historical hardware/software CE2-index match alone cannot prove descriptor visibility or error-path consistency. With exact loaded Windows image evidence, review head/descriptor/consumer ordering and zero-length RX handling using REA; correlate any malformed/zero-length completion with the last valid HTC trailer. Do not transplant Linux barriers into unrelated MMIO readers or assume Windows lacks equivalent ordering. The Linux firmware test identity is not established as identical to our firmware.

## 2. Shared interrupt enable ordering can silence all responses

[0a993772e0f0 — fix race due to setting EXT_IRQ_ENABLED too early](https://github.com/torvalds/linux/commit/0a993772e0f0934d730c0d451622c80e03a40ab1), merged 2024-05-28, documents a WCN7850 single-MSI case: a shared CE/data interrupt arrives before the data consumer is enabled, disables the shared IRQ, and never schedules the work that would re-enable it. The patch enables the consumer before publishing admission. This older fix was tested on the same Linux WCN7850 firmware family above.

**Applicability inference:** prioritize only if the actual Windows interrupt resources are shared and CE interrupt/DPC activity stops at the stall. Capture the assigned MSI address/data, CE RX progress and handler/DPC admission/re-enable state from the same attempt; distinguish a completion pending without service from target nonproduction. Windows does not use Linux NAPI, so the exact race is not presumed. Initial working exchanges make a permanently wrong vector less likely; later disable/re-enable loss remains a question. No interrupt injection or unowned mask write is proposed.

## Lower-priority matches rejected

[38055789d151](https://github.com/torvalds/linux/commit/38055789d15155109b41602ad719d770af507030) fixes WCN7850 **data-path TX** 128-byte IOVA alignment hangs under throughput tests; [6c40719489c8](https://github.com/torvalds/linux/commit/6c40719489c8d799798989b15bc07b0700c132f8), merged 2026-09-09, fixes Linux skb pointers after that alignment operation and was compile-tested only. Neither demonstrates an HTC control/credit-path alignment failure before association. [60031d9c3589](https://github.com/torvalds/linux/commit/60031d9c3589c7983fd1deb4a4c0bebf0929890e)'s CE-address correction was needed for AHB and describes the old constants as unused by then-current ath12k; it is not a WCN7850 PCIe stall fix.

The focused commit search did not identify a recent direct HTC-credit fix matching our Windows evidence. Continue the planned epoch observation, then select one of the two mechanisms only when fresh transport evidence supports it. No firmware replacement, binary modification, device access or live experiment was performed for this review.
