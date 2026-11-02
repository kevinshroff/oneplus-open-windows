# Resumed Wi-Fi observation

One original-driver initialization succeeded without a reboot request. The host log records real target scan activity and six management-receive/BSS indications, followed by loss of returned HTC credits/WMI responses. The explicit scan API returned success and an interface notification arrived, but the cached network list was empty and the interface remained disconnected. Association, DHCP and traffic remain unproved.

The pre-initialization device had no allocated BAR resource, so no G1295 baseline or fault-epoch comparison was manufactured.

The20KiB CE2 history contained successful receive/repost activity and no retained zero-length-reap event. Its final receive context matches the last WMI response in a separately captured, coherent host log. About1.61seconds after that response, HT SET_IE consumes the remaining credit and receives host sender completion; subsequent commands remain queued without returned credits. Silence during that interval does not prove when firmware stopped or that the valid HT command caused it. The evidence does not justify a speculative barrier patch or credit injection.

The last response belongs to a Wi-Fi Direct device lifecycle. Compiled-source review qualified `p2pDisable` as an optional single-variable capability-exclusion experiment for a future fresh initialization. It is a causal isolation candidate, not a demonstrated fix; no configuration change or additional initialization was performed. Raw captures, identities, descriptors and operator recipes remain private. Working networking is still unfinished.
