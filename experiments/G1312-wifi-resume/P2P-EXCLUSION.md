# P2P capability exclusion: negative result

A future fresh initialization can isolate the Wi-Fi Direct lifecycle using the original driver's recognized `p2pDisable` **REG_DWORD1** option. This is a proposed experiment, not a demonstrated fix. It must not replay initialization in an already-consumed boot.

The reviewed ARM64 driver is version1.0.4458.2600, SHA256:

```text
802b1f7c5325c312b710312ced0864f813beaf30ff0fceceeefd9f48b2f25d56
```

Static REA observations, expressed as RVAs for that exact image:

- Descriptor331568 names `p2pDisable`: integer input, default0, permitted range0..1, stored as one byte at configuration group3 offsetb9.
- Registry reader03dc78 applies the descriptor's bounds and width;03e790 performs the byte-sized store.
- P2P capability initializer139810 reads that byte at139870. The branch at139878 sends a nonzero value through the `cannot support P2P` log and success return, before P2P capability registration.

Boot162's last returned WMI response belongs to the Wi-Fi Direct device lifecycle; its buffer context matches the final CE2 receive. Later commands exhaust the remaining HTC credit without receiving another return. This makes excluding that lifecycle a useful discriminator. Temporal association does not prove it caused the response loss, or establish when firmware stopped during the quiet interval.

If selected, resolve the actual device **Driver software key afresh** before changing the option. Never assume a historical numeric instance. Preserve the prior presence, registry type and value for restoration. Change only this option; retain the original driver/firmware/BDF, secondary-station option, power policy, credit limits and valid IE contents. Existing boot, ownership, resource and once-only admission remain required.

The experiment must first prove the configuration reached the compiled gate and that the Wi-Fi Direct device lifecycle is absent; virtual-device numbering alone is insufficient. Then require real STA scan/channel/BSS progress and sustained returned RX credits beyond the old boundary. Association, DHCP and traffic remain separate success criteria. If the same stop recurs with the gate proved active, the simple P2P-lifecycle explanation is weakened; it does not justify an unrelated barrier or credit patch.

Root subsequently ran one fresh initialization and scan with this single option selected. The retained CPU log proves both configuration value1 and the compiled `cannot support P2P` gate; the Wi-Fi Direct lifecycle is absent. Early STA firmware scans and BSS indications still occurred, but the later HT capability SET_IE again consumed the final EP2 credit; its host sender completion succeeded, while no subsequent RX credit returned and the requested scan stayed queued. Cached networks remained empty. This excludes the simple claim that the Wi-Fi Direct lifecycle is necessary for this recurrence; it does not prove the final HT command caused it. Do not repeat this exclusion as an untested candidate.
