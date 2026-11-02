# Defined checkpoints

These counts describe the checklists below, not elapsed effort or a compatibility percentage. A checkpoint is complete only where native evidence exists. Hardware listed as unfinished may have research or prototype code. Historical success does not prove current device liveness.

## UEFI / ACPI — 4/6 complete

- [x] OEM boot-chain integration.
- [x] Custom DXE/ACPI resources.
- [x] Windows boot-manager handoff.
- [x] WinPE and full Windows boots.
- [ ] Portable public build/reconstruction workflow.
- [ ] Cold-start and recovery hardening.

## CPU — 2/4 complete

- [x] Windows ARM64 execution.
- [x] Eight logical processors enumerated.
- [ ] Platform DVFS/performance qualification.
- [ ] Idle and thermal-policy qualification.

## RAM — 2/4 complete

- [x] Usable Windows memory map.
- [x] Native allocations used by the working system.
- [ ] Full-capacity/stress qualification.
- [ ] Memory retention across suspend.

## UFS / installation — 3/5 complete

- [x] 4 KiB-sector filesystem integration.
- [x] Windows-compatible partition typing.
- [x] Installed Windows boots from internal storage.
- [ ] Reproducible installation/servicing workflow.
- [ ] Power-loss and storage-performance qualification.

## Inner display — 2/5 complete

- [x] Windows framebuffer desktop.
- [x] Usable desktop scaling.
- [ ] Accelerated presentation.
- [ ] Brightness management.
- [ ] Display sleep/wake lifecycle.

## Cover display / folding — 1/4 complete

- [x] Cover framebuffer cleared and verified black.
- [ ] Electrical panel-off.
- [ ] Fold-driven panel switching.
- [ ] Cover touch/display integration.

## Touch — 3/5 complete

- [x] Controller transport and report decoding.
- [x] Native HID/VHF input.
- [x] Sustained touch demonstrated by physical use.
- [ ] Complete fold/panel/stylus/palm coverage.
- [ ] General suspend/resume qualification.

## Physical buttons — 1/3 complete

- [x] Integrated cached hardware reader.
- [ ] Physical power-button display-off test.
- [ ] Physical second-press wake test.

## GPU / WDDM — 3/8 complete

- [x] Kernel resource/ownership foundations.
- [x] GMU firmware and HFI acknowledgements.
- [x] CPU-verified GPU buffer/table preparation.
- [ ] First CP command/fence completion.
- [ ] Repeatable submission, interrupts and completion.
- [ ] A740 WDDM memory/scheduling/DDI integration.
- [ ] Hardware-backed userspace graphics integration.
- [ ] Application rendering and desktop presentation.

## Wi-Fi — 3/6 complete

- [x] PCIe enumeration and register access.
- [x] Firmware load and initial exchanges.
- [x] Original Windows driver/interface initialization.
- [ ] Sustained firmware responses/credits.
- [ ] Stable scan, authentication and association.
- [ ] DHCP, DNS and real network traffic.

## USB — 3/6 complete

- [x] USB device/debug enumeration.
- [x] Kernel-debug and control data transport.
- [x] Read-only USB storage recovery demonstrated.
- [ ] External host keyboard/HID support.
- [ ] Reliable role switching.
- [ ] PD/power integration.

## Debugging / recovery — 4/6 complete

- [x] Kernel debugging.
- [x] Authenticated remote-control workflow.
- [x] Guarded one-shot boot/recovery workflow.
- [x] Sahara emergency reset demonstrated.
- [ ] Reliable reconnection after every crash.
- [ ] Actionable capture of the current GPU fatal boundary.

## Battery reporting — 1/4 complete

- [x] Raw physical sensor acquisition demonstrated.
- [ ] Installed Windows battery-class frontend.
- [ ] Validated pack/percentage/rate semantics.
- [ ] Sustained normal-Windows lifecycle.

## Charging — 1/4 complete

- [x] Bounded WinPE tests measured charging current.
- [ ] Sustained normal-Windows charging.
- [ ] Reliable USB-C/source negotiation.
- [ ] Complete safety/thermal/full-charge policy.

## Power management — 1/5 complete

- [x] Working awake profile for development.
- [ ] System suspend/resume.
- [ ] Display/power-button lifecycle.
- [ ] Idle clock and rail policies.
- [ ] Thermal/performance policies.

## Audio — 0/3 complete

- [ ] Windows audio-device integration.
- [ ] Speaker playback.
- [ ] Microphone capture.

## Bluetooth — 0/3 complete

- [ ] Windows radio integration.
- [ ] Pairing.
- [ ] Actual peripheral traffic.

## Motion / light / proximity sensors — 0/3 complete

- [ ] Windows sensor integration.
- [ ] Validated readings.
- [ ] Orientation/automatic-policy integration.

## Cameras — 0/3 complete

- [ ] Sensor/ISP initialization.
- [ ] Windows camera integration.
- [ ] Validated capture.

## Cellular — 0/3 complete

- [ ] Modem/SIM service integration.
- [ ] Network registration.
- [ ] Usable data/call paths.

## GNSS — 0/2 complete

- [ ] Windows location integration.
- [ ] Validated positioning.

## NFC — 0/2 complete

- [ ] Windows NFC integration.
- [ ] Functional transactions.

## TPM / production boot security — 0/3 complete

- [ ] Working Windows TPM integration.
- [ ] Production Secure Boot configuration.
- [ ] Security qualification without development test-signing.

## Important limits

- The working display is a framebuffer path; GPU acceleration is not working.
- Black cover pixels do not establish electrical panel-off.
- Firmware readiness, scan notifications and a visible Wi-Fi adapter do not establish connectivity. Earlier experiments observed AP beacons, but reliable networking remains unfinished.
- Raw battery sensing and a bounded charging experiment do not establish safe everyday Windows charging. The latest GPU dependency parent is clock-only; older continuously sampling sensor results are historical.
- Buttons have a healthy reader; physical display-off/wake validation was deferred.
- CPU frequency control, full RAM capacity/performance, general USB host operation and production suspend/resume are not claimed.
