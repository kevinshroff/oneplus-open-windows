# G1345 hardware-attempt result

Boot175 reached successful GMU startup: status0, HFI1 and startup acknowledgement mask15. The QTB operation then stopped at a confirmed second-chance access violation in `KeQueryInterruptTimePrecise`, called by `QtbNow` with a null required output pointer. The retained exception context confirms the faulting store used that null pointer.

This is a software API-contract defect, **not a hardware translation failure**. No QTB translation result was returned. Source ordering places the timer call in the first halt poll, after the halt-request write call; this supports only a control-flow inference that the write call returned. It does not establish halt acknowledgement, electrical state, successful ECATS execution or cleanup. The operation did not reach SQE1, a CP fence or WDDM execution.

The exception was inspected while held, without resuming it. One existing fixed debugger reboot was dispatched successfully, with one reset attempt and zero resume calls. A fresh PE kernel, controller session and offline startup fence were subsequently verified.

[G1347](../G1347/README.md) corrects only the broker timer adapter by supplying writable local output storage. It reuses the G1345 owner and dependency-corrected firmware. That compiled correction is not a successful translation result. The original G1345 source remains preserved; this result adds no binaries or runtime authorization.

The earlier source/compiled reviews missed the required output-pointer contract. Transaction-model tests did not exercise this native timer adapter. See [VALIDATION.md](VALIDATION.md) for the scope of those checks and [HARDWARE-RESULT.json](HARDWARE-RESULT.json) for the sanitized result.
