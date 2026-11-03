# G1347 hardware result

The corrected timer ran beyond the previous null-output-pointer failure. GMU startup again returned success, with HFI running and startup acknowledgement mask15. The attempt then stopped at bugcheck `0x50` on a store in `QtbSctlrWrite`, before producing a translation result.

The held CPU instruction was `str w19,[x8]`. The page-table entry for the destination resolved to physical `0x03dc0000`, the CB0 control-register page, and was read-only. Source and linked-code inspection agree: `QtbSctlrWrite` used the broad diagnostic SMMU mapping, whose range is intentionally mapped read-only. This is a software mapping-permission defect; it does not establish a failed hardware translation.

The attempted masked control value was `0x00c00127`. Source ordering places this write after a successful halt-acknowledgement poll, which is a control-flow inference from the observed fault location. There is no completed ECATS result, SQE1 write, command packet, fence or WDDM result.

The existing fault owner already holds a writable, noncached mapping of this exact CB0 page. The next correction will reuse that narrow mapping for the SCTLR store, with captured identity and lifetime checks. The broad diagnostic mapping remains read-only; no new firmware or resource grant is needed.

The held failure was inspected without resuming it. One fixed debugger reboot was dispatched, and a fresh WinPE kernel was observed. Recovery startup fencing is recorded separately by the operator before any further normal boot.
