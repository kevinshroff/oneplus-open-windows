# Retained G1325 CPU page-table audit

Offline auditor for the [completed G1325 witness](../G1325-pre-release-witness/HARDWARE-RESULT.md). The actual retained capture passed: all 29 GPU pages matched the locked-MDL PFNs, all 1,536 table slots matched, and all nine before/after pairs were identical. No new GPU start was needed.

The auditor reads files only. It never opens a debugger/device, maps memory, invokes the driver, changes tables or establishes hardware translation. Its inputs and detailed output contain runtime addresses and should stay private.

## Input and layout contract

The input plan uses `G1325-retained-published-CPU-copy/1` and names 18 separately captured files: retained global, owner, CP state, three-page pool, range records and four MDLs, each before and after. `files` maps each role to its exact `name` and `bytes`. Other fields include actual `BootId`, `phone_session`, `expected_root_physical` and `expected_run_id`. No sample runtime plan or capture is shipped.

Offsets apply to the reviewed G1325 ARM64 owner only (unsigned SHA-256 `5018590d9c8cbee2f45618d178a42cfe953ae6e6065c32831ff9ea30dd610bcc`). Its actual compiled retention path and Microsoft-header layouts were checked before the bounded snapshot. The driver keeps the separately allocated owner and CP objects after the intentional failure; the deleted device extension was not followed. Obtaining and qualifying a capture is a separate operator responsibility. This script cannot authenticate a live module, allocation lifetime or input provenance.

The expected profile is lower 39-bit input, 36-bit output, 4 KiB pages and 29 leaf pages: eight ring, one read-pointer, 19 SQE and one BV page. It compares all descriptor slots, including the 1,505 unused slots, against independently captured MDL PFNs and the fixed source permissions/cache policy. It never follows a descriptor outside the captured pool or calls the original inactive-audit/currentness callbacks on a published root.

```sh
python3 audit_captured_graph.py --plan PRIVATE_PLAN.json --captured-dir PRIVATE_CAPTURE_DIRECTORY --out NEW_PRIVATE_RESULT.json
```

A pass establishes consistency of these captured CPU bytes with the expected source graph and MDLs. The earlier native witness separately checked the SQE payload; these 18 files contain no SQE payload. GPU fetch, SMMU visibility/coherency, client transaction identity, interrupts, completion and acceleration remain unproved.
