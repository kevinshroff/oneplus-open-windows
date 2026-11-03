# Offline validation

- Exactly one included source changes against G1347; five bounded substitutions are pinned in BASE-AND-DELTA.json.
- Host regression executes the actual cleanup and SCTLR-write source under AddressSanitizer/UndefinedBehaviorSanitizer. Temporary masking and original restoration use only the captured CB0 pointer. Null/replaced pointer, bank, or generation refuses before a store. Retained poison/disconnected interrupts do not alone revoke original-value cleanup.
- Genuine Microsoft-header Clang ARM64 compilation passed for one broker translation unit. Fourteen COFF objects are reused byte-for-byte from actual G1347. No owner or firmware build.
- Native MSVC link passed for the 15-object broker. Independent compiled review confirmed the captured writable CB0 alias, admission and cleanup identity checks, and preserved valid timer output pointer.
- Existing-identity signing and independent PE payload/SPC digest/CMS verification passed. The owner signature and firmware are reused. See [offline qualification](OFFLINE-QUALIFICATION.json) for hashes. A successful hardware translation remains unproven.

[Boot177 hardware result](HARDWARE-RESULT.md): one hardware translation matched, controls restored, uncertainty0 and Windows remained responsive. The test issued no SQE start, packets or fence.
