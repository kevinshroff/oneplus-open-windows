# G1346 validation

The unsigned candidate is3841536 bytes, SHA256 `cb2ddd7e233f7c1af26ae2ef508fd7f72d6fc11744761a7ad5c61304add9988e`, derived from G1344 SHA256 `c5b543e6881e0e484caa8655444c6967c9864f6f64f18e2bfa319958866eaf21`.

Independent whole-image comparison found exactly six changed bytes confined to the two instruction words. Actual candidate REA review confirms NOP at the WLAN zero-release callsite and an unconditional branch to the original MHI release epilogue, preserving the existing atomic decrement and lock release. Three evidence records were exported and the session closed. Compiled review receipt SHA256: `24ff6f90a66b039a25924d244fc69de662723e57a1344cc45ece10617c64c6a2`.

Offline checks cover exact base/old-word guards, branch-target encoding, whole-file parity, inert default and exclusive-output refusal. These are source/artifact checks, not runtime power-state or suspend qualification. Proprietary images, signing material and private evidence bundles are excluded.

The actual signed candidate is3843000 bytes, SHA256 `a537535d6831ce17dbc5fbe90de9a06e6081e0adc5acef6703e63f0e41528e6c`. Host signing used the existing project identity. Independent local verification passed for unchanged unsigned PE payload, SPC image digest, CMS RSA signature and signer identity. This does not assert host-chain trust, change trust policy or qualify phone loading.

The prepared cache/profile task keeps the exact two previously qualified C# helper files unchanged; it reuses their byte-bound qualification and performs zero new C# compilations. The actual host check passed for all three task/policy PowerShell files and three current admission scripts, plus both default-inert task invocations. It reused the exact two-CS qualification and compiled zero C# units in this action; it made no device calls. The intended task remains one initialization, a minimum15 seconds from its actual callsite before one cache query, at most one exact saved-profile connection and bounded DHCP observation, with no explicit scan, optional statistics or HTTP request.

Electrical wake retention, sustained networking and suspend remain unqualified. The [Boot175 hardware result](HARDWARE-RESULT.md) records loaded patch words followed by the recurring credit/RX-silence boundary and local connection timeouts. The planned combined QTB firmware revision also changes the retained TCU vote; a future positive result cannot be attributed to this WLAN patch alone.
