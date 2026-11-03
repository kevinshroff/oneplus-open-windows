# G1349 validation

Exact unsigned input: SHA256 `cb2ddd7e233f7c1af26ae2ef508fd7f72d6fc11744761a7ad5c61304add9988e`,3841536bytes. Candidate: SHA256 `ca6c37d84444cedea51a2b85a20079603ff30269f95e4d7dd96d2f2d05b3369d`, same length. Exactly27bytes change within two spans:4bytes at RVA`1d775c` and24bytes at`1d7c24`.

The original store is `STP W28,W8,[X19,#0x10]`: W28 was copied from scan-priority argumentW5; W8 is the notification mask. The seam branches to:

```asm
eor w9, w28, #1
clz w9, w9
lsr w9, w9, #5
add w9, w28, w9
stp w9, w8, [x19, #0x10]
b 0x1d7760
```

For a32-bit input, CLZ produces32 exactly when input XOR1 is zero; shifting by5 therefore produces1 only for priority1. The instructions preserve NZCV, W8 and W28. X9 is dead at the seam: successor instructions`1d7760..1d7788` do not read it; the first later use at`1d778c` is `AND W9,W8,#1`, which defines W9 independently.

The first five instructions were locally assembled as ARM64 COFF with zero relocations and matched the recipe bytes. The return branch is encoded against its actual RVA. Local Unicorn execution passed4288cases across edge/random32-bit priorities and all16NZCV combinations, checking the return PC, every GPR except deadX9, NZCV and the exact original8-byte pair store. Wrong-base rejection and whole-image diff bounds passed. This is local instruction validation, not device qualification.

The cave's original fallthrough is blocked by adjacent `MOV W8,#0; CBZ W8,1d7c88` at`1d7c10`. Its inherited loop backedge from`1d7c80` to`1d7c28` is dominated by that disabled loop entry. Direct-branch inspection of the enclosing function found only that inherited edge plus the new intended entry. The new return exits the cave before the old loop continuation. Exact-base and no-hint guards are mandatory; the cave must never be applied to an unmodified hint-capable image.

Both spans are inside the same existing ARM64 runtime function `[1d7618,1d7eb0)`, xdata`32e134`. Prologue, epilogues, pdata, xdata and all other image bytes are unchanged. The new body has no call, stack operation or callee-saved-register modification and performs the same destination pair store. Existing frame/unwind context therefore remains applicable; independent compiled review passed on the actual candidate. The21-record REA session was exported and closed; review receipt SHA256 `fc7d1de8f0f30f2aaa3a4955f3bc4a6d6e2e6a6fc06ce8af95c53a8e1cd172ec`. It confirmed the actual entry/return branches, full-text direct incoming references, dead-X9 use, same frame/unwind record and whole-image bounds.

Actual existing-project signing produced SHA256 `bd36bb6c8877c138153ade9b444fe63d18f337f4d2bc8abfd1246708f997dda3`,3843000bytes. Independent local verification passed unchanged unsigned PE payload, SPC image digest, CMS RSA signature and the existing signer identity. No trust change is asserted. The unchanged two C# task helpers retain their prior byte-bound native qualification; current PowerShell/admission source qualification is pending.

Loading, runtime progression, scan success and networking remain unqualified. No firmware or GPU change is part of this driver derivative.
