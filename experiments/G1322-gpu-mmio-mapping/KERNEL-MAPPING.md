# Windows ARM64 mapping observations

The examined kernel is ARM64 Windows26100.1, SHA256
`db0c8b367c1927eb4d39d922cb54da4621e9b3c241e2655d33c5ecd46719aa13`.
The live recovery kernel's PE identity matched the retained artifact. A short
owned KD stop read only selected saved architectural fields and was resumed.
Its saved `MAIR_EL1` was `0x444400ff444400ff`:

| AttrIndx | MAIR byte | Architectural type |
|---|---|---|
| 0 / 4 | ff | Normal write-back |
| 1 / 5 | 00 | Device-nGnRnE |
| 2 / 6 | 44 | Normal noncacheable |
| 3 / 7 | 44 | Normal noncacheable |

No slot contains04, the Device-nGnRE byte used by Linux's default ARM64
`ioremap`. This establishes a difference in available types for this observed
Windows context, not the actual GPU-bank mapping or a crash cause. Linux source
and MMIO accessor comparisons are pinned in
[SOURCE-PARITY.md](../G1313-gpu-review/SOURCE-PARITY.md).

REA/Ghidra examined bounded, address-preserving byte slices of the same kernel.
Whole-image analysis exceeded its observation limit; it was not silently
repeated. The exported wrapper body is88 bytes. The protection translator has a
160-byte decoded body; its complete normal returns were qualified within a
bounded source window because it has no exact unwind entry. Two mapping routines
were extracted from actual unwind spans. Their slices include literal pools but
exclude some cold branch targets; decompiler warnings and those unknown branches
must not be treated as complete kernel reconstruction. Original-file data table
bytes corroborated the selected protection translations.

For `PAGE_READWRITE | PAGE_NOCACHE` (204), the protection translator returns0c.
For `PAGE_READWRITE | PAGE_WRITECOMBINE` (404), it returns1c. In the selected
small-range mapping path, the page installer also consults the physical page/IO
cache policy. It can replace the requested cache bits. Observed PTE templates
for protection indices04/0c/14/1c have AttrIndx0/2/1/3 respectively. Therefore
inferring the final GPU type from the public API flag alone is insufficient.

The [documented caching enumeration](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/miniport/ne-miniport-_memory_caching_type)
reserves `MmNonCachedUnordered` for system use; it is not an application-driver
escape hatch for Device-nGnRE. No reserved enum or global MAIR update is selected.
An existing alias/cache policy must not be bypassed.

The saved-state read used the typed KPRCB architectural fields described in
[this first-hand debugger investigation](https://community.osr.com/t/how-to-retrieve-values-of-ttbr-registers-on-arm64-from-my-windbg-extension/58736).
The `!pte` channel was separately qualified on shared kernel data: it returned
the leaf descriptor, the saved MAIR was consistent, the breakpoint list was
empty and the owned stop was resumed. This is observer-channel qualification,
not a GPU PTE observation. It did not read unrelated system registers or issue
`wrmsr`, change cache attributes, map GPU registers or start the GPU.

REA evidence:

- Mapping wrapper: `ev_4ff4de0bb602722c235e36f5ad5daa28f82464808a7acdcdc4430471c20ab769`.
- Protection translation: `ev_2f94d2cf497452112b78d5de34f1fc4767c0eccad5dad8ab0be1725f80015024`.
- Mapping core: `ev_65f0097b62c67fe5a91529429522c0399987a970818d18ce2f43ed52d5b7183d`.
- Cache classification: `ev_bfdf2ad50dcb441ecbc0a634e9d09245e460e4514e66daf611ae7414da10faea`.
- Page installation: `ev_e1d327fbf14edcb955c537c50ca655eefe84071640ac3a2c43981435cd16528c`.

Evidence was exported and each native session closed. Captured addresses,
machine details, kernel slices and decompiler text remain private. A fresh normal
Windows GPU PTE and MAIR observation is still required for the mapping trial.
