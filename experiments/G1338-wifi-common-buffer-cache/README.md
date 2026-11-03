# Explicit noncached common-buffer policy candidate

This untested candidate changes one allocator cache-policy initialization in the
matched4478 driver from MmCached to MmNonCached. The same value supplies allocation,
tracking metadata and matching free/cleanup. One byte changes at ARM64 RVA0x7dbc;
other code, bounds, lengths, address handling and firmware remain identical.

The driver calls [AllocateCommonBufferWithBounds](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-pallocate_common_buffer_with_bounds)
with an explicit cache-type pointer. Its semantics differ from the legacy
AllocateCommonBuffer ignored CacheEnabled parameter. NULL could still select
cached memory, so the selected candidate requests MmNonCached explicitly.

[patch_cache_policy.py](patch_cache_policy.py) defaults inert and requires the
exact privately obtained original input hash and a fresh private output. It
checks the ARM64 PE mapping, instruction encoding and entire one-byte delta.
The repository includes no OEM driver binary. Patching invalidates the original
signature; signing, exact-load verification and a separately reviewed trial are
required before use. This is research code, not an installation instruction.

[Preparation checks](PREPARATION.json) include bounded compiled disassembly and
exact byte comparison. No hardware success is claimed. The fallback allocation
backend is unchanged; preallocated shadow memory may use another path. Effective
shadow/descriptor cache attributes and transport progress must be observed before
attributing a result to coherency. Device logical addresses are not CPU physical
addresses. Declared ACPI coherency does not establish physical snooping.

The candidate has since been signed with the existing project certificate;
independent PE content-digest and RSA/CMS checks passed. Its exact runtime file
was copied and reread while Windows was offline in WinPE, with startup disabled.
The original runtime bytes are retained. The INF-selected DriverStore SYS is
intentionally replaced for this experiment; its catalog is not signature proof
for the modified binary. The original source-package SYS/CAT/INF/firmware payload
remains unchanged. No driver load, new boot or connectivity result is claimed.
[Signed inactive-stage result](SIGNED-DISABLED-RESULT.json).
