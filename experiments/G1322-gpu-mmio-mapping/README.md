# G1322: GPU register-window CPU mapping discriminator

**Hardware trial complete; SQE-start failure persists.** G1318's four SECVID zero stores returned
successfully but did not fix SQE start. This variant retains that tested baseline
and changes only the requested CPU mapping for the actual assigned GPU register
bank: `PAGE_READWRITE | PAGE_WRITECOMBINE`. The other four register banks retain
`PAGE_READWRITE | PAGE_NOCACHE`. GPU BO mappings, IOVAs, SMMU configuration,
firmware, clocks, security-call policy, initialization order and register accessors
are unchanged. The pre-store DSB, original 32-bit STR and post-store DSB remain.

Windows' write-combined mapping is **not Device-nGnRE**. On the observed kernel's
MAIR palette it selects Normal-NC when the requested cache policy is retained.
The point is to distinguish CPU MMIO type/write-acknowledgement behavior at the
fatal start boundary; neither a mapping defect nor a fix has been demonstrated.
See [compiled kernel and saved-state observations](KERNEL-MAPPING.md).

`g482_mmio_policy.h` defaults off. Enabled code requests the alternate protection
only for bank0 after the existing complete five-grant admission. It adds an early
mapping marker after all CPU views exist, before target IO in this binding.
There is no second mapping, PTE edit, MAIR write, new physical address or retry.
The actual leaf PTE and current MAIR must be qualified before interpreting a
trial: Windows can preserve an existing physical cache policy instead of the
requested one. Do not force an override or call a retained Device mapping a
successful Normal-NC test.

The next trial should stop briefly at the compiled, image-qualified early
mapping point, inspect the GPU-bank PTE and current MAIR, remove its owned stop,
then continue the same original attempt only if the intended mapping is
qualified. Keep this before GMU/CP startup. Use no self-modifying debugger
callback chain, stepping, PC edits or repeated CP start. An unexpected mapping
is a refusal/unknown result, not authority to relax ownership or cache guards.

## Build evidence

The complete 35-object owner compiles with `-Werror` and real external Microsoft
headers. With the option off, every object matches the prior G1318 build. Enabled
changes only `23_g482_resources.obj`. Native MSVC link also succeeded; linked
code review, signing and runtime admission are separate stages.

`test_mapping.py` compiles the actual G482 initialize/bind bodies with host
callbacks under ASan/UBSan. Both variants pass exact bank/protection selection,
repeat refusal, duplicate/missing/extra/bad-flags resource admission and partial
mapping rollback. It makes no hardware or Windows ABI claim.

```sh
python3 experiments/G1322-gpu-mmio-mapping/test_mapping.py
python3 experiments/G1322-gpu-mmio-mapping/compile_owner.py \
  --cc /external/clang --system-include /external/wdk/km \
  --system-include /external/kmdf --system-include /external/sdk/shared \
  --system-include /external/sdk/ucrt --system-include /external/msvc/include \
  --out /external/new-g1322-build
python3 experiments/G1322-gpu-mmio-mapping/package_native.py \
  --build-dir /external/new-g1322-build --out /external/G1322-OwnerLinkInputs.zip
```

The wrapper fixes the nonsecure64 VA, four zero stores and GPU mapping option.
The G1311 builder also exposes the named default-off mapping option. External
libraries and signing material are not distributed. Preserve one hardware owner
and the existing retain-on-uncertainty rules; no WDDM readiness or fence is implied.

## Actual trial result

The native-linked, reviewed and signed owner loaded in a fresh normal Windows
boot. Its exact early hardware execution stop qualified the loaded PE/instruction
before target IO. The actual first and last GPU-window leaf descriptors had
AttrIndx 3, with MAIR byte `44` (Normal noncacheable), the expected physical
endpoints and kernel read/write access. The adjacent register bank retained
AttrIndx 1 / byte `00` (Device-nGnRnE). All five views existed; binding completion
was still pending. No page-table or MAIR override was applied. These are direct
endpoint-page observations; the interior page containing offset `0x2020` was
not separately inspected. The single mapping request covers the whole window.

After removing the owned stop and restoring the module-load output policy, the
same activation resumed. It reached `STORE_CALL_BEGIN stage3`, then physical
Qualcomm 900E; no returned-call marker or first GPU fence appeared. Thus this
request variant did not remove the recurring fatal boundary. It does not prove
store retirement, an exact fault PC or exclusion of every memory-type issue.
No CP retry, graphics readiness or WDDM acceleration was claimed. Do not repeat
the unchanged variant. Native source/build/signing proofs and the private
endpoint observations remain distinct from that negative hardware result.
