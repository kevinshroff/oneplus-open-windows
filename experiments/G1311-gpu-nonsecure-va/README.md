# G1311: private lower39 nonsecure64 VA discriminator

This is an opt-in source experiment on the G1287 cold-aperture closure.
After native MSVC linking and REA review of the compiled start-write sequence
and 64-bit VA tables, a controlled trial using the selected signed image reached
the changed address readbacks and the same fatal start-call boundary; see the
[native review](evidence/NATIVE-LINK-REVIEW.json) and trial result below.
No GPU fence or WDDM acceleration was achieved. The only production
change is the private CP BO virtual-address initializer. The default remains
G1287. Physical allocation policy, NC mappings, permissions, firmware bytes, ownership,
SMC placement, translation registers, SQE-start sequence and retain-on-uncertainty
rules are inherited unchanged.

| BO | Bytes | Baseline (default or explicit 0) | Explicit 1 |
|---|---:|---:|---:|
| Ring | 0x8000 | 0xf0000000 | 0x4000000000 |
| Fence/shadows | 0x1000 | 0xf0008000 | 0x4000008000 |
| SQE | 0x13000 | 0xf0010000 | 0x4000010000 |
| Power-up register list | 0x1000 | 0xf0030000 | 0x4000030000 |

`G1287-cold-aperture/source/owner/gpu_va_layout.h` selects exactly these fixed
layouts. Compile the production `source/owner/gpu_cp_native.c` with
`-DOGO_GPU_NONSECURE64_VA=1` to select the experiment. Missing or explicit 0 keeps
the baseline; other numeric selections fail compilation. There is no registry
VA selector, fallback, runtime retry or additional hardware authority. Existing
bootstrap/CP/SCM opt-ins and cold resource admission still apply independently.
The new compile option alone cannot authorize startup.


## Native trial result, 2026-11-02

The selected nonsecure64 trial reached ring, BR/BV-shadow and SQE high-word
readbacks of 0x40, establishing that the changed VA layout was active. It then
reached the same stage 3 SQE-start `STORE_CALL_BEGIN` marker without a returned
marker, followed by Qualcomm 900E. No first CP fence completed. This trial did
not resolve whether the helper's pre-store barrier, STR or post-store barrier
completed. A fresh loaded-module identity attestation was not captured before
the failure; selection of the reviewed signed image plus the new address
readbacks must not be presented as full loaded-image identity proof. The VA
change alone did not clear this observed failure boundary.

## Source reasoning and limits

The handoff proposes this discriminator because the four baseline addresses
lie in KGSL's software secure32 reservation [0xf0000000,0x100000000), while
0x4000000000 is its nonsecure64 VA base. Primary source: [OnePlus SM8550 kgsl_iommu.h](https://raw.githubusercontent.com/OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8550/oneplus/sm8550_v_15.0.0_oneplus11/vendor/qcom/opensource/graphics-kernel/kgsl_iommu.h),
retrieved-byte SHA256
`ea0092046d65ec41eefa9cfa4e485303e78971e16d28fdb1877ff2495b73bac9`.
This is a branch URL with pinned retrieved bytes, not a claimed immutable commit.
This software convention does not prove
that A740 classified the old addresses as secure or caused the fatal start
boundary. The controlled trial above found that this VA change alone did not clear
the observed failure boundary; address security classification remains unproven.

The complete variant ends at 0x4000031000, below the existing lower39 limit
0x8000000000. Its L1 index is 256 rather than the baseline's 3. The same three
4K table pages map 29 physical pages under the same allocation policy with permissions15 (read/write/
execute/privileged), normal NC and outer shareability. PA output remains36;
the 39-bit IOVA does not require widening the PA profile. Actual PFNs can
differ across boots; this is not a promise of identical physical backing.
Legacy address-mode control writes are deliberately skipped on A7xx and are
not added by this experiment. The CPU model uses
noncontiguous >32-bit synthetic PAs to expose accidental truncation.

Actual production `reference/runtime/g433_cp.c` writes separate low/high words
for ring BASE, BR shadow, BV shadow, SQE BASE, CP_INIT power-up-list address and
EVENT_WRITE fence address. High words in the new layout are 0x40. Tests run that
implementation and the real PM4 encoder, and inspect both halves. They also
run the real ArmSmmu4K builder and inactive auditor, independently walk every
page and its last byte, check unmapped gaps/old and truncated addresses, and reject corrupted
root/permissions and out-of-profile VA/PA. These establish source encoding and
CPU table construction; hardware address-width acceptance, table fetches,
GPU firmware execution and completion remain unmeasured.

## Reproduce the offline checks

From repository root:

```sh
python3 experiments/G1311-gpu-nonsecure-va/test.py
```

Requires Python3 and Clang with ASan/UBSan. Uses a temporary output directory by
default. `--out /absolute/external/result-directory` retains executables and
`RESULTS.json`; those are local artifacts, not publication inputs. `--cc`
selects a compiler. Both layouts pass 21 CP model cases each, plus independent
29-leaf/3-page table audits, and two invalid-option compile refusals. Modeled
completion is explicitly a host test fixture.

For production ARM64 COFF qualification of the changed TU, supply locally
acquired Microsoft headers and an ARM64-capable Clang:

```sh
python3 experiments/G1311-gpu-nonsecure-va/compile_native.py \
  --cc /absolute/path/to/clang \
  --system-include /local/wdk/Include/10.0.26100.0/km \
  --system-include /local/wdk/Include/wdf/kmdf/1.15 \
  --system-include /local/sdk/Include/10.0.26100.0/shared \
  --system-include /local/sdk/Include/10.0.26100.0/ucrt \
  --system-include /local/msvc/include \
  --out /absolute/external/g1311-coff
```

The script uses only the five public G1287 include roots and explicit system
header roots. It compiles default, explicit0 and explicit1 with `-Werror`,
checks ARM64 COFF type, zeroes the nondeterministic timestamp and records source/
header/object hashes. It asserts missing-option equals explicit0 and variant
emission differs. The checked-in sanitized `evidence/COFF-RESULTS.json` records
the offline run. Default/0 hash3706425f39d77a1c0101d12fa3323eb5cf6659d17dc6fd17121c4c59a0e4cb80
also matches the historical G1287 changed-TU baseline object exactly. This is
an object correspondence check; it does not establish whole-image equivalence.

## Complete public owner build

`OWNER-SOURCES.json` explicitly lists the 34 production C translation units and
real `scm_set_cp0.S` thunk, preserving historical object names/order. Their
sources are solely the public G1287 `source/` and `reference/` closure.
`compile_owner.py` compiles all 35 with the historical fixed C/assembly flags,
the five public include roots, and explicitly supplied external system headers.
It requires an empty external output directory and one fixed layout. It does
not invoke a linker, signer, loader, broker build or device operation.

```sh
python3 experiments/G1311-gpu-nonsecure-va/compile_owner.py \
  --cc /absolute/path/to/clang \
  --system-include /local/wdk/Include/10.0.26100.0/km \
  --system-include /local/wdk/Include/wdf/kmdf/1.15 \
  --system-include /local/sdk/Include/10.0.26100.0/shared \
  --system-include /local/sdk/Include/10.0.26100.0/ucrt \
  --system-include /local/msvc/include \
  --layout nonsecure64 --out /absolute/external/empty-g1311-owner
```

Use `--layout baseline` with a different empty directory to reproduce the
baseline. `OWNER-COMPILE.json` records every object/source hash, historical
correspondence, all public closure file hashes, flags and compiler version.
Both complete builds were executed successfully with `-Werror`. All 35 baseline
COFF objects exactly match final historical G1287 timestamp-normalized pins.
All 34 other objects also match in the nonsecure64 build; only
`43_gpu_cp_native.obj` differs. There was no observed object drift from public
sanitization in this closure. The source file hash for `gpu_cp_native.c` changes
because of the default-preserving header extraction. Whole-image equivalence
is not established by these object comparisons. Sanitized results are in
`evidence/OWNER-QUALIFICATION.json`; binaries remain outside the repository.

`OWNER-LINK.json` records the actual historical reviewed native owner link
options and five library names. The builder emits `owner-link.rsp` with those
options, all 35 relative object names, library names, and directory-relative
SYS/map outputs. `owner-objects.rsp` and `owner-libraries.rsp` are also emitted
for independent review. No proprietary library is included. In the completed
output directory, the equivalent native MSVC link command is:

```powershell
& '<LOCAL_REVIEWED_ARM64_LINK.EXE>' /libpath:'<LOCAL_REVIEWED_ARM64_LIBRARIES>' '@owner-link.rsp'
```

The five required ARM64 libraries are `ntoskrnl.lib`, `hal.lib`, `libcntpr.lib`,
`bufferoverflowfastfailk.lib` and `aux_klib.lib`. Link policy is explicitly
`/machine:arm64 /driver /subsystem:native,10.00 /osversion:10.0 /nodefaultlib
/dynamicbase /nxcompat /opt:ref /opt:icf /Brepro /incremental:no
/entry:DriverEntry`. Selecting and qualifying the actual native linker,
libraries, exact linked PE and signing remain operator work. The portable compiler
does not link or sign. A later operator-controlled native link/sign preceded
the trial above; those actions do not turn host-model tests into GPU evidence. The unchanged
broker is not rebuilt by this recipe.

Historical G1287 `compile_all.py`/`freeze.py` still depend on excluded inputs;
the new explicit recipe supersedes those dependencies for this 35-object owner
compile. Locally obtained SQE/GMU/platform inputs and existing pin guards remain
required before runtime. No signing material, captured input, binary, device
identity, runtime addresses or live-control recipe is added. A later hardware
discrimination must recover fresh liveness, fence unrelated owners/once state,
choose exactly one layout and preserve the existing one-attempt/retain boundary.
Further native boundary evidence and the first actual CP fence remain
prerequisites for WDDM.
