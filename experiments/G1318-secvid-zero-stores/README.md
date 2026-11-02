# G1318: isolated four SECVID zero-store parity trial

The actual native MSVC-linked unsigned image passed a focused
[REA compiled review](COMPILED-REVIEW.md). Signature, load and hardware success
are not established by that review. This keeps G1311's nonsecure64 private BO layout and adds only four
explicit zero stores after the existing complete zero-prestate admission. The
hypothesis is that explicit store parity could matter; reading zero does not
prove a write strobe, and no missing-strobe cause has been demonstrated.

The default `OGO_GPU_SECVID_ZERO_STORES=0` preserves G1311 byte-for-byte. Explicit
1 enables the fixed data plan in `g456_secvid_zero.h`. Other numeric selections
fail compilation. The production executor uses the existing VendorPost/Write
path: lease/GX/AHB gates, sticky retention before attempts, barrier, fault
checks and journal behavior remain intact. There is no bypass or second start.

| Order | Register | GPU byte offset | Value |
|---|---|---:|---:|
| 1 | RBBM_SECVID_TSB_CNTL | 0x3e00c | 0 |
| 2 | RBBM_SECVID_TSB_TRUSTED_BASE_LO | 0x3e000 | 0 |
| 3 | RBBM_SECVID_TSB_TRUSTED_BASE_HI | 0x3e004 | 0 |
| 4 | RBBM_SECVID_TSB_TRUSTED_SIZE | 0x3e008 | 0 |

All four existing zero-prestate checks and the remaining original admission
finish before any new store. The plan runs at stage 2 before the existing setup
writes. Apart from those four entries, the write trace and order are unchanged.
Addresses remain in the actual assigned GPU register bank. The native GPU
callback's special SQE release admission is untouched; these are ordinary
pre-release setup stores. No VA, permissions, SMC, power, ownership, reset,
clock, command, SQE-start or security-exit policy is changed.

The zero order/policy is source-qualified against Linux and the actual Sheng
board path in [SOURCE-PARITY.md](../G1313-gpu-review/SOURCE-PARITY.md) and its
primary-source hash inventory. Android KGSL secure-reservation values are not
used. This remains a discriminator, not an asserted fix.

Run the CPU qualification from repository root:

```sh
python3 experiments/G1318-secvid-zero-stores/test.py
```

It compiles the actual G456 function bodies and numeric tables with scalar
host callbacks and the actual facts/report definitions. ASan/UBSan passes 8
baseline cases and 24 variant cases. Full successful traces are 140 versus 144
writes; removing exactly the first four new entries makes the traces identical.
Tests check admission-before-stores, each nonzero prestate refusal, ownership
refusal, all four new-store/barrier failures, before/after AHB drop, retention
and one-attempt refusal. Invalid options 2/-1 fail compilation. This is not a
Windows ABI or GPU execution test.

Full 35-object compile reuses G1311's explicit public inventory and exact link
policy. Supply the same external header roots described in G1311's README:

```sh
python3 experiments/G1318-secvid-zero-stores/compile_owner.py \
  --cc /absolute/path/to/clang \
  --system-include /local/wdk/Include/10.0.26100.0/km \
  --system-include /local/wdk/Include/wdf/kmdf/1.15 \
  --system-include /local/sdk/Include/10.0.26100.0/shared \
  --system-include /local/sdk/Include/10.0.26100.0/ucrt \
  --system-include /local/msvc/include \
  --out /absolute/external/empty-g1318-build
python3 experiments/G1318-secvid-zero-stores/package_native.py \
  --build-dir /absolute/external/empty-g1318-build \
  --out /absolute/external/G1318-OwnerLinkInputs.zip
```

The wrapper fixes nonsecure64+four stores. G1311's compiler also exposes the
named default-off `--secvid-zero-stores` option. Both complete 35-object variants
compiled with `-Werror`; default-off matches every prior G1311 object, and
G1318 changes only `47_g456_hwinit.obj`. See the sanitized
[evidence](evidence/OFFLINE-QUALIFICATION.json). Existing VA/table/PM4 checks
were rerun successfully. No captured firmware or proprietary libraries are
included in packaging. The package pins source, flags, all 35 objects and native
response inputs; libraries remain external. Run the reviewed native ARM64 MSVC
linker with its external library path and `@owner-link.rsp` from packet root.

A future native link changes the image and may move every RVA. Independently
review the exact new PE, four stores, helper/start callsite, signing content,
manifest and fresh loaded image/base before setting breakpoints. Never reuse
G1311 runtime addresses. Native link/signing, approval and a fresh one-attempt
activation remain separate operator work. A fatal or timed-out attempt retains
uncertain ownership; this option adds no retry, rollback or cleanup authority.

## Hardware trial result

The reviewed owner was signed with the existing project signer, its payload and
signature independently verified, and one fresh normal-Windows activation ran
with ordinary logging and no instruction breakpoints. Each of the four new
zero stores logged a successful return through the existing guarded write path.
The intended nonsecure64 address high words remained `0x40`.

The phone nevertheless entered Qualcomm900E after the same SQE
`STORE_CALL_BEGIN` at stage3, without a returned marker or first CP fence.
Explicit zero-store parity therefore did not resolve the failure. This trial
does not add an instruction-retirement observation or identify the root cause.
A fresh Sahara handshake and one RESET7/ACK8 recovery were acknowledged; that
acknowledgement alone is not completed WinPE recovery or offline fencing.
Fresh WinPE control subsequently returned, and the actual offline SYSTEM
control sets were fenced and read back before the hive was unloaded.
