# G1325: pre-release persistence witness and intentional stop

The [hardware witness completed](HARDWARE-RESULT.md): both register passes and
the full CPU SQE backing check matched, and Windows remained available after
the intentional stop. ARM64 COFF compilation, native MSVC linking, focused REA
review and signature verification preceded that activation. This option cannot
produce a CP fence. It observes CPU-visible state immediately before the original
SQE release and refuses that release, retaining ownership through the existing
failure path. GPU command execution and acceleration remain unfinished.

The hypothesis is that GPU translation configuration or SQE backing validated
before GPU_SET/GX-on no longer matches after power acquisition and setup. GMU
HFI success does not prove GPU SID0 translation: GMU uses its distinct SID5
path. An intact witness does not establish hardware page walks, GPU fetches,
secure aperture persistence, firmware correctness or SQE execution.

## Integration and admission

`OGO_GPU_PRE_RELEASE_WITNESS` is absent/0 by default; explicit 1 enables the
experiment and other numeric values fail preprocessing. The only runtime seam
is in actual `source/owner/gpu_cp_native.c::GpuWrite`, after the existing start
admission and SQE/ring readbacks, before the store journal, FirstUseConsumed,
MastersMayRun and G482GpuWrite. The existing cold translation `Current()` and
every programming guard remain unchanged.

The separate read-only guard requires the actual FirstUseFrame/OgoCpCurrent
authority, operation scope/thread/generation, published activation-qualified
tables, stage 3/Phase 4, held successful power/frequency/OOB state, actual power
attempt, the original live SMMU mapping and its fixed 0x40000 grant, and retained
input backing. Existing GX-on and AHB-clear checks precede the witness accesses.
Each fixed register read and each SQE page rechecks authority; loss of current
authority stops further reads. No new mapper, interface or IOCTL is added.

Only 25 fixed SMMU items are collected twice: CBAR0/CBA2R0, CB0 SCTLR, ACTLR,
TCR2, TTBR0/1, TCR, MAIR0/1; the owned SID0 SMR/S2CR; NSCR0/NSACR and ID0/ID1;
and GFSR/GFSYNR0/1/2 plus CB0 FSR/FAR/FSYNR0/1 and CBFRSYNRA0 (faulting SID). Full-width TTBRs and FAR are
preserved. Configuration expectations match the real existing activation,
including root_physical and the committed route/namespace values. The plan
does not sample unrelated context banks or enumerate the whole stream table.

Fault fields are read first; raw values and per-pass validity masks are emitted
even if a later read fails. The witness contains no ACK/clear. Existing broker
ISR policy is unchanged: an IRQ may concurrently latch/ACK a fault, or revoke
authority before all syndrome reads complete. Therefore the receipt can be
partial or non-atomic; a zero later status does not exclude an earlier fault.
The guard is never weakened to recover missing diagnostic data.

The SQE backing check compares all 0x13000 CPU-visible bytes against retained,
already hash-qualified input bytes after the original four-byte removal and
against the zero tail. Each page's CPU physical address is compared with the
existing locked MDL PFN. It reports checked bytes and the first mismatch offset
plus1; it emits no firmware content. This is CPU backing correspondence, not a
new table walk, device-side visibility proof or GPU translation test.

The attempt is consumed before new observations, including failed admission.
Every result returns a failure status: clean observations return
STATUS_NOT_SUPPORTED; incomplete/mismatched observations return
STATUS_DEVICE_DATA_ERROR. The original CP failure/retention and software-scope
unwind continue. FirstUseConsumed and MastersMayRun remain unset because no
start is attempted. This adds no cleanup, retry or second-release authority.

## Offline qualification

Run from repository root:

```sh
python3 experiments/G1325-pre-release-witness/test.py
```

The current run passes 167 scalar cases with ASan/UBSan and -Werror. It compiles
the actual new collector/native adapter and extracts the actual unchanged
FirstUseFrame and cold translation Current function bodies. Cases exercise
each of the 50 read mismatches/allones failures, authority loss after each
first 49 reads, SQE payload/tail and physical-backing corruption, power/GX/AHB
and active-authority refusals, once-only execution, and offset/width allowlist
refusals. Cold Current still refuses after power.attempted; the new observer
requires that attempt and the existing successful active power authority.

Absent/0 preprocessing of the actual owner body and CP structure is identical
to preprocessing with the new guarded seams removed. The builder adds no
default compile definition or flag; it adds the one definition only for
`--pre-release-witness`. Both complete 35-object ARM64 builds passed `-Werror`
using the same five genuine Microsoft WDK/SDK/MSVC header roots as the prior
owner. With the option off, all 35 objects match the prior G1318 build byte for
byte. Enabling the option changes only `43_gpu_cp_native.obj`. This is actual
COFF emission and byte correspondence, not a Windows native link or runtime
qualification. The scalar tests alone make no Windows ABI claim.
An unrelated translation unit including the option1 common header also compiles
with -Wall/-Wextra/-Werror, exercising unused inline-helper inclusion. Four
packager fixtures prove that both G1318 and G1322 reject either the witness
receipt selection or its compiler definition before processing objects or
creating a ZIP. An intentional stop cannot be packaged as either prior trial.

The existing G1311 `compile_owner.py` accepts `--pre-release-witness`; layout,
SECVID and mapping choices remain explicit existing options. There is no
implicit combined variant, package builder or live-control script here.
Before any native consideration, independently review the selected settings,
the 35-object default/0 byte correspondence, variant emission, exact new linked
PE with REA, and fresh image/load authority. This proposal grants no activation.

## Source basis and limits

The existing source activation values are in
`G1287-cold-aperture/source/owner/gpu_cp_translate.c:35-41` and independently
checked by `source/gpu_user_native.inc:38-47` before g440 acquire. Active checks
already reread SCTLR; this experiment addresses the remaining configuration
and backing persistence gap. The source admission and mapping lifetime are in
`source/gpu_user_native.inc`, `source/ns_scope_native.inc`, and
`source/open_smmu_activate_wdm.c::OsmaOpenNativeIo`.

The fault offsets follow the Arm SMMUv2 register layout used by the existing
broker. Primary Linux definitions:
[arm-smmu.h](https://github.com/torvalds/linux/blob/e2f57c576f14f96449cfee840860cb9707501d23/drivers/iommu/arm/arm-smmu/arm-smmu.h).
There is no ATOS write: the admitted ID0's ATOSNS bit prohibits assuming v2
translation-operation support. No PTE, cache attribute, clock, ACTLR, route,
aperture call, firmware byte, ZAP order or command packet is changed.

## Native preparation

The complete 35-object closure linked successfully using the existing native
MSVC toolchain and five external ARM64 libraries. Focused REA review covered
the actual GpuWrite release branch, witness, current-authority guard, fixed
read adapter, FirstUseFrame, backing check and two-pass collector. The compiled
`0x2020` path reaches a refusal or the witness return; it cannot fall into the
general register-write path. The witness returns only failure statuses.

Assembly also confirmed that dynamic expected root/route values are stored
after the constant-plan copy; decompiler scalar assignments must not be read
as execution ordering. The reviewed image was signed with the existing project
certificate. Independent local PE/CMS hashing and RSA verification confirmed
the original payload and signer. Host trust and actual Windows load remain
separate from that content verification. No new trust setting was applied.

`package_native.py` freezes the actual source/COFF closure and admits only the
explicit nonsecure64, four-zero-store, non-WC, pre-release-witness combination.
It refuses a package without the intentional-stop definition. External Microsoft
headers, libraries and signing material are excluded. For a previously qualified
build directory:

```sh
python3 experiments/G1325-pre-release-witness/package_native.py \
  --build-dir /external/g1325-coff --out /external/G1325-OwnerLinkInputs.zip
```

The image is selected offline alongside preserved older images with all
startup/once flags disabled. A future trial still requires fresh normal-boot
resource, ownership and original-WLAN admission. It must retain the intentional
stop contract and distinguish a complete witness from a partial/refused one.
No real GPU fence, hardware translation or WDDM acceleration has been achieved
by these preparation checks.
