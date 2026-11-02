# G1330: complete G779 KMD compile and native-link inputs

The complete **21-unit G779 KMD now compiles and links natively** from the
public source. All translation units compile to ARM64 COFF with real external Microsoft WDK/SDK 26100 headers and Clang 17,
`-Wall -Wextra -Werror`. The objects total 202371 bytes; the receipt hashes 119
unique source/header dependencies. This includes G1315's current complete DDI.
No G779 runtime source changed in this experiment. Adapter readiness stays false
and `TgStartDevice` still returns `STATUS_DEVICE_NOT_READY` after prerequisite
binding. The exact inputs were linked once with native Microsoft MSVC. The unsigned
ARM64 WDM image is 107520 bytes, SHA256
`e8a37c9f8f8ca7feb8bf17d4364d9b0348e7bd0a04039b6c1bf92a7fe78858f7`.
No signing, loading or hardware operation occurred. The
[compiled review](COMPILED-REVIEW.md) records the scoped native-image checks.

This closes the full-source compile inventory gap described in G1315. The
35-object G1311 native-owner build has a different entry point and cannot stand
in for this KMD. The actual source inventory is explicit in `compile_kmd.py`:
DDI, MSM, engine, display, logging, HAL/power, G321 GMU runtime, G433 CP runtime,
G440/G456/G482 and three vendor helper units. `DriverEntry` is in `ddi.c` and
calls `DxgkInitialize` with the existing WDDM1.3 interface.

## Reproduction with external inputs

Run from this repository, using new exclusive output directories outside it:

```sh
python3 experiments/G1330-wddm-link-prep/compile_kmd.py \
  --compiler /external/clang \
  --include-dir /external/WDK/Include/10.0.26100.0/km \
  --include-dir /external/WDK/Include/wdf/kmdf/1.15 \
  --include-dir /external/SDK/Include/10.0.26100.0/shared \
  --include-dir /external/SDK/Include/10.0.26100.0/ucrt \
  --include-dir /external/MSVC/include \
  --include-dir /external/display-shared-headers \
  --out /external/new-kmd-coff
```

The display root supplies the actual `acpiioct.h` and `d3dkmddi.h` needed by
Microsoft's `dispmprt.h`. Supply the corresponding complete Microsoft headers;
no replacement declarations, fake kernel headers or SDK files are shipped here.
The script records compiler version/hash, diagnostics, exact per-unit commands,
object hashes and complete per-unit dependency hashes. Receipts contain local
paths and should remain outside the public repository.

```sh
python3 experiments/G1330-wddm-link-prep/inspect_inputs.py \
  --coff /external/new-kmd-coff \
  --nm /external/llvm-nm --readobj /external/llvm-readobj \
  --library /external/ARM64/ntoskrnl.lib \
  --library /external/ARM64/hal.lib \
  --library /external/ARM64/displib.lib \
  --library /external/ARM64/aux_klib.lib \
  --library /external/ARM64/libcntpr.lib \
  --library /external/ARM64/bufferoverflowfastfailk.lib \
  --out /external/new-native-inputs
```

The local direct-symbol audit found 48 external symbols, all covered by these
archives. `DxgkInitialize` is provided by **displib.lib**; adding a guessed
`dxgkrnl.lib` is unnecessary. Object hashes must match the compilation receipt.
Every object must report ARM64. The local Microsoft `libcntpr.lib` is a mixed
archive containing ARM64, ARM64EC and x64 companion members, identical to the
archive used by prior native-owner links. To use such an archive, explicitly add
`--allow-mixed-archive /external/ARM64/libcntpr.lib`; the receipt records the
member-machine counts. The native linker must still select compatible members.
Pure ARM64 archives need no exception. This admission is explicit and applies
only to selected libraries, never the compiled KMD objects.

`inspect_inputs.py` stages only outside the public tree, writes input hashes and
`native-link.rsp`, and never invokes a linker. Its response selects
`/machine:arm64 /driver:wdm /subsystem:native /entry:DriverEntry /nodefaultlib
/incremental:no`, the 21 explicit objects and six selected archives. Run native
MSVC `link.exe @native-link.rsp` from that input directory only as a separate
reviewed build operation. No `/FORCE`, ignored unresolved symbols or default
library search is used. The response produces an unsigned `topazgpu.sys` and
map; it does not package an installable driver.

## What the audit establishes

Observed: all 21 units compile; every direct external symbol has an archive
provider; the staged inputs are hash bound. Duplicate external-definition
candidates include WDK `DECLSPEC_SELECTANY ExPoolZeroingNativelySupported` and
compiler constants. For example, the former is explicitly COMDAT `Any` in the
objects, so a symbol-name duplicate alone is not a proven link error.

Actual native MSVC 14.29.30159.0 link completed with exit 0 and no diagnostics in
the authoritative raw link log. It resolved archive selection, transitive static
references and COMDAT/directive/relocation processing for this exact packet. The
result has 52 PE imports from ntoskrnl.exe/HAL.dll, ten DIR64 base relocations,
ARM64 entry RVA 0x3ce0 and no certificate table. The compiled review confirms the
StartDevice and provider gates and G1315 failure propagation in the actual image.
This closes the native KMD image-build gap; it leaves the real
owner/provider/security/fence, BO residency/lifetime, scheduler/IRQ, preemption,
TDR/recovery and presentation boundaries described in
[G1315](../G1315-wddm-integration/README.md). Neither compilation nor linking
establishes A740 acceleration or authorizes opening StartDevice.
