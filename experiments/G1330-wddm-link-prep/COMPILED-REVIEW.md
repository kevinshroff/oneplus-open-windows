# G1330 focused compiled-image review

The exact private unsigned native-linked image has SHA256
`e8a37c9f8f8ca7feb8bf17d4364d9b0348e7bd0a04039b6c1bf92a7fe78858f7`,
size 107520 bytes. Its 21 source objects come from the unchanged public G779
closure including G1315's DDI correction. Native MSVC 14.29.30159.0 returned 0;
the actual UTF-16 link-log file contains the linker banner and input list with
no warning or error. All files were hash bound to the staged manifest before
that single root-operated link. The build, import libraries, raw evidence bundle,
map and image remain private; no Microsoft library or driver image is published.

## PE observations

- PE32+ machine ARM64 `0xaa64`, native subsystem1, seven sections.
- WDM driver, dynamic-base, high-entropy-VA and NX-compatible characteristics.
- Image base `0x140000000`; entry RVA `0x3ce0`, exactly matching map
  `DriverEntry` at `0x140003ce0` from `ddi.obj`.
- 52 imports: 51 from `ntoskrnl.exe`, one (`KeGetCurrentIrql`) from `HAL.dll`.
  No user-mode CRT or ARM64EC dependency appears in the PE import descriptors.
- Ten DIR64 base relocations; relocation directory RVA `0xa6000`, size `0x2c`.
  Native linker completed actual relocation processing without `/FORCE`.
- Exception directory RVA `0xa3000`, size `0x130`; load configuration is present.
  These are structural observations, not a complete unwind/security audit.
- Certificate directory and CHPE metadata pointer are zero. Image remains
  unsigned and was never loaded by this experiment.

The local structural receipt uses LLVM20 `llvm-readobj` file headers, imports,
base relocations and load configuration. It establishes the described PE fields,
not that a particular Windows kernel will load this research driver.

## Focused REA checks

Ghidra 12.1.4 analyzed the exact image without executing it. Addresses below are
preferred-base virtual addresses; map names are source/build attribution, while
REA generally recovers `FUN_...` labels. Evidence IDs refer to the exported
private session bundle. Decompiler prototypes are inferred and are not WDK ABI
proof; the checks use recovered assembly alongside the actual source.

| Source/map function | Address | Observed compiled behavior | Evidence |
|---|---|---|---|
| DriverEntry | `0x140003ce0` | Initializes a 0x608-byte callback structure, sets version 0x4002, registers StartDevice and SubmitCommand addresses and calls the linked DxgkInitialize implementation | `ev_47cb16271526eda6d5a4e97d5aedb9a23c48dac607fa1d221f61565bf3bdbe91` |
| DxgkInitialize (displib) | `0x140015d50` | Contains native initialization/version dispatch and kernel interface acquisition; call target is included in the image | `ev_92d4090a3626369f05e9b1752300f7c98f9b10af9588f14d6e640cfa3a4b263e` |
| TgStartDevice | `0x140004028` | Propagates GetDeviceInformation/bind errors; after bind succeeds explicitly constructs 0xc00000a3 and returns it | `ev_a16773aa02652fa43b08dac4c20474c58275410d70d33e7e096d5e671919d072` |
| TgSubmitCommand | `0x140005174` | Stores attempted fence before EngSubmit; `AND w0,w0,w0,ASR31` preserves failure NTSTATUS and returns 0 for nonnegative status. No completion callback appears in its complete body | `ev_ff4dc14def07df41cb403648ea724d3257f07e6aff4fa811b9e80582b9932f46` |
| EngSubmit | `0x140007ad8` | Missing worker returns 0xc00000a3; allocation failure returns 0xc0000017; only accepted allocation is enqueued and event-signaled | `ev_aff331e4022fd70dad2346cfd167ce1253e7ca04a9d3d16abb014c039b954a62` |
| HwStart | `0x140002380` | Reads the CpReady byte and returns it; does not write readiness | `ev_09e015d38cbee57cd5ae87424e37dd794eb0249a996849c07f7a23afb21d58aa` |
| A740BindDevice | `0x1400026b8` | Preserves PASSIVE-level composition lock/resource checks and native/HAL prerequisite paths; StartDevice still refuses after success | `ev_7dbcc9b1c2cb5a6ed6a56af03e68fe368800b98d982f9b405666f1cea652495c` |
| A740BindSubmitAuthorization | `0x14000352c` | Requires Begin/End, no previous provider, prepared CP stage 9 and not poisoned/closed; successful path copies auth fields only, without writing CpReady | `ev_38b37d8ff9022e00d38efcce7f71b932321c3af2fdfdebbefe961cec18f0a594` |
| HwSubmitOwned | `0x140003634` | Checks process/device/array limits; missing Begin provider returns 0xc00000a3 before resource-vector allocation or G433SubmitAuthorized | `ev_51e933384633516fd6bff0bc7046486dce96c80835f740733514817c067b558a` |

These checks confirm the specific readiness/provider refusals and the absence
of fabricated completion on the two G1315 queue-failure paths in this image.
The queue return remains a fatal scheduler qualification boundary described in
G1315; it is not a usable backpressure contract. Source still installs no genuine
provider and never sets CpReady true. The compiled bind hook does not supply one.

Scope limits: nine function dossiers, not a whole-driver proof. An exact
HwReady-address query did not have a recovered function boundary, so no dossier
claim is made for that selector; HwStart's byte-read behavior and the complete
StartDevice refusal were directly reviewed. No WDDM callback execution, loader,
interrupt, hardware fence, authenticated security transition, dynamic BO mapping,
preemption/TDR, provider lifetime or acceleration was exercised. Imported kernel
API availability on the actual target OS and full ABI/lifecycle qualification
remain external requirements. The REA evidence bundle and analysis snapshot
were exported and the shared analysis session closed.
