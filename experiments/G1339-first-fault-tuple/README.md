# G1339: first SMMU fault tuple before ACK

Default-off broker diagnostic. The enabled 15-unit broker has now been compiled against genuine Microsoft headers using ARM64 Clang COFF and linked by native Microsoft 14.29 tools. Focused compiled review and existing-project signing verification passed. It has not been installed, activated or hardware-tested. Existing G1335 owner artifacts remain frozen. This captures missing fault evidence; it does not establish GPU execution.

The existing broker ISR journals status/counts and acknowledges observed W1C faults without saving FAR or syndrome registers. G1339 adds `OGO_GPU_FIRST_FAULT_TUPLE=1` to save one private first-fault record per broker owner generation before the existing ACK. The default is0; invalid selectors fail compilation. The original `OfAckPolicy` source, W1C masks, fatal latch, revocation, retained mappings and disconnect/join paths are unchanged. No public interface or query structure changes. Original G1339 additions are not assigned a new license; existing and third-party notices are preserved.

## Actual baseline binding

The installed historical broker identity is SHA-256 `a54a0449072248d19734687746fa6ba35348f6ce1cc3c2c864c3ca9e6411d34a`, version1.0.0.1148. A focused offline REA review of those exact bytes observes ISR RVA8360–8423: original status load83c8, policy calld6b4 at83d4, ACK store83f4. No FAR/FSYNR/GFSYNR reads occur between them. The policy preserves Format400, rejects allones without ACK, and uses context mask800001fe.

All five pre-change files below match the exact G1335 native-input archive and the G1148 broker source byte-for-byte; hashes are in `BASE-PINS.json`. The35-object G1335 owner closure contains these broker sources but **does not compile this broker ISR**. Owner-side `open_smmu_activate_wdm` is a different TU and cannot establish broker ISR behavior. Retained local broker COFF/build records identify the source closure; the exact installed PE's REA review supplies the actual compiled ISR claim. The enabled broker now has its own complete 15-unit compile/link and focused compiled review; see `COMPILED-REVIEW.json`.

- `source/fault_owner_native.inc`: integrated capture and one bounded debug line.
- `source/fault_owner.h`: conditional private enclosing-owner pointer.
- `source/fault_policy.h`: default-off selector and conditional private journal extension.
- `source/fault_policy.c`: unchanged ACK/fatal policy.
- `source/broker/open_smmu_wdm.c`: unchanged enclosing lifetime/ISR TU.

Paths are relative to `../G1287-cold-aperture/`.

## Captured data and authority

The raw record keeps owner generation, ISR index, original status, read mask, allones mask and refusal bits. A single interlocked CAS claims the record; state1 means incomplete and state2 publishes completion. Another IRQ cannot replace it or emit another line. An earlier global, GMU/CB2, allones-status or guard-refused event consumes this same single slot and can prevent capture of a later CB0 tuple. This deliberately preserves the first observed event; it does not guarantee that GPU syndromes will be captured. Only the new record is reset, only for a different owner generation during the existing empty-map/non-retained connect interval with no armed/known/uncertain interrupt. Existing fatal/count state is never reset by this diagnostic.

The global read guard requires the same nonpaged enclosing owner, matching generation, existing bank/global mapping, started D0 reference and no removal. It reads only already-mapped GR0 GFSYNR0/1/2 at50/54/58. CB0 reads additionally require ISR index2, existing CB0 mapping, qualified active SID0 owner with matching generation and broker, and the still-held NS token/generation/bank/fault relation. That route is CB0, not the GMU's CB2. If any predicate fails, the raw first status/refusal is retained and the original ACK/fatal path continues; no guard is weakened to obtain data.

The CB0 tuple is FAR low/high at60/64 and FSYNR0/1 at68/6c. No additional GPU aperture, ATS/PAR, translation command, status clear, SID change, mapper or power operation is added. The already-read status is preserved before policy processing. An allones status is latched without further MMIO or an ACK; allones in a diagnostic word is kept raw and marked, not silently interpreted as a valid address or fault. Global/GMU first faults save global syndromes only and cannot cause CB0 reads. Read masks represent completed software reads, not proof that hardware fields describe one atomic transaction.

One scalar ASCII `DbgPrintEx(DPFLTR_IHVVIDEO_ID, DPFLTR_ERROR_LEVEL, ...)` line precedes ACK, matching existing IHVVIDEO mask9's bit0. It uses no file I/O, allocation, callback into another owner, Unicode formatting or repeated log loop. Debug delivery is best effort and changes interrupt latency. A firmware/interconnect fatality may prevent the ISR or line entirely; no line does not exclude a fault.

## Primary register authority and limits

[REGISTER-AUTHORITY.md](REGISTER-AUTHORITY.md) identifies the architecture tables, access widths, implementation-defined fields and matching Qualcomm reads. The reporting registers are RW, not read-only; reads have no specified clear/ACK operation. Fake MMIO tests do not establish register presence.

Pinned primary [OnePlus arm-smmu.h](https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550/blob/c87f74901db572a762241d6dfcacc42dbdd9f798/drivers/iommu/arm/arm-smmu/arm-smmu.h) defines GR0 GFSYNR0/1/2 at50/54/58 and CB FAR/FSYNR0/1 at60/68/6c. These are fault-report registers, not W1C commands. The [same primary fault handlers](https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550/blob/c87f74901db572a762241d6dfcacc42dbdd9f798/drivers/iommu/arm/arm-smmu/arm-smmu.c) read the syndromes/FAR for reporting, then separately acknowledge FSR/GFSR. G1339 preserves the existing broker's separate W1C operation; it does not import Linux's optional debug/ATS/recovery actions.

The software first record is the first serviced qualifying status, not necessarily the first faulting GPU transaction. FAR's two32-bit halves and the rest of the tuple are not a hardware-atomic snapshot; subsequent faults or global-versus-context reporting may differ. Do not decode a global syndrome without its matching global cause, interpret stale FAR as a translation proof, claim CPU store retirement, or infer a GPU fence. This does not make an otherwise fatal start safe.

## Validation

`test.py --out <fresh-directory-outside-checkout>` extracts the actual helper/ISR slice from the integrated native include and compiles it with a CPU MMIO shim. It tests ordering before ACK, status-policy masks, zero/Format/allones, busy atomic claim, first-record retention across another source, each effective guard and generation-reset restrictions. Both modes pass ASan/UBSan with `-Wall -Wextra -Werror`:102 default-off and127 enabled cases. Default-off ISR preprocessing matches the frozen pre-change fixture, and the default journal remains28 bytes. The shim establishes software behavior only, not Windows IRQL timing, device power, MMIO safety or GPU translation.

A separate genuine WDK26100/SDK/MSVC-header ARM64 **Clang** check compiles the complete broker and policy TUs in both modes. Default-off objects match pre-change objects except COFF TimeDateStamp bytes4..7; no other object bytes differ. Enabled objects compile without diagnostics. This particular comparison is a compiler/source check. The separate native link and compiled review below establish the linked artifact; hardware behavior remains untested. `VALIDATION.json` records the scoped results; private local paths/operator data are excluded.

Only a reviewed future broker build may select the flag consistently across its closure. Existing owner-only compilers/packagers do not enable this broker feature. No live operator or automatic activation path is supplied here.

## Actual linked and signed artifact

The complete 15-unit enabled broker linked successfully into an 87,040-byte unsigned ARM64 native image, SHA-256 `792fbad89b4e9492f4afb0e283996d21af537ef2494760f60f6d249e2c2c4fa1`. All 67 public dependencies and 92 manifest files were checked. Focused REA disassembly confirms guarded first-record claim, seven 32-bit diagnostic reads, publication and one IHVVIDEO level 0 print before the unchanged policy call and W1C store. There are no additional ISR MMIO writes. `COMPILED-REVIEW.json` records exact ranges and limits.

The 88,504-byte signed image is SHA-256 `379b4b72100dd6490d642eb281f27efe19c8c54a81873a647b12880a1f1986ec`. Independent verification checked unchanged unsigned payload, Authenticode content digest, CMS/RSA mathematics and existing project signer identity. This does not assert host trust-chain acceptance or phone loading. No certificates, keys or driver binaries are distributed here. `SIGNED-ARTIFACT-PROOF.json` records the scoped result.
