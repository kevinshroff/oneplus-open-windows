# G1318 native linked-image review

**PASS for the reviewed static change.** REA/Ghidra12.1.4 examined the actual ARM64 PE after native MSVC link, SHA256 `a89f2cb4dd0c505a4d6444cca72ff7eaf909a1b9fee52e3eebe307929517a6ba`, 134656 bytes. This is unsigned-image evidence, not signing, loaded-image identity or hardware success. The analysis session was exported privately and closed.

The compiled executor contains four direct calls to the existing VendorPost path with immediate register arguments, in order: TSB control, trusted base low, trusted base high, trusted size. Every value argument is zero. Their GPU byte offsets are `0x3e00c`, `0x3e000`, `0x3e004`, `0x3e008`. The compiler unrolled the source table: this is executable call evidence, not merely presence of unused constants. Each call is followed by a nonzero-status exit to the common failure path.

Before those calls, the compiled function loops over all16 original prestate entries, exits on a failed read or nonzero value, then completes the original two status reads. The retained table contains all four SECVID entries plus the other original admission entries. Stage2 is set only after this admission. The opt-in behavior is therefore baked into this image; there is no runtime option branch bypassing admission.

The compiled VendorPost path retains lease and pre-write AHB admission, marks ownership retained and increments attempted writes before invoking the GPU write callback, records the result, and checks the completion barrier and post-write AHB result. Failure exits without a retry or rollback. It remains a write-only register operation; this review does not claim a new readback or hidden hardware acknowledgement.

The compiled Prepare function uses the same four-entry nonsecure64 VA table and sizes as G1311, including high words0x40. The exact G482 write helper and unique SQE-start callsite retain their previously reviewed instructions: pre-store DSB SY, original 32-bit STR, post-store DSB OSH; the caller still passes offset0x2020 and value1. No barrier removal or second start was introduced. Exact build-relative RVAs and instruction bytes are retained in the private review for future identity-qualified use; no runtime addresses are published.

Source and direct object comparison established that34 of35 object files are byte-identical to G1311; only the hardware-setup object differs. The SMC and translation objects are unchanged. Compiled top-level ordering still prepares resources and completes translation before GPU power/configuration and CP initialization. This supports unchanged existing secure-call policy and placement; it is not an exhaustive proof of all indirect-call behavior. The new four-call path itself introduces no SMC or nonzero trusted-range value.

REA evidence:

- Executor and guards: `ev_ad85aae0f4df81c9b95d95b0deb7f2e77e9f1289472839e6d7292d795b7bc9a2`.
- Prestate table: `ev_394b8b1f1700b15d1f5e9229ae170c31ae7394e6072bbbd9b9243eb66d9ab575`.
- VendorPost: `ev_8d553af6bb1a32de10e7c0fc909da9fff7e63508a32221d5c848244023149fe0`.
- Prepare/VA data: `ev_37de067ab329666e6de416bab134aa85af26cdf28827024a87013b0f5a9afc23`, `ev_2b4bd5d88dc5a196d7ff90594376c8ff6f08b6761f49556ceed5f7049b1100de`.
- Helper/caller: `ev_45c606330790d16fd0b35d27262f34fe3c18a0adf9a84f126ef28e205c340aae`, `ev_fdddee78b08125b49d1032d311fce79ed4ec8f31fc9b51ce1c5ed186a979e8a0`.
- Top-level/translation: `ev_2e035c0b41abe1e81c06fa04d939f529c904c84a813ad7c27678f587bd56aafa`, `ev_5cdb2a83e33bd2116ffb6f0ad1fa06a18baf2bbe0a438f1f45123fa0a3db51a9`.

Decompiler text is reconstructed, not original source; assembly and retained data bytes corroborate the focused findings. Static analysis cannot establish permission to access these registers, successful write strobes, GPU fetch or the cause of the prior fatal start. A fresh one-shot trial remains the discriminator.
