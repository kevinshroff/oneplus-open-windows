# Validation

The fixed source differs from the G1345 preimage only in the `QtbNow` function. The genuine Microsoft WDK26100 declaration requires the output pointer; its file hash is recorded in [CONTRACT.json](CONTRACT.json). No SDK header is distributed.

Local Clang compiled only `source/broker/open_smmu_wdm.c` to ARM64 Windows COFF with the previously qualified Microsoft headers and exact G1345 flags. The remaining14 broker objects are byte-identical to the prior native-link inputs. Owner compilation and firmware build counts are zero.

The host ASan/UBSan regression executes the actual old and fixed function bodies against a writable-output API stub. It detects the old null argument and verifies the fixed function supplies writable storage while preserving the return-value division. Run `python3 experiments/G1347/test_required_output.py`. This is not a kernel API execution or hardware test.

Native MSVC LINK passed for15 broker objects: unsigned `9709ab03e93efc0eb7280a21b8d5a16a607f9b521027b0fb257dde31f08e745d`,92672 bytes. Independent compiled review confirmed a valid stack output pointer at the timer call and the exact reciprocal multiply/shift implementing division by10; REA was exported and closed.

The broker was signed with the existing project identity: `65cfd26debcbac6b749d8474d8f0c96d519762d1fa25a2ac4841b4f14d89c38f`,94136 bytes. Independent PE payload/SPC digest/CMS RSA verification passed. Original owner and firmware proofs were reused; there was no new owner compile/sign or firmware build. See [offline qualification](OFFLINE-QUALIFICATION.json).

No new driver load, translation result or hardware success is established here. The old access violation supplies no QTB translation verdict. A future result must come from the separately reviewed linked broker and a fresh admitted GPU-only epoch; the consumed attempt is not replayed.
