# G1342 native and signed validation

The CE3 getter candidate passed offline whole-image comparison and actual compiled REA review. Its only changes from G1340 are four bytes in the two allowlist DWORDs at RVA0x14e194 and0x14e198, selecting CE3 source HP0x01b86400 and TP0x01b86404. All executable instructions, unwind information and native wake/window/error behavior are unchanged.

| Artifact | SHA256 | Bytes |
|---|---|---:|
| Unsigned candidate | `a98840b66a8598ddb4ef2aa59300e36b4f1a6d626156b4f9aa68c1b6ec1961db` | 3841536 |
| Signed candidate | `c5eb06416f3f66110d7a689a059b8b240b356f4e53ea0f289e034a7f7c7adc6b` | 3843000 |

Actual candidate REA inspection confirmed the fixed table and preserved getter gates. The session was exported and closed. Existing G1340 compiled findings are reused only where whole-image byte parity establishes unchanged code; no new full-driver analysis is claimed.

The adapted client passed native compilation and codec checks without device calls. It requests only index4 then5, stops on the first refusal, and retains the existing conservative refusal of zero and error sentinels. Four init helper files are byte-identical to G1340; their existing native C# qualification is reused, not recompiled. The modified policy passed native AST validation, binds the new candidate and requires a fresh boot greater than172. The init-only outcome schema remains unchanged because the implementation is unchanged.

Signing used the existing project identity. Independent PE content-range hashing and CMS RSA/SHA256 verification passed, preserving every unsigned payload byte except the normal PE checksum/security-directory fields and appended certificate data. This establishes the signed artifact's content and signature mathematics; it does not assert platform trust or successful loading.

The prepared next-boot flow requires fresh admission, disabled GPU services, one combined current module/50-word firmware capture, one initialization, bounded loaded getter/NC-code verification, and the two native queries. It does not reuse Boot172 evidence as proof of the new boot. GPU owner and broker remain the previously selected G1341 aliases during Wi-Fi work.

This validation records build, source and signature evidence only. It contains no G1342 hardware result and does not establish that the WMI credit stall is fixed.
