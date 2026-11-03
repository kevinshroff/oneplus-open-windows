# Validation

Completed offline:

- Both source profiles compiled with Clang to Windows ARM64 COFF against genuine retained Microsoft headers: owner35 plus broker15,100 objects total. All50 disabled-profile objects match their reviewed G1343-owner/G1341-broker baselines except COFF timestamps.
- Enabled changes are listed in [LOCAL-COMPILE-RESULT.json](LOCAL-COMPILE-RESULT.json). ABI growth changes structure offsets in several owner units; this is not a two-object-only claim.
- Host ASan/UBSan transaction tests cover exact raw extraction, normal success, all24 returned I/O failure boundaries, uncertain writes that reached modeled hardware, preexisting fault/foreign halt/trigger refusal, halt and injection timeouts, cleanup after poison, lost cleanup capability and changed foreign bits. Failed cleanup cannot remain MATCH.
- Host firmware-adapter tests verify exact native route, pair bytes, vector word count/request, no post-EBS calls, retained partial failures/no retry, default-off zero calls, and packed OWQT checksum/payload. This is behavioral harness coverage, not an EDK2 ABI or firmware build claim.
- Exact AML source comparison permits only the single additional MMU descriptor; original ranges and interrupts are unchanged. Public recipe reconstruction checks every overlay preimage. Owner terminal control flow precedes configuration and cannot continue to SQE release.

Run `python3 experiments/G1345/test_source.py` for the authored host tests. Pure models cannot prove MMIO completion, interrupt races, real resource lifetime, translated addresses or interconnect settlement.

Native MSVC linking subsequently passed for the matched pair: owner unsigned `5bc8bfe64534ccdcc8b1c2b5b44ca5fbde81dd35c5d116fd73f7cd603148f714` (131584 bytes), broker unsigned `9cf6b033f51271de10981c6bbc4ff5f26df876d5104f6d401b8b29c608125b21` (92672 bytes). Independent compiled review passed and exported/closed REA.

The publisher dependency revision adds exact NPA and ICB protocol dependencies. Static ICB initialization precedes protocol installation; this does not guarantee node registration succeeded. The arbiter availability check remains. The first offline firmware build remains preserved and unbooted. The dependency revision was separately built and packaged successfully: image `328ffac3c14e885a355b7297747e6906430489c98eb0dc82ff4e5ed945923e8c`. Only the publisher and compression container changed; all other raw firmware files matched the G991 base.

Both linked drivers were subsequently signed with the existing project identity and passed independent PE payload/SPC digest/CMS RSA checks. Signed owner: `a089ee59de66d26a009ec63eaf72a16e6f2dbb621ecc7734c0c17e8f70b82cc3` (133048 bytes); signed broker: `b36064106521f032e9d48f8a73218f7299b5b993d09d68cea181ddabb9d1b1ce` (94136 bytes). No trust change or phone load is implied. See [OFFLINE-QUALIFICATION.json](OFFLINE-QUALIFICATION.json).

Not qualified here: new firmware publication, driver activation or hardware transaction. No future boot/session/resource fact is supplied. A future root-owned operation requires the exact new firmware/provider/table identity and matched images, actual grants, current namespace/clock/MDL ownership and review of every retained-uncertainty path.
