# G1340 bounded native CE getter

Source-only experiment. Wi-Fi remains unfinished. No OEM firmware, driver binary, certificate, device identity, network profile or captured dump is supplied. These authored files add a bounded read-only diagnostic route to a privately obtained, pinned driver derivative; no blanket license is added to OEM material.

The existing `read_reg` command is changed from firmware-mediated QMI ATHDIAG to a magic/index-only native getter. Magic `0xce28`, index0..7 selects eight fixed CE2 registers. Other inputs fail. It resolves the current adapter/HIF/HAL through the existing dispatch ownership route, requires the dynamic HAL branch, and calls unchanged native `1eb588`. That helper performs its own wake, shared window locking, selection/DSB/read, unlock and normal release. No arbitrary address, direct kernel callback, MMIO mapping, cache flush or firmware/credit write is exposed.

The new body snapshots HAL selector-error counter77e4 and accepts only an unchanged counter plus a nonzero DWORD other than `ffffffff`/`c000000d`. Zero is deliberately unavailable, even if legitimate. The initial runtime scope is index2 **status HP first**, then optionally3/0/1 only under separate root selection. Stop the whole sequence at the first failed/refused query; no retries, next index, scan, init or restart. RRI-high0 may therefore remain unavailable. Reads are sequential, not an atomic hardware snapshot.

Known retained limitation: native wake failure can leave its existing MHI wake reference. This experiment does not fix that path and performs no extra release based on data. It also retains the production selected window/cache state, rather than promising restoration of the previous selector. A selector-error counter change can conservatively reject a query because of concurrent activity. Nonzero data is not independent proof of bus power, firmware liveness, effective cache attributes or target production.

## Offline build and validation

Supply the privately retained unsigned NC base, SHA256 `927bf9450f462607435d616c0d2f00884f6689bcd2c395bcc949896ff93c8ee0`,3841536bytes. It derives from original4478 SYS `f59d9e98bb736ccd78aa4ebd569616456fa0f09bf345a7b1002b0105693aeeef`, preserves the cache-policy MOV0, and has the old certificate removed. Original OEM package/INF/CAT/firmware are unchanged. Never patch a signed runtime image directly with this recipe.

`python3 patch.py` is inert. Explicit offline operation:

```
python3 patch.py --build-offline --base PRIVATE_UNSIGNED_NC.sys --out NEW_DIRECTORY --clang /usr/bin/clang --ld /path/to/ld.lld
python3 verify_candidate.py --verify-offline --base PRIVATE_UNSIGNED_NC.sys --candidate NEW_DIRECTORY/qcwlanhmt8380-G1340-unsigned.sys
python3 test_offline.py --base PRIVATE_UNSIGNED_NC.sys --candidate NEW_DIRECTORY/qcwlanhmt8380-G1340-unsigned.sys
```

Requires clang with AArch64 ELF assembly and LLD. The linker places the body atRVA14e09c with absolute module-relative symbols; no output relocations remain. Body58instructions232bytes +table32bytes +NOP16bytes fills exactly280bytes `[14e09c,14e1b4)`. Original function prologue/GS/frame/epilogue/unwind, NC instruction and HAL helper remain unchanged. Candidate unsigned SHA256 `2a0d977055dd6e8e59cbad80f2e3462d6e1e2d6a62d88f18a0753504d60e8495`:258changed bytes, all within the approved body, file offset1365148. Manifest includes exact BL/ADR/ADRP and branch targets; independent verifier reconstructs the entire immutable base by restoring only that body.

Offline tests passed for the actual private base/candidate, outside-body/body corruption refusal, malformed branch rejection and client source scope. This is not a runtime success claim. Compiled REA review and native source qualification must be recorded separately before root selects any trial. No signing/staging/activation is performed by these scripts.

## Client qualification and later root operation

`CeGetter.cs` compiles without calling native APIs. `CodecOnly()` tests the actual128-byte input /100-byte output codec and rejects forwarded zero-count, wrong-count/length/status and invalid values. `Native-Compile-Only.ps1` defaults inert; with `-CompileReviewedSource -SourcePinsSha256 ACTUAL_SOURCE_PINS_SHA` it checks source hashes, parses both PS scripts, exercises the query script's inert default and runs only pure codec tests. Save its actual result as `native-compile-result.json`. No device open occurs during qualification.

Root must create a new, hash-reviewed settings file from `review.candidate.json`, supply actual future normalBoot>171/session/PCI instance/runtime DriverStore image, independently verified newly signed getter SHA/receipt, actual loaded identity/noUnload and current session qualification, and a new nonce/exclusive output directory. All runtime flags in the template are false. Root must keep GPU/broker stopped4 and GPU once flags0; parent remains running. Native source qualification and independent signed-content receipt are hash-bound. A disk hash is not independently read loaded bytes; that remaining scope is recorded.

`Query-Once.ps1` defaults inert. Only after root review, `-ExecuteRootReviewedQuery -Review ACTUAL_REVIEW -ReviewSha256 ACTUAL_SHA` permits one operation. Default selected mode is `statusHP-first-only` (index2); `first-four-status-first` (2,3,0,1) additionally needs `accept_first_four=true`. No task scheduler/transfer/operator infrastructure is supplied; root can reuse its existing reviewed one-SYSTEM-task transport.

The client opens only `\\.\QcomWifi` with ordinary DeviceIoControl0x220182; input command is `read_reg`, integer count2, magic/index at offsets20/24hex. Success requires APItrue,100returned bytes, countbyte1, expected zero padding and one nonzero accepted DWORD at+4. A successful forwarded request with count0 is refused. Every response is recorded, then the first failure stops. This is synchronous native I/O:10s helper waits do not establish an end-to-end wall-clock bound. No forced task termination or replay is selected.
