# G1295 phase-aware fault-epoch reader

Local source and WindowsAMD64 cross-compile only. No helper execution, host/phone operations, staging, new tests or target read occurred. Default run is INERT before loading DbgEng or touching markers. G1278/G1289 artifacts are unchanged.

`guard.go` is byte-identical to G1278. Its active clock/reset/PERST94/WLAN_EN80 checks, GPIO83 observation correction, exact physical access/BAR binding guards, eight-DWORD MHI/BHI allowlist and one qualification recheck remain unchanged. No force, reset, status-clear, injected command, native WLAN/QMI call, interrupt, resume, mapping or write API has been added. Host result/phase-marker writes are the only new writes.

## Admission phases

Both require actual BootId>161, a phone session different from consumed Boot161, root's actual fresh NORMAL-boot qualification and accepted boot/current-table/loaded OpenG184/endpoint-resource evidence hashes. Image SHA must be explicitly supplied and match the same-boot ledger; the old9906 image is not silently presumed. Root must validate the actually selected image's qualified WLAN/root-transport/resource contract before granting existing access flags. Kernel/held PC/owner identity are independently checked as in G1278. Boot/image/session facts remain explicit hash-bound root evidence, not inferred from metadata or SCM.

Proof schema is `G1295-root-phase-fault-epoch/1`; it supplies an actual host-local action-ledger file plus its hash. Ledger schema is `G1295-actual-boot-action-ledger/1`. Proof and ledger must match phase/boot/session/image. Both require fresh timestamps, with ledger no later than proof and less than5 minutes older; the proof must be less than5 minutes old at entry. Unknown JSON fields and missing/extra evidence keys refuse. Ledger count/start scalars must be actual explicit values: null is not interpreted as zero.

| Phase | Required actual admission |
|---|---|
| PRE_HOST_INIT | Start4/Stopped, no native init and no explicit scan in this actual fresh boot, root proves no prior native init; actual pre-host-init-state evidence hash. Init selection/outcome/failure/result hashes must be empty, and recorded-outcome flags false. No future failed-scan hash is allowed. |
| POST_STALL | Exactly one actual native init and one explicit scan, actual init-selection/outcome and post-init failure-log hashes; actual PRE result and consumed PRE marker hashes. PRE can have safely refused access: that gives no valid baseline, not a zero tuple. POST uses a distinct nonce and cannot relabel the PRE state as post-init evidence. |

Each ledger has explicit root-selected force/native-diagnostic/reset/status-clear counts, all required0. The existing one native initialization is counted separately; its normal internal MHI startup protocol is not falsely labelled an injected diagnostic. No runtime actions are performed by the ledger or reader. An ambiguous/unproved action history refuses rather than inventing a count.

## Once-only behavior and recovery ownership

A fixed host marker is exclusively created and flushed **before debugger connection**:

`%USERPROFILE%\Downloads\Open-G17\payloads\G1295-Boot-<actual>-<phase>.once.json`

The caller cannot choose its location. A phase cannot be replayed with a different result filename/nonce. PRE cannot follow an existing POST marker. POST verifies the matching actual PRE marker contents/hash/session/image and requires a new nonce. The marker records intent, not successful read completion; an access refusal still consumes that phase. Do not delete a consumed marker to retry. This permits at most the two explicitly selected phase attempts in the one already-required boot, not an automatic loop.

Root owns the preexisting BREAK6 and final cleanup/resume. This executable never interrupts or resumes. No launcher, trigger, reboot or automatic phase transition is included. External process termination can still bypass a surrounding PowerShell FINALLY; root must preserve its existing ownership/cleanup policy. Source is for the next otherwise-required recovery boot, not a standalone diagnostic boot.

## Evidence and interpretation

The historical four templates are absent from the publication. Generate replacement templates using `../G1312-wifi-resume/templates.py`; they intentionally contain missing/null actual context and false approval flags. They are not ready proofs and must not be filled with planned future outcomes. PRE's proof contains no failed-scan key; POST requires the actual new-boot one-init/log boundary and PRE artifacts. Root hashes the exact supplied proof and ledger after actual evidence exists.

Same valid tuple in PRE and POST weakens interpreting it as newly created by this Windows init/scan operation. Valid PRE different/empty and POST tuple bounds assignment to the interval containing initialization plus scan/stall; it does not identify the SET_IE instant, marker meaning or executed assertion. Invalid/refused PRE permits no A/B epoch inference. Neither normal MHI state nor CAFECACE alone proves firmware health/fault. The existing8-DWORD tuple is not a credit injector or fix.

## Root review/use

Historical local cross-compile passed; its BUILD-RECEIPT.json is absent from the publication. Use `../G1312-wifi-resume/build.py` for a fresh source/binary receipt. The G1312 review rejects trailing proof/ledger JSON documents and includes image/action-ledger hashes in result rows; physical guards and read sequence are unchanged. Native default-inert behavior has **not** been executed/verified for this new binary. Root independently reviews, stages and default-inert checks it later.

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o G1295-FaultEpoch-amd64.exe main_windows.go guard.go phase.go
```

If subsequently selected under an existing owned BREAK6, each phase uses a fresh actual proof and exclusive result:

```text
G1295-FaultEpoch-amd64.exe --execute-reviewed-reads --proof ACTUAL-PHASE-PROOF.json --proof-sha256 ACTUAL64HEX --result EXCLUSIVE-NEW.jsonl
```

No phase is selected or approved here. Read semantics/side-effect authority remain G1278/CONTRACT.md; source predicate/experiment interpretation remains G1291. No changed offset, magic-value heuristic or speculative firmware patch is introduced.

G1312 supplies the current offline build/template/comparison tools and exact operator sequence in [its README](../G1312-wifi-resume/README.md). The old G1278/G1291 qualification documents are not exported here; retrieve or independently qualify their contract before asserting physical-access approval. Sequential debug-register reads are not atomic Q6 snapshots even when the host CPU is held.
