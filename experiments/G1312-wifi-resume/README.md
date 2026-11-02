# G1312 Wi-Fi resume: one epoch comparison, then transport evidence

Offline preparation on 2026-11-02 for the operator's resumed work. No device or debugger connection, driver load, signing, staging, reboot, reset or target read was performed here. The next live action belongs to the single root operator after recovery control and GPU fencing are established. The historical publication pause is superseded only by the operator's actual resumed authorization.

The minimal next Wi-Fi experiment remains G1295 around **one otherwise-required fresh normal boot and one original initialization/explicit scan**. Its value is to decide whether the CAFECACE tuple was already present before that operation. It is not another post-stall QMI request and cannot itself repair networking. Do not burn a standalone reboot to collect the same post-stall tuple.

## Source review and changes

The G1295 source preserves the active clock/reset/GPIO checks, identity checks, current BAR binding, eight-DWORD allowlist and once-per-boot/phase markers. The physical read sequence is unchanged. PRE refuses when access/power/memory-decode requirements do not hold; this is not a reason to force power or loosen a guard. GPIO83 level remains observation-only. POST requires a consumed PRE marker even if PRE safely refused after consumption.

Two small changes are included in G1295: reject a second/trailing JSON document in proof and ledger, and emit the already-admitted image/action-ledger hashes on every result row. The latter makes automated PRE/POST pairing reject mixed images or unrelated ledgers. JSON hashes still bind exact bytes; these checks do not independently discover actual boot/action history. Proof and ledger are operator attestations, and unknown field rejection is not duplicate-key rejection.

The publication omitted the four templates, old build receipt and G1278/G1291 contract files referenced by G1295's README. This folder supplies fresh templates and a reproducible receipt generator; it does not fabricate omitted historical evidence. An operator who needs the old read-side-effect/source qualification must retrieve the private reviewed contract or independently qualify it before granting physical-access flags. Successful compilation does not grant those flags.

`BREAK6` stops the host CPU; it does not freeze Q6. The four error words are sequential MMIO reads. Stable MHISTATUS/EXECENV does not prove an atomic or immutable debug record. Preserve raw words and chronology; do not interpret the tuple as an executed assertion, ROM address, specific failing SET_IE, or proof of firmware health.

## Offline preparation

Run from the repository root, choosing **new, private output directories**. These tools only create local artifacts; they do not execute the Windows binary.

```sh
python3 experiments/G1312-wifi-resume/build.py --out /tmp/G1312-wifi-build-new
python3 experiments/G1312-wifi-resume/templates.py --out /tmp/G1312-wifi-proofs-new
python3 -m unittest discover -s experiments/G1312-wifi-resume -p 'test_*.py' -v
```

The build script records the exact three source hashes, output hash, Go version, windows/amd64 target and explicit false execution flags. There are no external Go modules. The output is an **AMD64 host debugger helper**, not an ARM64 phone driver. It uses the existing host `OpenG80` debug server and the fixed Windows SDK x64 `dbgeng.dll` path. Do not repurpose it into a phone-side executable. Build output/proofs/receipts remain private; retain only source in publication.

## Exact operator sequence

1. Complete recovery control and GPU startup fencing independently. Establish actual fresh normal boot, current image/table/resource contract, fresh session and currently loaded `OpenG184` identity. Do not reuse historical kernel addresses, image identity, held PC, connection status or boot receipts. If boot/action history is ambiguous, stop this diagnostic admission rather than invent zero counts.
2. Review/stage the exact binary and its receipt on the Windows AMD64 host through the existing operator path. First invoke `& $reader` **without flags**. Require exit0 and `INERT: no debugger connection or target read; root actual proof and explicit selection required`. This new binary has only been cross-compiled here; native inert execution remains pending. Do not use `--execute-reviewed-reads` to test default behavior.
3. Before any native Wi-Fi initialization or explicit scan in that boot, collect actual Start4/Stopped/no-init evidence. Under the root's already-owned BREAK6 and qualified resources, populate PRE ledger from the actual action history, then hash it into PRE proof. Supply real accepted-boot/normal-admission/current-table/owner/BAR/state evidence hashes. PRE contains no future init-selection/outcome/failure hashes. Use a fresh nonce, actual image and timestamp; proof must be younger than5 minutes, ledger no later than proof and less than5 minutes older. Preserve the fixed marker directory `%USERPROFILE%\Downloads\Open-G17\payloads`; the reader does not create it.
4. With private `$reader`, `$proof` and unused `$result` paths set by root, execute the following once for PRE. Root retains the existing break/cleanup/resume policy; the helper never interrupts/resumes. An access refusal after marker consumption is final for that phase. Do not delete a marker, change boot IDs or try a different nonce to replay it.

```powershell
$proofHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $proof).Hash.ToLowerInvariant()
& $reader --execute-reviewed-reads --proof $proof --proof-sha256 $proofHash --result $result
$readerExit = $LASTEXITCODE
# Preserve result, stderr, exit code and fixed once marker before root-owned cleanup.
```

5. Root reviews PRE and resumes through its existing owned control path. Select the already-reviewed original initialization once and explicit scan once, retaining the actual selection/outcome/failure log. No automatic retries, QMI diagnostic request, reset, status clear or new firmware patch belongs to this interval. Do not fabricate a POST_STALL if initialization/scan did not actually reach a stall. A successful scan/interface notification still does not establish association or DHCP.
6. If that single interval stalls, collect fresh current identity/resources under root-owned BREAK6. Populate POST ledger/proof with the actual one-init/one-scan outcome and failure evidence, plus exact retained PRE-result and PRE-marker hashes. Use a different nonce and a new result path. Execute the same PowerShell invocation once with POST paths. Root reviews and performs its normal cleanup/resume; process timeout is not cancellation or rollback.
7. Copy the retained artifacts through the existing private evidence path and compare offline:

```sh
python3 experiments/G1312-wifi-resume/compare.py \
  --pre-result PRIVATE-PRE.jsonl --post-result PRIVATE-POST.jsonl \
  --post-ledger PRIVATE-POST-ledger.json --pre-marker PRIVATE-PRE.once.json
```

The comparison verifies same boot/session/image, distinct nonces, completed or refused phase outcomes, tuple read consistency, stable MHI state/EE, POST ledger hash, and its binding to PRE bytes/marker. It is an evidence consistency tool, not an independent implementation of all G1295 admission predicates. Old unbound results from the pre-correction binary intentionally refuse automatic pairing. Keep identities and logs private.

## Decision after this interval

| Observation | Actionable next question |
|---|---|
| Same valid sequential PRE and POST tuple | Stop using the tuple as evidence of a newly triggered init assertion. Prioritize one fresh HTC/CE credit-loss timeline: last endpoint2 receive/credit report, available/requested credits, UL3/DL2 producer/consumer progress and interrupt delivery at the actual stop. Historical matching CE2 indices do not settle a new boot. |
| Changed valid tuple | Bound the observed change to the init/scan interval and correlate the same-boot log before choosing one finer boundary. This does not identify a writer, marker semantics or causal assertion. Do not patch firmware from the filename/496 correspondence. |
| PRE refused/incomplete, POST valid | No epoch inference. Retain POST as a qualified post-only observation. Choose transport evidence from the same attempt rather than repeating initialization or forcing baseline access. |
| Both unstable/refused, or identity/hash mismatch | No qualified pair. Preserve evidence; no repeat in consumed phases. Resolve the specific qualification problem before a future otherwise-required boot. |
| Responses continue and scan/association advances | Continue the existing networking path toward association, DHCP and actual traffic; keep the success criteria separate. Do not manufacture a stall just to complete POST. |

The next transport experiment needs an observed discriminator between target nonproduction, CE delivery/reaping and host credit accounting. Nothing in current public source justifies injected credits, HT-IE truncation, arbitrary firmware changes or more post-stall QMI calls. The host error predicate's normal MHI/BHI status does not settle debug-tuple semantics. Firmware/host binary reconstruction is outside this offline source-only change; use REA against the exact privately supplied image if that becomes necessary.

## Validation performed here

The corrected three-file Go closure cross-compiled successfully with Go1.27.3 to Windows/AMD64. Seven synthetic artifact tests cover same/changed tuples, refused PRE, tampered result binding, mixed images, truncated/unstable outcomes and inert templates. Native host inert execution subsequently passed with exit0 and no debugger connection or target read. Actual proof admission and target reads remain pending. No networking improvement is claimed.

## Optional offline CE2 history decoding

If the root operator independently captures the exact original driver's512×40-byte CE2 history and retains matching metadata, decode the private file locally:

```sh
python3 experiments/G1312-wifi-resume/parse_ce_history.py \
  --ring PRIVATE-CE2-HISTORY.bin --cursor ACTUAL-DECIMAL-CURSOR --tail 32
```

The parser accepts exactly20480bytes and a cursor0..511. It emits counts over nonzero physical slots and at most the selected1..512 tail rows, with software index, event, raw time,16-byte descriptor, descriptor length bits31:16, and context. It never connects to a debugger or reads target memory. Keep captures and output private; output contains raw descriptor/context values.

Cursor denotes the last **reserved** record, not next-free. Its row is marked possibly incomplete; no other row is independently certified complete. Tail order follows reservation slots, not time. Cursor0 does not establish a wrap or empty state; all-zero input is reported only as a byte property. Event0x30 records the zero-length receive branch, but the logger re-reads the descriptor later, so a nonzero length in that record is allowed. This parser does not establish capture qualification, interrupt liveness or causation. The suite now includes six synthetic CE-history tests plus the seven pair/template tests, all passing.
