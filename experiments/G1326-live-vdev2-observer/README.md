# Live vdev2 baseline and post-stall observer

Source for a diagnostic experiment, not a Wi-Fi fix or a complete bring-up package. No live PRE/POST result is included here. Reliable networking remains unfinished.

The [pre-scan statistics experiment](../G1323-wifi-prescan-stats/README.md) did not send the intended fresh WDI request. This experiment observes an existing automatic vdev2 statistics call instead. It adapts the [G1295 fault reader](../G1295-wifi-fault-epoch/README.md) to a running-driver phase with actual resources, without invoking its old PRE_HOST_INIT admission unchanged.

## Included source and external boundary

- The six Go reader files implement strict ARM/PRE_LIVE_VDEV2/POST_STALL admission, fixed once markers, current resource and mapping checks, the existing fixed fault tuple and bounded CE2 observations. `guard.go` preserves G1295's access predicates.
- `Observer.ps1.in` performs the critical observation and resume locally on the debugger host. `Cleanup-Timeout.ps1.in` supplies a separately selected timeout cleanup. There are no debugger callbacks, self-rearm chains, software breakpoints, stepping or PC edits.
- `generate.py` is an offline generator for an inert host packet after an actual loaded-module receipt. `Register-Observer.ps1` registers an independent host task only when explicitly selected; it does not start one. Default invocations are inert. The loaded-receipt template contains null current facts and false observations.
- `analyze.py` checks recorded tuples, hashes/markers, pause timing, phone-clock alignment, subsequent RX/credits and CE boundaries. Tests use synthetic CPU/parser models; they are not hardware observations.

The original-init/one-scan renderer, controller transport, helper executables, signing and current resource/boot evidence are private operator dependencies and are deliberately excluded. This generator does not reconstruct or stage the phone task. The literal named-pipe, fixed marker directory, helper names and helper hashes preserve the reviewed host interface; they are compatibility constants, not credentials or authority to connect to any debugger. Independently obtain or reconstruct matching qualified host tools before considering runtime use. Do not remove a guard or change a hash simply to make a different tool pass.

The host helpers must implement the qualified interfaces: status/owned resume/one explicit interrupt, and held command capture. The latter must be called only after independently observing the owned held state. Their source/native behavior and debugger lifecycle require separate qualification; these dependencies are not certified by compilation of this directory.

No proprietary binary, captured log, raw REA dossier, SDK, signing material, device identity or actual context is included. Public source changes and regenerated artifacts require their own exact build/native qualification. Historical private binary/preflight hashes do not authenticate a public rebuild.

## Exact source boundary

The supported artifact is original ARM64 qcwlanhmt8380.sys version 1.0.4458.2600, SHA256 `802b1f7c5325c312b710312ced0864f813beaf30ff0fceceeefd9f48b2f25d56`. RVAs apply only to that image.

PRE_LIVE_VDEV2 is at ol_ath_request_stats entry, RVA `1ea630`, before PACIBSP and before buffer construction/submission. The first 16 bytes are `7f2303d5f353bda9f55b01a9f76302a9`. Actual X0 must equal the current source-owned context; DWORD[X1] must be `0x109`; BYTE[X2+9aa8] must be 2. The reader rechecks the frame, original loaded identity/code, current ownership, one free endpoint2 credit and zero queued sends. A previously starved/queued state is not accepted as this live baseline.

Compiled assembly evidence: `ev_b5982cc533c14521eabab4f138f3290f49c11774d240f6d1d741705eb73dcb72`. Independently pin the actual artifact and loaded boundary when rebuilding. The previously published driver-side statistics chain and its evidence IDs are documented in G1323. Source-derived entry/argument constraints do not prove future execution.

## Current resource evidence

The old pre-init state supplied no allocated BAR. This reader does not manufacture that missing grant from the expected PCI address, call a phone collector while held, or accept the old BARQualified boolean.

It reads the current typed WDF resource context at Q+3968d0 and checks its adapter pointer against Q+396c20. It examines bounded retained raw/translated CM descriptors and requires exactly one translated Memory descriptor matching the context's actual PA/VA/length, the current resource record, and HIF/HAL/MHI BAR mapping. Actual debugger VA→PA translations must agree at mapping start/end and every planned device-read endpoint. Existing active clock/reset/PERST/WLAN_EN, root link, endpoint identity, D0, memory-decode, PCI BAR, fixed allowlists and before/after safety checks remain. Any mismatch refuses before fault/CE MMIO.

This is current driver-retained evidence of its OS-translated CM resource and actual debugger mapping. It is labelled separately from a fresh enumeration of the kernel's global CM database. See [resource provenance](RESOURCE-ORIGIN.md).

ARM consumes only host-local intent and performs no debugger connection/read. PRE/POST permissions authorize the runtime checks; they do not assert that those checks have already succeeded. There are no selector, reset, interrupt-mask, error-clear, doorbell or target-memory writes in the reader.

## Call counts and phone-task integration

Manual service configuration can implicitly load the driver before the explicit installed-driver call. Therefore ARM/PRE caller-entry and scan counts may be explicitly `NOT_OBSERVED_AT_STOP`, with null counts. Null is not zero. The reader does not infer API entry or native-in-call status from task registration, service state or a module-load stop. POST requires actual completed one-init/one-scan outcome and failure evidence.

An external phone-task adapter must preserve the original one-call/one-scan guards and add only durable caller journals around these existing sites: before manual service configuration, before the existing InvokeOnce call, after its return and before the existing explicit scan. The private adapter is not shipped or replaced with a pretend public reproduction.

The analysis journal contract is `original-wifi-caller-journal/1`. Relevant fields are `kind` (including `explicit-scan-callsite-begin`), actual `BootId`, root nonce, `phone_utc`, `install_callsite_attempts`, `explicit_scan_callsite_attempts` and `actual_callee_entry_not_independently_observed=true`. These record caller sites, not entry inside the operating-system API. Preserve all original source/trigger/manifest hashes after integration. Add no extra WLAN/QMI request.

A baseline before the explicit caller-site journal retains that label. Multiple matching vdev2 setups, driver unload/reinitialization or missing chronology make attribution unqualified. Actual access admission is the current live frame/resources, independently of the later API-count accounting.

## Host sequence and timing

Root remains the sole hardware operator. Prepare and qualify the external once-init/once-scan task, current GPU exclusion and exact original driver first. At the owned original module-load hold before DriverEntry/FW initialization, qualify actual base, kernel, code, debugger PID/run identity and empty breakpoint inventory. Restore only the owned load-event filter.

With actual evidence, the offline generator emits false proof/review templates and a plain manual `ba0 e 4` arm command without callback. Consume the fixed ARM intent before arming; preserve it even if arming fails. Root independently verifies the exact owned hardware slot. Register the independent host observer without starting it, then start it only at the still-qualified module-load hold.

The local observer verifies that initial stop and resumes locally. It waits 5–30 seconds and accepts at most two owned hits: one source-qualified vdev0/request109 skip, then the selected vdev2/request109 observation. At the selected stop it binds actual frame evidence, runs the fixed reader, removes only its owned slot externally and resumes locally. It does not wait for a controller round trip. Recognized own-stop read failures receive guarded cleanup; foreign/unknown stops remain held.

Stop-duration upper bounds run from the preceding known-GO sample start, or owned pre-FW resume start, through verified local resume. An immediate following hit retains the earlier resume-operation start as its lower bound. Unknown/inconsistent bounds or a breached selected budget are pause-perturbed/unqualified. Even within budget, timing neutrality is never proved. Native COM calls can block; finite logical hit/deadline limits are not a wall-time cancellation guarantee. Process termination is not rollback.

**A timeout is not safe until the armed slot is removed.** A later hit could otherwise stop the phone after the observer exits. Root must monitor its terminal result and immediately handle `owned_slot_cleanup_required`. The separate cleanup requires exact terminal-timeout, ARM-marker, PID/run, boot, original image/code and slot bindings. GO permits at most one qualified interrupt attempt. Only an exact owned hardware stop, or our successful interrupt at the pinned kernel break instruction with the actual expected exception, permits clearing slot0 and resuming. Foreign/unknown held states are preserved. Require a cleanup receipt proving slot removal and GO before any later work; never replay the initialization/scan to recover a missing observation.

After the original task returns, preserve actual outcomes, caller journals and one qualified CPU host log. Root can select one POST_STALL observation with actual PRE/ARM artifacts and failure evidence. The reader itself never interrupts or resumes. A refused PRE can coexist with useful POST data, but supplies no paired epoch claim.

## Build and offline validation

A local Windows AMD64 crossbuild of this six-file reader closure can be made with Go:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o LiveVdev2Observer-amd64.exe main_windows.go proof.go phase.go guard.go support.go ce.go
```

The executable is an external local build product, ignored by this source directory and not supplied in the repository. Run tests from this directory:

```sh
go test -race proof.go phase.go guard.go support.go ce.go reader_test.go
python3 test_workflow.py
```

The publication's six Go and six Python test groups pass. The Windows crossbuild also passes. These are CPU/model/parser checks, not new native read or networking results.

`generate.py --syntax-preview --out NEW_DIRECTORY` produces neutral, explicitly non-operational parse carriers. Their default invocations are inert and explicit execution always throws before runtime work. Actual host generation requires a fresh loaded receipt and its exact hash; generated approval flags remain false. Independently parse and review the exact generated source and default-inert binary before any later selection. No runtime permission is granted here.

## What distinguishes an outcome

Actual subsequent WMI receive activity and returned endpoint2 credit before the next scan show return-path progress after the baseline pause; they are not necessarily a specific command acknowledgment. Unique source vdev2/request109 attribution, measured header-to-inline-SystemTime alignment and the actual scan caller journal establish ordering. Do not substitute controller timestamps for the phone clock.

| Actual observation | Supported interpretation |
|---|---|
| Baseline tuple already present, followed by real RX/credit progress | Weakens treating the tuple as newly created by the later stall. |
| Tuple changes between qualified observations | Bounds assignment to the interval; does not establish assertion semantics, source line or fault PC. |
| Qualified hardware status HP differs from TP | Unreaped receive status: investigate RX visibility/servicing. |
| Hardware/shadow or hardware/local index mismatch | Narrows pointer-update/visibility or host publication/servicing. |
| Matching hardware/software/shadows, posted destination buffers, empty status ring | Weakens receive-backlog explanation; shifts toward target/CE production or upstream command delivery, without proving firmware crash. |
| Empty RAM shadows without a hardware quartet | Still unresolved; no target-nonproduction inference. |

The hardware quartet is read only when the existing selector is naturally `0x40000037` and current mapping checks pass. Another selector yields an explicit refusal without a write. The experiment does not promise a decisive split in every attempt. No cache/LDAR patch, credit injection, pool expansion or firmware replacement follows from this source alone.
