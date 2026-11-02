# ARM64 hardware execution observation channel

This is a prepared channel test, not a claim that hardware breakpoints worked on this phone. The helper compiled for AMD64 Windows. Root's native **no-argument** invocation returned exit0 and the expected INERT output, with no debugger connection, breakpoint creation or target access. The disabled configuration probe and actual execution-hit test remain unperformed. Root retains all live control.

Microsoft explicitly documents two ARM64 execution processor breakpoints and two read/write breakpoints. Use one execution slot and move it between observation points. AMD64 WinDbg is appropriate on the AMD64 host for a remote ARM64 kernel. [Microsoft ARM64 debugging](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-arm64).

The processor-breakpoint API is `AddBreakpoint(DEBUG_BREAKPOINT_DATA)`, `SetDataParameters(size, DEBUG_BREAK_EXECUTE)`, and parameter readback. Software code breakpoints are a different type. The documented parameter-size table omits ARM64, so neither size1 nor size4 is asserted from that table. [Microsoft breakpoint parameters](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/controlling-breakpoint-flags-and-parameters), [SetDataParameters](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugbreakpoint-setdataparameters).

## Stage 1: disabled configuration probe

`probe_windows.go` connects to the existing OpenG80 pipe only with argument `probe-disabled`; no arguments are inert. It requires a live, already stopped kernel, actual/effective ARM64 and an empty breakpoint inventory. For sizes1 and4 independently it creates an empty disabled processor breakpoint, requests EXECUTE, reads back type/architecture/size/access/disabled state, and removes exactly its own object. It confirms the original count and stopped state afterward. It never supplies an address, enables a breakpoint, reads/writes target memory, interrupts, resumes or executes a debugger command. Rejection of a size is a recorded HRESULT, not a fallback to a software breakpoint.

Build on the local workstation:

```
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o G1313-HwExecProbe-amd64.exe probe_windows.go
python3 audit.py /absolute/path/to/DbgEng.reference.h
```

Root must bind the current engine/process/pipe before invoking this on Windows. Native no-argument invocation first must report INERT. `probe-disabled` does not acquire or release a kernel hold. An accepted size proves metadata acceptance only: insertion can fail later when execution resumes, and an accepted breakpoint may still never fire.

Breakpoint lifetime deliberately uses `RemoveBreakpoint` without a later `Release`: Microsoft states removal deletes this object and prohibits any subsequent use. Ordinary client/control interfaces still receive `Release`. The named return value is intentional: deferred cleanup sets its `removed` field before the caller receives it. [RemoveBreakpoint lifetime](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugcontrol-removebreakpoint).

## Stage 2: actual benign EL1 hit and next-instruction test

Use a current, symbol-qualified `nt!NtQuerySystemInformation` entry, with actual kernel module identity and loaded instruction words recorded. This is an existing kernel path for the read-only class35 query previously used to inspect debugger presence. Do not introduce a new kernel driver or touch GPU registers. A user-mode G85 breakpoint alone is inadequate: Microsoft says a kernel processor breakpoint may or may not affect a user-mode context. [Processor breakpoints](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/ba--break-on-access-).

At an already qualified root-owned stop:

1. Select an accepted size and one unused ID. Set a **processor EXECUTE** breakpoint at that kernel entry; read back type DATA, ARM64, exact address, size, EXECUTE and enabled state. No `bp`/`bu`, register edits or stepping. Check debugger output for insertion failures when resumed.
2. Resume, then arrange one native class35 query through the existing controlled mechanism. A natural unrelated syscall can arrive first; that still tests a comparator but is not the intended query. If selecting that caller matters, use the debugger's documented kernel `/p EPROCESS` filter for the freshly established trigger process, not its PID; do not feed EPROCESS to `SetMatchThreadId`.
3. On the hit require fresh event type breakpoint, the owned ID, exact entry PC, actual thread/process and raw registers. For the intended query, W0 must be35 decimal (`0x23`), and the buffer/length should agree with its caller. Merely seeing state6 does not prove the owned hardware breakpoint fired.
4. Inspect the actual first instruction. Continue this test only if it is an ordinary linear non-MMIO prologue instruction whose successor is the next aligned instruction. Remove the consumed breakpoint and move the same hardware slot to that successor, using a fresh `/t ETHREAD` filter if needed. Resume normally; require the next event's owned ID, exact successor PC and same ETHREAD. Then remove the breakpoint and resume the query. Its ordinary returned status/data confirm completion.

This tests the exact capability needed for a before/after-instruction observation at EL1 without releasing CP. Do not overwrite unrelated breakpoints. If no event arrives, a configuration error appears, or continuity fails, report the actual channel result and remove only this owned breakpoint at the next qualified stop. Do not retry CP to test the debugger. No timeout should kill the target or debugger.

`ba<ID> e <accepted-size> <qualified-address>` is the processor-execute command form. `/p` takes EPROCESS and `/t` takes ETHREAD in kernel mode. SDK `IDebugBreakpoint::SetMatchThreadId` is not equivalent: its header explicitly says kernel-mode thread restrictions are unsupported there. Prefer the documented command filter or a root-reviewed engine mechanism; do not transplant a user-mode thread-ID call.

## Stage 3: CP observation, only after stage 2 works

Use the exact current owner REA dossier plus the newly loaded owner identity. For G1311 unsigned SHA256 `3ee73237c4311eec9fe083f3d5067407bde1884d84bddb9f8d65c2370dba1d4b`, retained REA evidence `ev_df71cc8d2fc48d51a77a5c3338ead601e6d7bb17d4a7f3a890a4401ccc64b17c` confirms RVAs143d0(pre-DSB),143dc(STR),143e0(post-DSB),143e4(success MOV). These are not live addresses. The prior plan describes register checks and saved LR.

Move one slot A→B→C→D, deleting the consumed stop before each resume, preserving the original instructions. A pre-STR hit alone repeats an older result. C or D arrival, or a qualified exception record, is the new discriminating evidence. A missing event still does not uniquely identify an exception or prove GPU fetch.

## Validation performed offline

The helper was cross-compiled with Go for Windows AMD64. `audit.py` checks actual SDK vtable indices (including the variadic-method slots), allowed COM call sites, disabled-only methods and cleanup/readback invariants. `test_lifecycle.py` extracts the actual probe function and exercises it against fake COM: successful named-return cleanup, parameter rejection, failed creation, unexpected enabled state, wrong type, bad readback and failed removal. All seven cases passed; no post-removal object access occurred. A failed removal remains an explicit error, never an automatic replay. Root then staged the resulting helper and its native no-argument invocation passed with exit0/INERT; this does not exercise DbgEng. The tested executable SHA256 is `fdfda58a55cd5cce44972fbe273fdb9ac3a668399341e6bd7128a5efe5c82ebb`. These checks do not replace disabled-probe results or the actual benign hit test. No kernel operation or debugger connection has been performed by this helper.

The benign-hit test does not need another custom COM event inspector. Existing reviewed debugger-command transport can retain `bl`, `.bpcmds`, `.lastevent` and `r` output for exact owned breakpoint ID, processor-execute metadata, current PC and registers; root must additionally bind current thread/process and loaded code identity. Prefer this bounded existing observation route over a new event-callback client. Do not interpret status6 or a generic interrupt event as the owned execution-breakpoint hit.
