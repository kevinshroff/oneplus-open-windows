# Root-owned benign EL1 breakpoint test commands

Templates only: replace `ENTRY`, `NEXT`, `THREAD` and `SIZE` with fresh qualified hexadecimal addresses and the accepted size. Do not paste placeholders or historical addresses. This uses existing reviewed debugger command transport, not a new callback client. No commands below were executed in this preparation.

Prerequisites are the current stopped ARM64 kernel and an empty breakpoint inventory, the fresh kernel module identity/symbols, a successful disabled-only probe result, and the exact staged ARM64 query caller. The root operator owns the stop/resume sequence. ARM64 supports only two execution processor breakpoints; this test uses one.

Read-only initial capture:

```
vertarget
lm m nt
x nt!NtQuerySystemInformation
u nt!NtQuerySystemInformation L4
bl
```

Select `ENTRY` from that actual symbol result. Check its loaded instructions and choose `NEXT` only after confirming the first instruction has a simple linear successor (no branch or exception instruction). If symbols/code are not qualified, stop rather than guessing an RVA.

Create owned ID0 with the size accepted by the disabled probe. The nested conditions deliberately avoid the historically problematic MASM `&&`. They filter for class35 (`0x23`) and length2, and leave the target held on a matching event. They do not prove which process issued it.

```
ba0 e SIZE ENTRY ".if (@x0 != 0x23) { gc } .else { .if (@x2 != 2) { gc } .else { .echo G1313_QUERY35_ENTRY } }"
bl 0
.bpcmds
g
```

These are **processor execution** breakpoints. Do not substitute `bp`/`bu`. Record any insertion error on resume as a failed channel result. Root next invokes the staged caller exactly once with `query35`, using its existing independent dispatch mechanism. Do not kill/retry that caller while the kernel is held.

When an event arrives, record these separately through the reviewed command transport:

```
.lastevent
bl 0
.bpcmds
r pc,sp,x0,x1,x2,x3
? @$thread
? @$proc
!thread @$thread 0
!process @$proc 0
u @pc L2
```

Require the owned breakpoint ID0, exact entry PC, class35/length2 and the intended query caller process. The process image/identity must match the staged native helper; an unrelated system-information query is not that trigger. Preserve the current ETHREAD as `THREAD`, not a TID. If desired, a fresh `/p EPROCESS` restriction can be used when the caller process was independently established before arming; a PID is not valid there.

After recording the event and verifying the first instruction's linear successor, remove ID0 and set a new processor execution breakpoint at `NEXT`, restricted to that same kernel thread:

```
bc 0
ba0 e SIZE /t THREAD NEXT
bl 0
.bpcmds
g
```

On the next event, repeat `.lastevent`, `r pc,sp,x0,x1,x2,x3`, `? @$thread`, `? @$proc`, `!thread @$thread 0`, `!process @$proc 0` and `u @pc L2`. Require the exact successor PC, owned ID0 and same ETHREAD/process. Stop B demonstrates CPU progress past the original entry instruction. Remove only the owned breakpoint and resume:

```
bc 0
bl
g
```

Collect the query caller's native returned JSON. Expected success has NTSTATUS0, returned length2 and sample_valid=true. Both debugger flags are observed data, not preconditions for success. A state6 or ordinary manual interrupt alone does not satisfy the hardware-hit test. No event means no proof; it does not justify another CP start.

`bl`/`.bpcmds` retain the processor-execute definition; `.lastevent` identifies the actual event; registers and thread/process identify where it occurred. The separate hardware configuration probe reads the DbgEng processor type and access parameters directly. Together these are stronger than merely reading original code bytes, because debuggers can virtualize software-breakpoint instruction reads.

Reference semantics: [Microsoft ba command](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/ba--break-on-access-), [ARM64 debugging](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-arm64). The command templates remain subject to native parser acceptance and actual execution observation; no local test claims a remote hardware hit.
