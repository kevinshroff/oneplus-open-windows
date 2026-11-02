# G1311 SQE-only hardware-breakpoint gate

Select **RVA0x192c4**, instruction word **97ffec22**, `BL G482GpuWrite` at RVA0x1434c. This is the dedicated `CP_SQE_CNTL` path after the optional STORE_CALL_BEGIN logging call returns. It avoids trapping the earlier ordinary GPU writes. This is static compiled evidence; no live GPU breakpoint was placed during this review.

Identity: exact G1311 unsigned `OpenGpuStart.sys`, SHA256 `3ee73237c4311eec9fe083f3d5067407bde1884d84bddb9f8d65c2370dba1d4b`, preferred base0x140000000. Map symbol `GpuWrite` starts at RVA0x18cd8 in `43_gpu_cp_native.obj`. REA complete function dossier `ev_7a818142e8e57a7ff3e4ca5fb51680094524eff7c685177dcfd3699ae7cd5b95` was produced for that exact artifact, exported privately and the native session closed. [Compact instruction receipt](SQE-SPECIAL-CALLSITE.json) retains the selected decoded instructions and independently extracted PE instruction words. The encoded BL target was also checked directly from its signed immediate.

## Compiled path and register shape

The function saves the caller's offset into W21 and value into W19. RVA18d68 compares the offset with2020; the following branch selects the special path. RVA18d70 compares W19 with1, and any mismatch takes a rejection path. Later RVA1920c compares the offset again and RVA19228 branches to the generic path at19384 if it differs. Generic writes call G482GpuWrite at19394, not192c4. Thus no filter on the universal helper entry is needed.

| RVA | Word | Instruction |
| --- | --- | --- |
| 192b0 | d63f0100 | BLR X8, optional STORE_CALL_BEGIN DbgPrintEx |
| 192b4 | 91078296 | ADD X22,X20,#0x1e0 |
| 192b8 | 52840401 | MOV W1,#0x2020 |
| 192bc | 2a1303e2 | MOV W2,W19 |
| 192c0 | aa1603e0 | MOV X0,X22 |
| **192c4** | **97ffec22** | **BL helper RVA1434c — selected stop** |
| 192c8 | f942ae88 | LDR X8,[X20,#0x558], first instruction after helper return |

At the selected stop, before BL executes:

* X20 is the owner pointer; X0=X22=X20+0x1e0 is the binding pointer.
* W1=W21=0x2020; W2=W19=1.
* The first-use/masters-may-run software flags have already been conservatively set. Do not require them to be zero or interpret them as a retired hardware write.
* If logging was eligible, its call returned before this stop. The gate is still reached if tracing is suppressed; logging is not its admission condition.

Inside G482GpuWrite the register roles change: X19 becomes the binding, W20 becomes value1, W21 stays offset2020, and X9 becomes the actual mapped GPU address+2020. At the inner points the outer caller return address is saved at SP+0x10. Do not confuse outer X20=owner with inner W20=value.

## Load gate before the independent owner restart

The current selected service image alias is `OpenGpuStart-G1311.sys`. First record `sx` and the current breakpoint inventory, then set:

```
sxe ld:OpenGpuStart-G1311.sys
sx
```

The `ld:Module` form accepts a module-name string, and an unbracketed hyphen is literal. Only the latest load filter is retained. [Microsoft event filters](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/controlling-exceptions-and-events), [wildcard syntax](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/string-wildcard-syntax). Microsoft's driver sample documents this load-event technique as stopping before driver code executes. [Driver debugging tips](https://github.com/microsoft/graphics-driver-samples/wiki/Debugging-Tips).

Root then starts the independently owned, exact broker/owner PnP sequence. On the owner load event, require the actual `.lastevent` load identity, selected image alias, freshly loaded base and PE identity. Bind it to the reviewed signed payload and its unchanged unsigned code; compare the loaded gate block and helper instruction words against the exact receipts. Do not substitute an old module base or a symbolic expression containing an ambiguous hyphen. Module-load evidence is not evidence that DriverEntry or hardware initialization completed.

Let **B** below mean the actual qualified numeric base, substituted by root; it is not a debugger variable. With one owned empty slot, arm only:

```
ba0 e 4 B+0x192c4
bl 0
.bpcmds
```

Restore **only** the previous `ld` policy while still held, and verify it with `sx`. For example, use `sxi ld` only if the captured previous policy was Ignore; use `sxn ld` if it was Output. Restore any previous module filter too. Do not use `sxr`, which would reset unrelated event policy. Then resume normally. This arms no universal G482 helper breakpoint during GMU startup or earlier GPU configuration.

At the owned gate hit capture `.lastevent`, `r pc,sp,x0,x1,x2,x19,x20,x21,x22`, `? @$thread`, `? @$proc`, and the loaded instruction. Require the selected PC, owned breakpoint ID and argument shape above. Preserve the actual owner/binding/ETHREAD in the root receipt.

## Move the one slot into the exact helper window

After the gate is qualified, clear ID0 and arm a processor-execute stop at B+143d0 restricted with `/t` to the captured **ETHREAD address**, then resume the unchanged BL. For each subsequent point, clear the consumed stop and move the same slot to the next point. Never use stepping, software BRK breakpoints or register/PC changes.

| Next RVA | Word | Observation on arrival |
| --- | --- | --- |
| 143d0 | d5033f9f | Before DSB SY, helper admission passed |
| 143dc | b9000134 | Before STR W20,[X9], pre-DSB and stack spill/reload passed |
| 143e0 | d503339f | Before DSB OSH, CPU advanced past STR |
| 143e4 | 2a1f03e0 | Before success MOV, post-DSB passed |

Command template for each selected point:

```
bc 0
ba0 e 4 /t ETHREAD B+RVA
bl 0
.bpcmds
g
```

Capture the exact event ID/PC/thread and registers at each arrival, keeping holds short. W0 before143e4 can still contain the helper's default failure value; success is assigned only at143e4. If the helper completes, let the original code return; a later outer marker is not required to establish arrival at143e4. The outer returned-instruction address for this call is192c8.

Successful benign EL1 hardware hits establish the observation channel, not GPU success. Missing the next breakpoint still leaves immediate fatal target activity and event-delivery failure distinguishable only with stronger exception evidence. Do not replay a start write after an uncertain result. The native owner operation must retain its independent lifetime; the180-second agent timeout accepted for the benign class35 query does not authorize placing GPU initialization under that watchdog.
