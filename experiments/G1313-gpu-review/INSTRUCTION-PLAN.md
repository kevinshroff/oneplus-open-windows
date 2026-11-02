# Fixed execution-breakpoint plan

**Current G1311 update:** the benign EL1 hardware execution channel has passed, and the exact compiled SQE-only outer callsite is now qualified at RVA192c4. Use [SQE-SPECIAL-CALLSITE.md](SQE-SPECIAL-CALLSITE.md) for the load-event gate and first breakpoint. The baseline discussion below predates that caller classification; do not arm the universal helper during early startup.

Prepared offline. This document performs no live operation and is not a reusable address configuration. The root operator must derive the newly linked variant's addresses and current loaded base before selecting instrumentation.

## Baseline identity and exact instructions

The supplied G1292 unsigned `OpenGpuStart.sys` hashes to `08f30c7158e0c740d40c67d99e2c6a7df9ea216413748607ebc83f070da31164`. Its preferred image base is `0x140000000`, image size `0x26000`. The link map identifies `G482GpuWrite` at RVA `0x1434c`, object `23_g482_resources.obj`; the outer `GpuWrite` is RVA `0x18cd8`, object `43_gpu_cp_native.obj`.

The retained complete REA function dossier `ev_711fb39ca5c19a472178f78b7d8d06d872255eba317d7ae39a41c204317c2119` binds exactly that binary digest and procedure `0x14001434c`. Its assembly supplies the instruction semantics below. PE section-aware byte extraction independently supplies the instruction words. `BASELINE-BOUNDARY.json` preserves this small, public-safe receipt. The giant earlier changed-function dossier was inspected only structurally; it was not needed to rediscover this already retained helper evidence.

| Baseline RVA | Instruction word | Instruction / stop meaning |
| --- | --- | --- |
| 143cc | 8b294149 | ADD X9,X10,W9,UXTW computes target |
| **143d0** | d5033f9f | **Stop A: before DSB SY** |
| 143d4 | f90007e9 | STR X9,[SP,#8], stack spill |
| 143d8 | f94007e9 | LDR X9,[SP,#8], stack reload |
| **143dc** | b9000134 | **Stop B: before STR W20,[X9]; pre-DSB passed** |
| **143e0** | d503339f | **Stop C: before DSB OSH; CPU advanced past STR** |
| **143e4** | 2a1f03e0 | **Stop D: before MOV W0,WZR; post-DSB passed** |
| 143e8 | a9424ff4 | Restore saved X20/X19 |

All four stops are immediately **before** their named instruction. Do not move PC, replace the STR with a nop, weaken a barrier or replay the start write. The helper has an inlined access-validation path, not a separate out-of-line Access routine. Binding, mapped mask, PASSIVE IRQL, offset and base validation precede A.

At A–D, the SQE start specialization expects W21=`0x2020`, W20=`1`, X19=current binding, X9=current mapped GPU base+`0x2020`. At A, X10 also holds that GPU base. Read RAM from the binding only if needed; do not dereference X9 as an extra GPU MMIO sample. The helper may still have W0=`0xc000008a` before D: it assigns success only at D, so that temporary W0 is not a failed admission. Its saved return address is at SP+`0x10` after the prologue; current X30 has been used by the IRQL call and is not a reliable outer caller witness.

Retained REA incoming references include outer calls at baseline RVAs `0x192c4` and `0x19394`, plus `0x12990`. These are reference observations only; this review did not classify which outer call is SQE-only. Do not use either as a unique SQE gate without reviewing the caller's actual variant assembly. Filtering the helper by current W21/W20/binding/thread avoids guessing the callsite.

## Root execution sequence

1. Before starting the owner, establish the fresh module-load stop and bind the signed payload to the reviewed variant's code. Derive the four variant RVAs using its map and REA disassembly; inspect the real loaded instruction words and current module identity. A module-load debug event does not require planting a software breakpoint in this helper.
2. Confirm the actual ARM64 debugger/controller supports **hardware execution breakpoints**. Confirm breakpoint type and execution access mode through the debugger's breakpoint metadata and successful configuration result. Reserve available hardware slots without deleting unrelated breakpoints. The historical record proves ordinary software breakpoints worked; it does not prove hardware execution support or slot availability for this controller.
3. Set a hardware execution stop at A, qualified for SQE offset/value and the selected owner. A debugger condition filters events after a hardware match; it does not make the hardware register comparison itself conditional. If avoiding all earlier GPU-write stops matters, first qualify the real SQE-only caller and gate there using another hardware execution stop. Do not assume helper-wide filtering has zero timing effect.
4. On the selected A event, capture PC, thread/CPU, X19/X9/W20/W21, current run identity and breakpoint metadata. Disable/remove the consumed hardware stop, arm B, and continue normally. Repeat B→C→D, removing each consumed stop before resume. This can reuse one hardware slot, avoids stepping commands, and leaves both barriers, stack operations and STR intact. Keep capture bounded and pauses short.
5. At D, record arrival and release the consumed breakpoint. Allow the unchanged instruction sequence to return and observe ordinary owner evidence. Do not force a return or alter status. If the device crashes or the debugger loses connection, stop this sequence: no retry, stale-base reuse or automatic recovery replay follows from this plan.

The exact command spelling and execution-breakpoint size accepted by this ARM64 controller remain unverified offline. Therefore this plan intentionally supplies no guessed `ba e <size>` command. For a DbgEng-based controller, the required semantic request is a hardware/data breakpoint with **execute** access, not a software code breakpoint; the controller must use its architecture-supported size and verify the returned type/parameters. Unsupported hardware execution is a reported blocker for this no-code-patch plan, not permission to silently substitute `bp`, `bu`, software BRK insertion, or instruction stepping.

Instruction reads alone may not prove absence of software patching because debuggers can present restored original bytes. Check breakpoint metadata and controller implementation, not just a reassuring disassembly. No such capability claim was made in this offline review.

## Interpretation and historical limit

A hit confirms access checks were passed. B confirms the pre-store DSB and two stack instructions passed. C confirms CPU progress beyond STR, but does not establish completed GPU fetch or instruction execution. D confirms CPU progress beyond the post-store barrier. Failure to receive the next breakpoint is still not a decoded exception cause: asynchronous fatal behavior and debug-event delivery remain alternatives. Capture exception PC/ESR/FAR only through an already functioning facility if available; do not invent registers from an opaque dump.

An earlier, different owner image already reached PRE-STR with the intended address/value and then entered900E without the next-instruction breakpoint being observed. That trial used software breakpoints and long pauses. It narrows that historical trial, does not qualify this baseline or the new VA variant, and means another pre-STR hit alone adds little. The useful new observations are C/D arrival, a qualified exception record, or a changed outcome with the isolated VA layout.
