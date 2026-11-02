# G1315: WDDM integration boundary and one latent completion fix

Offline source inspection only. No G1287/G1311 owner change, hardware access,
native link, signing or adapter enablement. G741 is the earlier HAL discovery
checkpoint; G779 adds real GMU/CP/owned-submit source but still deliberately
withholds rendering. Successful CP fence1 in OGO will not make G779 ready.

## The two command paths currently diverge

Mesa G739 `fd_wddm.c` turns msm ioctls into `DxgkDdiEscape` calls. G779
`msm.c:Submit` snapshots and validates arrays/BO ownership, then calls
`HwSubmitOwned` -> `G433SubmitAuthorized` -> `g433_cp_submit_run`. This is a
real packet/submission implementation with no installed authorization provider.
It expects a live managed HAL-S1 role and CP stage9 after authenticated ZAP and
secure-mode fence2. It is not connected to OGO's native CB0 context.

`DxgkDdiSubmitCommand` is a separate path: it queues private `TG_CMD` records to
`eng.c`, whose PASSIVE worker performs CPU blits/fills/aperture operations and
reports a scheduler fence. It does not execute A740 IBs. Those scheduler fence
IDs are distinct from the CP's hardware completion sequence. The UMD's
`topaz_wddm.cpp` creates shared/WDDM allocations naming BOs and uses linear CPU
presentation after render work; it is not an A740 presentation implementation.

| Area / actual G779 source | Implemented behavior | Remaining boundary |
|---|---|---|
| `ddi.c:TgStartDevice` | Copies Dxgkrnl interface, obtains translated resources, calls `A740BindDevice` | Always returns DEVICE_NOT_READY after successful bind; worker/Started/success path unreachable |
| `hw.c:A740QualifyRuntime`, GMU/CP wrappers | Owner callback/currentness checks and concrete staging | No OGO provider; `CpReady` never set; don't set it to bypass missing components |
| `a740_hal.c` | Discover/create/attach/map/unmap bookkeeping and poison/retain | HAL managed-S1 ownership differs from OGO's bank/table authority; cannot attach both |
| `msm.c`, `msm_validate.h` | Copied-array checks, BO ownership, command spans, escape dispatch | Metadata bounds do not authorize arbitrary PM4; actual `G433_SUBMIT_AUTH` Begin/End absent |
| `g433_runtime.c` | Owned-MDL mapping, synchronous authorized submit and bounded poll | Requires PAS/ZAP/secure transition and HAL-S1 role; current OGO finishes at fence1/stage6 |
| `ddi.c:TgCreateAllocation`, paging/present | Real donor allocation bookkeeping and CPU operations | Not live A740 residency/page-table integration |
| `ddi.c:TgInterruptRoutine` | Always FALSE | GPU completion IRQ qualification/ack/notification absent |
| `TgDpcRoutine`, `CompleteFence` | Dxgkrnl callback plumbing | Currently driven by CPU work, not observed GPU interrupt/fence |
| `HwCompletedFence`, `HwWaitFence`, `HwTimestamp`, `HwGmemSize` | Zero or readiness refusal | Must read actual provider state; no completed render fence is exposed |
| `TgPreemptCommand`, timeout reset/restart, `TgResetDevice` | Success/no-op stubs | No real preemption, reset, context restore or recovery |
| Stop/remove | Cancels staged runtimes; probe release guards | Not a qualified live-DMA drain/removal lifecycle |

Source reference root: `drivers/gpu/gpu-wddm-bridge-G779/source/`. G741
`source/hw.c` lacks the later GMU/CP composition entirely; starting from G741
would discard useful G779 validation rather than connect the current owner.

## Narrow code change

`G779/source/ddi.c:TgSubmitCommand` previously called `CompleteFence` and returned
success when `EngSubmit` rejected the packet (worker absent or allocation
failure). That reported work as completed although it never entered the queue.
The change removes fabricated completion and propagates the failure. It retains
the existing LastSubmittedFence publication before EngSubmit can wake the worker.
On fatal queue failure that field therefore records the attempted submission; it
is not claimed to be an accepted-only counter. StartDevice remains closed.

This is a fail-closed latent-error correction, **not** a usable backpressure
implementation: legacy SubmitCommand error returns cause Dxgkrnl bugcheck0x119.
Before opening the adapter, reserve/preallocate submission storage before this
DISPATCH-level callback rather than relying on fallible allocation there.
[Microsoft's SubmitCommand contract](https://learn.microsoft.com/windows-hardware/drivers/ddi/d3dkmddi/nc-d3dkmddi-dxgkddi_submitcommand)
also rules out calling the sleeping G433SubmitAuthorized implementation directly
from that callback. Do not convert queue failure into either invented completion
or a claimed recoverable rejection.

Run `python3 experiments/G1315-wddm-integration/test_submit.py` from repository
root. It extracts the actual changed DDI body, substitutes only queue acceptance
and scalar WDDM types, and checks worker-absent/allocation failures and successful
queue acceptance under ASan/UBSan. The stub also verifies that LastSubmittedFence
is published before queue entry, which can wake/complete work immediately.
Three cases pass. This is CPU source testing,
not a scheduler or hardware qualification. Full DDI COFF compilation was
attempted with the G1311 external WDK profile but stopped at missing Microsoft
`acpiioct.h` in `dispmprt.h`; a complete display WDK header closure is required.

## Concrete integration order after first native completion

1. Keep OGO as the sole hardware owner. Add a referenced kernel provider bound
   to the actual PDO, boot generation, bank token, owner thread/scope and rundown.
   It must reacquire real `OasEnterRunningScope` authority for work and preserve
   retain-on-uncertainty. Do not cast G1287 `G433_RUNTIME` into G779's distinct
   layout or call `A740HalOpenRole` against the already-owned SID0/CB0 context.
2. Qualify the real post-init security transition separately: current OGO ends
   at CP stage6/fence1. G779 submission requires authenticated ZAP, secure-mode
   transition and fence2/stage9. Port only reviewed submission routines and
   state fields into the current CP core after that boundary; wholesale G779
   replacement would lose later cold-start/BV-shadow/budget fixes. First prove
   one immutable kernel-owned IB and real completion under the same owner.
3. Implement owner-backed BO residency/mapping and lifetime. OGO's current
   inactive table build maps four private BOs/29 pages; it has no dynamic user-BO
   VM contract. G779's HAL Role.MapHead checks cannot stand in for that contract.
   Require actual page-table/TLB publication, coherent data, generation/rundown,
   PM4/resource authorization, and retention of mappings/seals on uncertain DMA.
   Bind this implementation behind existing `HwSubmitOwned`/authorization
   callpoints; retain validation of the copied msm arrays.
4. Keep sleeping owner work off DISPATCH_LEVEL. Introduce reserved asynchronous
   submit records, retaining BOs and translating scheduler fence IDs to actual
   hardware sequence IDs. Notify Dxgkrnl only after genuine completion, with
   actual interrupt/DPC synchronization and ordered wrap handling. Real stop,
   preemption/TDR and recovery must drain or retain all outstanding work.
5. Only after those contracts exist, replace the unconditional StartDevice
   refusal with provider acquisition and complete readiness checks. Start
   render-only with zero sources/children, preserving the existing framebuffer.
   Bring Mesa render/BO/fence escapes up before adapting display/presentation.

The next concrete owner patch is the generation/rundown-bound provider plus a
single kernel-owned IB submission under existing scope, after authenticated
fence2. An empty interface or a `CpReady=TRUE` assignment would not supply that
behavior. No speculative provider/mock framework was added here while fence1
and that security boundary remain unproven.

## Rebuild gaps

The G1311 35-object recipe produces the native owner, not a WDDM KMD: it includes
a different entry point and no DxgkInitialize/DDI/display import closure. G779
needs its own explicit source inventory, complete display WDK headers, reviewed
Dxgkrnl/kernel import libraries, ABI/resource INF and native link recipe. No
portable public G779 full-image recipe currently exists. A successful owner
link is not a substitute.

Mesa G739 is an overlay against commit
`62f1e49a1eb3a408f748725326fe53447887f97d`: apply `final-tracked.patch` once, then
copy the shipped final-untracked overlay. Upstream Mesa/toolchain/generated
headers and Windows D3D10 UMD dependencies remain external. No full reproducible
public configure/link/package recipe is included. Neither a historical ARM64
D3D10 DLL nor the A610 donor establishes A740 support or presentation.
