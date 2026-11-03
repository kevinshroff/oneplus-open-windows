# Agent handoff — Wi-Fi and GPU development

Latest update (Boot177):

- [G1348 hardware result](../experiments/G1348/HARDWARE-RESULT.md): one SID0 instruction-translation query matched the expected MDL page, with result8/status1, restored controls and uncertainty0. GMU/HFI startup succeeded. Windows remained responsive; native calls returned and future Starts4/once0 were verified. No SQE start, packet, command fence or WDDM execution occurred.
- The timer’s required output pointer and CB0 writable-mapping defects are corrected. The broad diagnostic mapping remains read-only; owner and TCU-vote firmware were reused. Continue toward first command/fence only under a new conditional owner profile with fresh same-run authority checks.
- G1349 initialized once, queried the cache once, submitted one saved-profile connection and obtained no DHCP address within25seconds. The loaded scan-priority code words matched. The existing CPU transport log is retained for comparison; no conclusion about target-visible priority or association cause follows from the cache result alone.

Previous update (Boot173):

- [G1342 hardware result](../experiments/G1342/HARDWARE-RESULT.md): two accepted native CE3 reads returned HP20/TP20. Fifteen stable CPU spans matched local/cached/RRI indices20, software entry slots5/5 and reap16→20; all32 ownership-context slots were zero. EP2 queue7/credits0 makes this a credit-blocked snapshot without persistent source TX backlog. Correct device-visible payloads and target WMI execution remain unresolved.
- One initialization succeeded without a reboot request. The initializer requested no scan, cached-list query or connection.
- [G1343 zero-write control](../experiments/G1343-zero-write-control/HARDWARE-RESULT.md) returned through the original store/barriers, post-AHB0 and readback0, with Windows still reachable. It then stopped intentionally at stage3 with no submission/fence. This narrows the earlier value1 failure toward release/value-dependent behavior; it does not prove a healthy first fetch. The task verified future Starts4/once0 while retaining hardware ownership.

Previous update (Boot172):

- [G1340's actual hardware result](../experiments/G1340/HARDWARE-RESULT.md) establishes a working bounded native CE2 getter: four accepted register queries matched the later stable CPU snapshot. Status HP/TP were 132/132 and destination HP/TP were 62/66, in DWORD index units. The observations were sequential, not atomic; the CPU capture's pause upper bound was 910.4454 ms.
- Wi-Fi remains unconnected. One initialization succeeded without a reboot request, but the trace again ended with EP2 credit 0 and queue 25. The 9,144 retained records contain 101 credit debits and 100 returns from initial credit 1; the final debit was START_SCAN 40965. No later WMI RX or credit return was recorded, including after the getter queries. The 677.429164-second retained interval starts at the last credit return, not the final debit.
- Matching hardware producer/consumer indices, CPU cached indices and RAM RRI shadows show no persistent CE2 status receive backlog at these observations. They do not prove firmware death, delivery/execution of the final TX command, absence of transient servicing faults or correctness of all coherency paths. The getter uses the native wake/lock/window protocol; actual DMA cache attributes remain unmeasured despite the loaded noncached-allocation instruction match.
- Source-qualified CE TX publication/ownership is the next distinct evidence gap. Do not repeat timing/cache variants or infer networking from scan notifications. No new GPU hardware outcome is established by this Wi-Fi checkpoint; retain the prior GPU results below.

The [G1341 matched containment trial](../experiments/G1341-cb0-stall-containment/HARDWARE-RESULT.md) subsequently reached the same SQE start-call boundary and confirmed Qualcomm 900E without a store return or fence. The unchanged profile is consumed. Acknowledged software reset and fresh recovery-kernel attachment followed; the detailed result distinguishes selected disk images from independently measured mapped-image identity.

Previous update (Boot171):

- Wi-Fi4478/firmware341 matched package installs and initializes without reboot; all18 runtime files and platform policies verify. Corrected published-INF→DriverStore selector and exact native source qualification are in G1333.
- The first requested RF scan received two management frames and firmware completion. A later scan60seconds afterward exhausted the final command credit; no later RX/credit return, association or DHCP. Both the immediate Boot169 and cache-only Boot170 trials failed to obtain DHCP. Windows still initiated a scan in170 despite zero task scans/statistics reads.
- G1335 low-physical candidate has35-object parity/boundary tests, native MSVC link and bounded compiled review. It changes CP BO/table placement only, retains original IOVAs and GMU policy, and was activated once on Boot170: it again entered900E at the release-store boundary, with no store return/fence. Low physical placement alone did not fix it. No WDDM acceleration yet.
- G1334's low-SQE trial is consumed and negative; recovery is complete. Keep GPU disabled during Wi-Fi work and do not reuse old Wi-Fi RVAs on4478.


Status date: **2026-11-03**. Development resumed with owner approval for Wi-Fi and GPU acceleration. This handoff records the publication baseline and subsequent work; it is not a general live-device authorization or an installation recipe. Re-establish actual device/boot identity before each experiment.

Resume work is tracked in [G1311 GPU VA experiment](../experiments/G1311-gpu-nonsecure-va/README.md), [G1312 Wi-Fi observations](../experiments/G1312-wifi-resume/BOOT162-OBSERVATIONS.md), and [G1313 independent GPU review](../experiments/G1313-gpu-review/REVIEW.md). The GPU variant built, linked with native MSVC, passed compiled review, and reached the same fatal CP start-call boundary in a hardware trial. Original Wi-Fi initialization succeeded and early firmware scans reported BSS entries, but firmware replies and credits subsequently stopped; usable networking remains unfinished.

The [Boot167 Wi-Fi comparison](../experiments/G1326-live-vdev2-observer/BOOT167-RESULT.md)
completed: the pending PRE receive entry was serviced, the error tuple stayed
unchanged, and credits still stopped. The [G1334 low-SQE trial](../experiments/G1334-low-sqe-iova/HARDWARE-RESULT.md)
then confirmed the reference address but reached the same fatal start boundary;
software recovery restored WinPE control and disabled future GPU starts.
A [newer matched Wi-Fi package](../experiments/G1333-wifi-new-package/README.md)
initialized on Boot168 and completed the first RF scan, but a later scan again
stalled credits. See its runtime result and immediate-connection next step.

The [Boot169 immediate-connection trial](../experiments/G1336-wifi-immediate-connect/README.md)
requested connection7.162seconds after initialization but still failed association
and DHCP. Its first postscan command again exhausted the final credit. A metadata
observer exposed three incorrect cross-wrapper assumptions in the reader; the
allocation headers matched, and no driver-data corruption was established. The corrected observer completed65 paired CPU-state reads; software wake counters showed no recorded failures, without proving hardware receive state.

## Read first

1. README.md and STATUS.md distinguish demonstrated features from prototypes.
2. SOURCE_MAP.md identifies current source closures. Most numbered experiments are historical.
3. CREDITS.md and file-specific notices describe dependencies and licensing.
4. BUILDING.md explains missing external inputs, privacy placeholders and build limitations.

The former private repository's old leading README described a much earlier sensor/touch checkpoint. Its live-state paragraphs are superseded. This public repository has a new publication history; private transcripts, job databases, snapshots, signed capsules and captured binaries are intentionally absent. A private operator may possess additional evidence. Do not fabricate their contents or treat a source identifier as a currently loaded image.

## Historical publication checkpoint

The last normal Windows experiment used the G1287 GPU owner. Its fixed NORMAL secure-aperture call returned successfully once, GMU/HFI and later CP setup proceeded, and the phone then entered Qualcomm 900E at the first SQE-start write-call boundary. A Sahara RESET request received its ACK, and the USB-EEM network interface subsequently reappeared. Fresh WinPE/Windows control had **not** been confirmed at that historical publication checkpoint; the resume results below supersede that recovery status. The debugger's old GO status and old log are not proof of a new kernel connection.

That historical failure could leave experimental startup/once flags armed; the latest recovery re-established the fences described below. Before any later normal-Windows boot, verify recovery control and offline-fence the actual Windows SYSTEM control sets: `OpenGpuStart` Start4, BootstrapOnce0, CpInitFenceOnce0 and ScmApertureOnce0; `OpenSmmuD0` Start4. Do not mount the wrong hive or equate a successful emergency reset with completed fencing.

Preserve the installed Windows system, working native touch, desktop scaling, development test-signing configuration, black cover framebuffer, Never sleep/display settings and WinPE recovery default. Do not enable charging, change clocks or run overlapping hardware owners as incidental preparation.

## Resume checkpoint

Recovery WinPE control was restored after the temporary G991 boot. The actual offline SYSTEM hive was opened and its existing control sets enumerated. The GPU owner is now Start4 with BootstrapOnce, CpInitFenceOnce and ScmApertureOnce all0; the GPU broker and Wi-Fi service are Start4. All values were read back and the hive unloaded successfully. This prevents the prior GPU attempt from automatically running on the next normal boot.

G1311 builds the complete 35-object owner from the public closure with explicit external Microsoft headers. All 35 baseline objects match the historical build. The nonsecure64 build differs only in the intended CP address-layout object. Its hardware trial confirmed the new address high words but did not achieve CP execution or a fence. G1312 supplies stricter Wi-Fi artifact binding and source-qualified history decoding.

Normal Windows subsequently booted successfully with the selected nonsecure64 owner still disabled. The known parent cold-start repair completed, and the exact G991 pre-Wi-Fi post-EBS comparison passed all50 measured words. A fresh debugger transport initially remained in NoDebuggee7; one qualified attach interrupt resolved it, and the owned stop was resumed. Refreshing the debugger module inventory was also necessary before interpreting empty module queries as absence.

The planned G1295 PRE baseline could not be admitted: Windows reported the disabled Wi-Fi endpoint with problem32 and no allocated BAR memory resources. No G1295 phase was invoked or consumed, and there is no baseline tuple. Do not invent one or force the paired POST schema. One original initialization and explicit scan subsequently completed without a reboot request, but cached networks remained empty. Source-qualified CE2 and host-log captures show early receive/interrupt activity and later credit starvation; no retained zero-length-reap event supports the proposed ordering patch. The existing scan trace was retrieved and decoded without another scan. The [WDDM integration review](../experiments/G1315-wddm-integration/README.md) identifies remaining real submission boundaries and removes a latent fabricated-completion error; the adapter remains disabled.

The isolated G1311 VA trial confirmed the intended address high words but again entered Qualcomm900E at the SQE-start boundary. Later manual hardware execution-breakpoint captures reached the STR stop after the pre-store DSB completed. Releasing that stop led to900E; neither later stop was observed. This narrows the boundary but is not formal proof of store retirement or a recovered fault PC. The host callback-based debugger helper encountered a DbgEng access violation and is deprecated; do not reuse it.

WinPE control was subsequently recovered and the actual offline Windows startup/once fences re-established and verified. G1318 added only the four source-parity SECVID/TSB zero stores. Its native-linked, compiled-reviewed and signed-content-verified owner then ran once with ordinary logging and no instruction breakpoints. All four new stores returned successfully, but the same SQE start-call boundary led to900E without a first fence. WinPE control and offline startup fences were recovered and verified again. This parity gap did not resolve first CP start; do not repeat the consumed activation. No CP completion or acceleration is established.

Boot163's [P2P exclusion](../experiments/G1312-wifi-resume/P2P-EXCLUSION.md) reached the actual compiled gate and removed the Wi-Fi Direct lifecycle, but the same credit stall recurred. The first four successful HT submissions also used the same printed body and credit-request/debit1→0 behavior as the fifth stalled submission. Compiled WMI transport resynchronizes DMA after writing the final HTC header; actual device-visible header bytes remain unavailable. No credit or cache patch follows from this evidence. The [legacy mode trial](../experiments/G1312-wifi-resume/LEGACY-MODE.md) subsequently confirmed runtime modeSelect0x2c, six HT/VHT builds each with length0, and no retained host-log VDEV SET_IE submission. The credit/reply stall persisted after a START_SCAN submission, with zero cached networks. This excludes the HT capability command as a necessary trigger; it does not identify a firmware fault site or establish device-visible bytes.

## Architecture and achieved foundations

Windows runs directly on SM8550 ARM64 hardware. The boot path preserves OEM firmware components and composes reviewed DXE/ACPI additions; it is not a clean-room replacement of all Qualcomm/OnePlus firmware. Windows' existing CPU, filesystem/storage and USB functionality is reused. Device-specific resources, memory maps, interrupt routing, IOMMU ownership and peripheral/power interfaces require custom work.

Early storage progress depended on correct 4 KiB geometry, suitable filesystem sizing and Microsoft Basic Data partition typing. WinPE became interactive before the full Windows installation reached its desktop. Later boot-volume/BCD recovery work enabled continued installation and boot repair. A historical boot-repair header containing captured GPT data is deliberately replaced by a compile-stopping placeholder; regenerate local data instead of sharing identifiers or boot sectors.

The inner display uses an existing framebuffer path. Cover blanking writes and verifies black pixels; it does not electrically power off that panel. Native touch was physically exercised and reported excellent by the operator, including sustained drag/hold/lift behavior. Current input source is the G379 clock-vote integration and its local dependencies, not the earlier G185 snapshot. Keys have an integrated reader, but physical power-button off/wake remains unverified. Production charging, battery reporting, audio, Bluetooth, camera, cellular and complete suspend/fold behavior are unfinished.

## GPU: exact current boundary

Relevant source: G1287 cold-aperture owner/broker closure, G1268 query-only helper, current parent G746, G741/G779 WDDM scaffolding and Mesa integration sources. G numbers identify experiments/source revisions; they are not compatibility or driver-quality scores.

Demonstrated separately:

- Native resource ownership and actual GMU firmware/HFI initialization, including startup acknowledgements.
- CPU-side GPU buffer contents, translation-table construction and register readback. These do not prove GPU fetches.
- A fixed FAST INFO64 query `x0=c2000601, x1=1, x2=02000c1b`, reserved arguments zero. One invocation returned raw x0=0/x1=1: the service is advertised available.
- The fixed NORMAL64 setter `x0=42000c1b, x1=4, x2=ffff0000, x3=x4=x5=ffffffff`, initial x6/x7 zero. G1287 invoked it once under real cold ownership before translation activation/GMU release. Raw x0/x1 were0/0, with one entry/return and no interrupted continuation.
- The changed baseline still reached the first CP start-call boundary and crashed into900E. It is not an acceleration result or a successful CP fence.

G1287 placement matters. The owner reserves CB0/SID0/ASID0, qualifies its token before entering the namespace interval, and invokes the setter inside `OasActivate` after cold/namespace/bank/fault/table admission but before programming translations. It rechecks admission afterward. The new `ScmApertureOnce` service-root option defaults off and requires explicit CP/bootstrap opt-ins. Attempted failures, unsupported asynchronous results and lost postconditions retain ownership and block continuation. Software namespace/mutex ownership must be released safely; generic unpublished cleanup must not unwind uncertain hardware state.

Keep query and setter semantics distinct. INFO's x1 is an availability value. The reviewed normal dispatcher places the setter handler's return in the native frame's x0; support failure16 is not a successful x0 with an ignored x1 error. Preserve all raw registers. Only full-width interrupted1 receives its exact continuation/cookie; busy errors do not automatically replay, and WAITQ2/3 are deliberately unsupported/retained. A process timeout cannot cancel secure firmware execution. A private mutex does not serialize every Windows firmware consumer.

The original secure resource graph has been traced: the selected GPU SMMU clock request uses03d95000, with an optional03d95004 dependency, while Windows' HLOS1 vote is03d97000. The selected static dependency graph does not traverse the generic CX/MX vote/unbounded chain-poll paths examined earlier. The enabled-GPU original cold initializer programs the aperture and balances resource acquisition/release. Runtime counts, later reconfiguration and aperture persistence through subsequent power transitions remain unmeasured. The setter experiment is a valid source-baseline trial; it neither proves the original aperture was missing nor excludes every retention issue.

### Do not overinterpret the fatal boundary

The historical `STORE_CALL_BEGIN` marker alone did not distinguish the helper's pre-store DSB, STR and post-store DSB. Subsequent manual hardware-breakpoint evidence reached the STR stop after the pre-store barrier completed, then release led to900E without either later stop being observed. Do not promote that ordering to a formally retired store, completed command or known fault PC. `CP_SQE_CNTL=1` is the reviewed start encoding; warm halt uses3. The AHB fence readback is distinct from `CP_AHB_CNTL`.

The nonsecure64 VA discriminator has already been consumed: address high words matched, but no CP completion followed. Do not present it as an unrun next experiment or replay the consumed task. G1318's separate four-zero-store parity trial also failed after its new stores returned; explicit zero-store parity did not resolve the start boundary. Applicable source ordering still does not support moving ZAP/PAS ahead of CP initialization, adding an arbitrary ME-enable write or changing unrelated SMMU/cache attributes. Keep the original hardware owner, admission and retention rules; use fresh boot/current evidence and ordinary logging for the selected next trial.

### WDDM distance

The complete current public KMD closure now builds all21 translation units against real Microsoft headers and links successfully with native MSVC. The resulting ARM64 WDM image passed a focused compiled review; it remains unsigned, uninstalled and intentionally refuses startup without a working GPU provider. See the [G1330 full build](../experiments/G1330-wddm-link-prep/README.md) and [G1315 integration review](../experiments/G1315-wddm-integration/README.md). This closes the native build/link blocker, while adapter functionality remains unfinished. The first CP completion is still a prerequisite. WDDM/Mesa work includes compiled prototypes, a built ARM64 D3D10 UMD and owned-BO/submit/authorization scaffolding; none establishes a functioning A740 accelerated adapter. Reliable submission, completion interrupts/fences, memory residency/lifetime, reset/recovery, scheduling/DDIs, userspace compatibility and presentation still require integration and real hardware validation. The Topaz donor's A610 backend must not be presented as A740 support.

## Wi-Fi: what is and is not established

The original Qualcomm Windows driver reaches firmware/HTC startup and initial exchanges. Earlier experiments received AP beacons. Later response/credit activity stops; stable association, DHCP and traffic are unproven. A successful native initialization API, scan notification or queued connect request is not connectivity.

The retained Boot162 and Boot163 host logs show early real firmware scan/channel/BSS activity followed by endpoint2 credit starvation. Boot163 proved P2P disabled without removing the recurrence; its last returned payload/credits differ from Boot162 while the later HT submission boundary remains common. The26-byte HT IE fits the target's31-byte limit. The mapped target wrapper takes a copy-shaped path; no command-buffer free/credit producer has been proved there. Do not truncate that valid IE or inject credits based on this observation.

Investigations already completed and not worth blindly repeating:

- Actual root/endpoint D0, linkL0 and ASPM/CLKPM/L1SS enable bits off in the observed state.
- A historical CE2 hardware/software index comparison matched, without a demonstrated unreaped receive backlog.
- Source-backed host credit-request intent is present.
- The corrected native QMI read was attempted after the transport had stalled and timed out; its zero buffer is invalid data, not a memory observation. Do not replay that request into a known stalled transport.

An unforced post-stall status read found normal MHI state/EE and no SYSERR, alongside BHI debug values CAFECACE / CAFECACE /014feeab /496. In the original initialized firmware image,014feeab is exactly the string `cmnos_thread_patch.c`; candidate packed metadata also contains496 and that filename pointer. The middle candidate value01414020 has no initialized/BSS backing in the supplied ELF. The writer, record format, timing and causal connection to credit loss remain unknown. Do not promote this correspondence to an executed assertion at a known source line, label unmapped data ROM, or import semantics from the different CAFECAFE marker.

The original host error predicate looks at MHI SYSERR and BHI transfer-status bits; it does not inspect these error/debug fields. Therefore normal host error detection does not resolve the tuple. The old fallback consumer copies raw typed data and does not establish assertion semantics or an epoch.

The G1295 phase-aware reader remains available only if a fresh pre-HOST-init state independently satisfies its allocated-resource and access guards: one qualified baseline and one post-stall observation around one original initialization/scan. It must not run its pre-init phase in the already-consumed epoch. It uses explicit action counts, current resource/image evidence and distinct per-phase markers; pre-init evidence must not contain a fabricated future failure hash. If access/power/memory-decode guards fail, refuse the baseline. An already-present tuple weakens a newly-created-stall interpretation; a new tuple bounds assignment to the interval, not the exact SET_IE instruction. The actual disabled-service state supplied no allocated BAR baseline, so this reader was not run. Do not force a paired POST or invent a PRE tuple; prefer the already source-qualified host log for the selected legacy-mode discriminator.

## Additional closed investigations and traps

### Secure-call transport

The original pre-EBS G1245 query did not issue a secure call: its PE identity guard rejected the real provider header (`e_lfanew=0xe58`) because it imposed a0x400 bound. The corrected r2 used the actual production qualification path against the original mapped PE, compiled and passed packaging review, but was not boot-qualified. Actual Windows runtime INFO success later answered availability without another query-only boot. Do not describe the original failed qualification as firmware reporting unavailable.

The SCM protocol GUID is `77ed108d-8524-4b8b-9d2e-34987aecb9c1`; `16e48f1f-7944-4baa-bca5-2d0cb788a904` identifies its firmware file, not the protocol. A Boot Services DXE method/pointer is not a post-ExitBootServices Windows interface. The installed trusted-runtime provider lacked the expected bound firmware device/interface; forcing TPM/RPMB initialization or fabricating its PDO was not justified. The implemented direct fixed-profile kernel transport supersedes that availability blocker.

A resource-entry failure can leave secure counts/requests changed before returning16. A success/failure predicate must follow the real dispatcher, and a failed call must not be blindly retried. Normal completion, preserved raw status and applied-before-GMU timing still do not establish persistence at CP execution.

### Wi-Fi transport and backing

The corrected native QMI request timed out with-3 after the stall was already present. A source-pinned CPU capture showed its worker waiting with no active/pending copy operation, ruling out that observed copy/lock deadlock hypothesis; this did not establish command delivery. MHI channels20/21 belong to the QMI path. Endpoint2 credit loss uses the HIF/CE transmit/receive route (UL3/DL2); do not equate the channel families or infer a CE doorbell fault from a later QMI timeout.

The original image's PH20 comparison was narrowed to262 rows of40 bytes grouped into13 register descriptors.249 internal pointer deltas matched end-minus-start ranges; the mutated row+14 field is best supported as backing/copy-storage pointer data. The exact writer/direction/lifetime remains unknown. Do not call that bounded prefix code corruption, nor use it to exonerate every historical image difference. Several target functions lie in the loader's explicit pager span; a host image copy does not prove a current Q6 mapping, page fault or direct host-DDR execution.

GPIO83 was an early device-identification input. A copied runtime-low predicate incorrectly refused an initial hardware status reader before BAR access. The correction retained mux/input/EGPIO checks and made the input level observation-only. It was not a GPIO write or a firmware-ready signal. Preserve the actual access guards and avoid reinstating the unsupported low-level assumption.

## Input, power and preservation

Current touch integrates real bus/key cores, strict report handling, sustained HID delivery and clock-vote admission. Earlier fixes addressed completed-prefix/reread handling, a rejected packet, display timeout confusion, cold-start shared-clock handling and preservation through recovery. A frozen debugger can alter peripheral timing; do not repeatedly run physical touch campaigns that the operator already completed.

The latest touch link closure has23 translation units and local G100 dependencies. Its old `compile-driver.py` covers19 TUs and is not the complete linked build recipe. The key-report unit requires `G293_POWER_REPORTS=1`; preserve the actual compile configuration. Current parent746 is a seven-TU clock-only dependency. Older continuously sampling battery/sensor claims belong to previous parent variants and must not be treated as current.

Physical button testing was explicitly deferred. Charging/battery work was also deprioritized. Raw sensors, semantic models and bounded WinPE charge tests exist, but production Windows charging and a validated installed battery-class frontend do not. Do not infer charging from a connected powered hub or an unqualified gauge percentage. Do not start overlapping PMIC/GLINK/clock owners while investigating GPU or Wi-Fi.

## Recovery and evidence discipline

Offered-table Sahara recovery and one RESET7/ACK8 were demonstrated; always-unattended recovery was not. Old network debugger engines can retain stale GO state after a crash. Reconfirm the actual process/connection, target boot and controller; never reuse old kernel addresses or saved session tokens as authority. A tiny selected TZ dump from the latest failure was opaque/high-entropy. Earlier diagnostic sections were also opaque; no useful crash registers or cause were decoded. Do not keep collecting them or seek unrelated key regions as a substitute for an actionable diagnostic question.

Keep one live hardware operator. Other agents can research/build offline without touching the device. Stage and verify an exact payload before asking for physical fastboot, because this device leaves inactive fastboot quickly. Never automatically replay a timed-out native API/SMC, treat termination as rollback, or relax a guard merely to obtain a green result. Preserve uncertain ownership until a qualified recovery boundary.

Public source has privacy placeholders and excluded inputs. Historical host model/COFF/native-review results describe the private source closure tested then; they do not certify a bit-identical rebuild of this sanitized publication. Acquire inputs, configure paths/signing locally, regenerate manifests and validate the exact result before a future hardware attempt.

The [cache-only Wi-Fi result](../experiments/G1337-wifi-initialization-cache/README.md) and [G1335 runtime result](../experiments/G1335-low-physical-cp/BOOT170-RESULT.json) are the latest negative experiments. Next work focuses on Wi-Fi receive-ring visibility and GPU release/security ordering, rather than another timing or address variant.

The next [Wi-Fi cache-policy candidate](../experiments/G1338-wifi-common-buffer-cache/README.md)
is prepared offline: one allocator policy changes from cached to noncached, with
matching metadata/cleanup and exact compiled byte validation. Boot171 initialized it and verified the live changed opcode, but the response/credit stall remained; effective mapping attributes are unverified. Five historical Windows minidumps were also recovered; one symbolized
stack proves a debugger physical-read SEA, with matching address patterns in the
others. They do not explain Boot170's GPU release failure.

[G1339 first-fault capture](../experiments/G1339-first-fault-tuple/README.md)
adds a default-off broker record and one bounded debug line before existing fault
ACKs. Source tests and genuine-header ARM64 Clang checks pass, with default-off
object parity apart from timestamps. Native MSVC/link/signing and runtime tests
remain; it is diagnostic coverage, not a GPU execution fix.
