# Agent handoff — publication pause

Status date: **2026-11-02**. This is a source/research handoff, not a live-device authorization or an installation recipe. Development was paused at the owner's request. Leave the phone powered on; do not shut it down or resume experiments merely because this file describes them. Recover fresh authority and liveness when the operator explicitly resumes the project.

## Read first

1. README.md and STATUS.md distinguish demonstrated features from prototypes.
2. SOURCE_MAP.md identifies current source closures. Most numbered experiments are historical.
3. CREDITS.md and file-specific notices describe dependencies and licensing.
4. BUILDING.md explains missing external inputs, privacy placeholders and build limitations.

The former private repository's old leading README described a much earlier sensor/touch checkpoint. Its live-state paragraphs are superseded. This public repository has a new publication history; private transcripts, job databases, snapshots, signed capsules and captured binaries are intentionally absent. A private operator may possess additional evidence. Do not fabricate their contents or treat a source identifier as a currently loaded image.

## Closing physical/control state

The last normal Windows experiment used the G1287 GPU owner. Its fixed NORMAL secure-aperture call returned successfully once, GMU/HFI and later CP setup proceeded, and the phone then entered Qualcomm 900E at the first SQE-start write-call boundary. A Sahara RESET request received its ACK, and the USB-EEM network interface subsequently reappeared. Fresh WinPE/Windows control had **not** been confirmed when publication work took over. The debugger's old GO status and old log are not proof of a new kernel connection.

The experimental driver's future startup/once flags may still be armed. Before any later normal-Windows boot, the operator must verify recovery control and offline-fence the actual Windows SYSTEM control sets: `OpenGpuStart` Start4, BootstrapOnce0, CpInitFenceOnce0 and ScmApertureOnce0; `OpenSmmuD0` Start4. Do not mount the wrong hive or equate a successful emergency reset with completed fencing. This is pending recovery work, not permission to perform it during the pause.

Preserve the installed Windows system, working native touch, desktop scaling, development test-signing configuration, black cover framebuffer, Never sleep/display settings and WinPE recovery default. Do not enable charging, change clocks or run overlapping hardware owners as incidental preparation.

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

The last `STORE_CALL_BEGIN` marker precedes the call to the GPU MMIO helper. That helper validates access, issues a pre-store DSB, executes the volatile STR and then a post-store DSB. No returned marker establishes which instruction completed. Do not call this a proven instruction fetch, retired CPU store or completed command. `CP_SQE_CNTL=1` is the start encoding in the reviewed Gen7/mainline/UniXNU sequences; warm halt uses3. The logged AHB fence value0 is different from `CP_AHB_CNTL`, whose readback was1.

The next bounded GPU discriminators are:

1. Determine the instruction/exception boundary around the real helper's barriers and STR using a fresh loaded image/base. Do not repeat earlier CPU-only table inspection as if it answers retirement.
2. Evaluate one VA-layout experiment. All four current private BO IOVAs—f0000000, f0008000, f0010000 and f0030000—fall in KGSL's software-reserved32-bit secure VA range. A source-qualified private nonsecure64 layout beginning4000000000 can fit the existing lower39-bit profile while preserving physical pages, permissions and ownership. This is a proposed discriminator, not proof that this hardware classified the old VA as secure. Validate high address words, table walks and command fields before selecting any variant.

Do not batch the VA experiment with unrelated changes. Four SECVID/TSB zero stores are present in comparison sources while the current path only reads/qualifies zeros; that separate parity gap is not proof a write strobe is necessary. ZAP/PAS initialization follows SQE start/CP initialization in the reviewed applicable branches, so a pre-start PAS change is not justified by those sources. Do not introduce an arbitrary FAST setter, shared TBU, guessed ACTLR value, firmware/BDF byte patch or raw unowned aperture mapping.

### WDDM distance

The first CP completion is still a prerequisite. WDDM/Mesa work includes compiled prototypes, a built ARM64 D3D10 UMD and owned-BO/submit/authorization scaffolding; none establishes a functioning A740 accelerated adapter. Reliable submission, completion interrupts/fences, memory residency/lifetime, reset/recovery, scheduling/DDIs, userspace compatibility and presentation still require integration and real hardware validation. The Topaz donor's A610 backend must not be presented as A740 support.

## Wi-Fi: what is and is not established

The original Qualcomm Windows driver reaches firmware/HTC startup and initial exchanges. Earlier experiments received AP beacons. Later response/credit activity stops; stable association, DHCP and traffic are unproven. A successful native initialization API, scan notification or queued connect request is not connectivity.

The latest coherent host log shows the last endpoint2 credit/receive activity before background HT SET_IE processing. The26-byte HT IE fits the target's31-byte limit. The mapped target wrapper takes a copy-shaped path; no command-buffer free/credit producer has been proved there. Do not truncate that valid IE or inject credits based on this observation.

Investigations already completed and not worth blindly repeating:

- Actual root/endpoint D0, linkL0 and ASPM/CLKPM/L1SS enable bits off in the observed state.
- A historical CE2 hardware/software index comparison matched, without a demonstrated unreaped receive backlog.
- Source-backed host credit-request intent is present.
- The corrected native QMI read was attempted after the transport had stalled and timed out; its zero buffer is invalid data, not a memory observation. Do not replay that request into a known stalled transport.

An unforced post-stall status read found normal MHI state/EE and no SYSERR, alongside BHI debug values CAFECACE / CAFECACE /014feeab /496. In the original initialized firmware image,014feeab is exactly the string `cmnos_thread_patch.c`; candidate packed metadata also contains496 and that filename pointer. The middle candidate value01414020 has no initialized/BSS backing in the supplied ELF. The writer, record format, timing and causal connection to credit loss remain unknown. Do not promote this correspondence to an executed assertion at a known source line, label unmapped data ROM, or import semantics from the different CAFECAFE marker.

The original host error predicate looks at MHI SYSERR and BHI transfer-status bits; it does not inspect these error/debug fields. Therefore normal host error detection does not resolve the tuple. The old fallback consumer copies raw typed data and does not establish assertion semantics or an epoch.

The G1295 phase-aware reader is prepared for the next otherwise-required fresh normal boot: one qualified pre-HOST-init baseline and one post-stall observation around one original initialization/scan. It must not run its pre-init phase in the already-consumed epoch. It uses explicit action counts, current resource/image evidence and distinct per-phase markers; pre-init evidence must not contain a fabricated future failure hash. If access/power/memory-decode guards fail, refuse the baseline. An already-present tuple weakens a newly-created-stall interpretation; a new tuple bounds assignment to the interval, not the exact SET_IE instruction. Do not create a standalone reboot merely to repeat these reads during the pause.

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
