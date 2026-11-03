# G1345 — terminal QTB translation witness

Source-only, disabled by default. No hardware result, firmware image, signed driver or selected activation is provided. This couples an explicit GPU TCU interconnect request, one additional OS resource and a matched owner/broker operation. It is a diagnostic, not a GPU execution fix.

The earlier [zero-write control](../G1343-zero-write-control/HARDWARE-RESULT.md) returned without releasing SQE. This experiment asks whether hardware can translate the actual retained SQE mapping before engine start. It never writes SQE1, submits packets or continues to normal configuration.

## Source preparation

Run `python3 experiments/G1345/prepare.py --prepare --out /absolute/new/external/directory` from the checkout. Without `--prepare`, it is inert. Preparation reconstructs G1343, checks all changed-file preimages and installs the authored overlay. It performs no compilation or target operation. Existing file-specific notices remain; no OEM binary is included.

Both owner and broker require `OPEN_QTB_WITNESS=1`; the owner compiler exposes `--gpu-qtb-witness`. Keep the G1341 CB0 stall profile and G1335 low-physical/nonsecure/SECVID flags unchanged. Profile0 preserves ABI6 and six-range admission. Profile1 requires ABI7, exactly seven MMU memory descriptors and the original three interrupts. A mismatched pair refuses. The GPU owner's five resources and IORT remain unchanged.

Firmware keeps original `Mmu1.h` for profile0. Profile1 includes `QtbMmu1.h`, generated separately from `firmware/G991/QtbMmu1.asl` during a reviewed future build. It appends only `03de8000/1000`. The publisher performs the retained NPA request and publishes its receipt before committing the new resources. Failure prevents QTB grant publication through this path. No firmware build runs here. The publisher DEPEX now waits for exact retained NPA and ICB protocol GUIDs as well as ACPI. ICB initialization is called before ICB protocol installation; this improves dispatch ordering but does not guarantee resource registration succeeded. The actual arbiter availability check remains mandatory. The added protocol dependencies also apply to the disabled publisher code path.

## Retained power request

Existing pre-EBS NPA10003 selects `/icb/arbiter`, native provider pair196→0 (`alm_gpu_tcu`→`ebi`), vector-client type400, eight-byte pair and eight-word request `{4,0,1000000,0,0,0,0,0}`. Raw Ib units remain an accepted QTI-family inference, not an exact Linux1000kB/s claim. The source retains client/image until reset, including partial failure; no Complete/Delete or NPA call after EBS is added. Stock completion can block internally without a cancellable outer bound.

OWQT is an80-byte pre-EBS receipt with checksum, exact pair/request and inference marker. Expected fields are not electrical-on evidence or provider attestation. Root review must bind exact new firmware/provider inputs, actual tables and translated grant. Existing WLAN votes already include SH1; this does not claim SH1 was absent or missing bandwidth caused the fatal start.

## Native ownership and cleanup

The owner enters after actual GMU/HFI/OOB readiness and two SQE0 reads, before configuration. It supplies actual SQE Buffer[2] locked MDL and IOVA[2]. The broker validates existing GPU user/namespace authority, active table range/permissions, exact grant, firmware receipt and MDL PFN. It captures thread, namespace tag/token/generation, separate QTB/SMMU maps, table pool/root, remove/code references and held clock/client identities. It does not set Programming or relax baseline Current.

Normal transaction checking permits only original or owned masked SCTLR phase and rejects poison/revocation. Cleanup checks captured immutable identities, deliberately omitting poison, and permits only own Trigger0, original SCTLR and own HALT restoration. Actual STOP/removal, mapping or identity loss refuses further MMIO. The vendor shared fence/ACK protocol backpressures SID0..3ff including live GMU5; it does not require GMU fully stopped or prove a host mutex serializes secure firmware.

The core requests exactly SID0, coherent nonsecure privileged instruction read (`INFLD0=0`, `INFLD1=3408`) of the actual SQE IOVA. Halt and ECATS have separate local100us poll bounds plus finite iteration limits; synchronous bus faults cannot be guaranteed to return. There is no new fault ACK, RESUME, retry or address sweep. Evidence is saved before SCTLR restoration can invoke the existing capture-before-ACK ISR. No new explicit ACK therefore does not mean the ISR can never ACK.

Cleanup attempts Trigger0, original SCTLR, own HALT restoration and same-block synchronization, in that order. Ownership is recorded before writes. Independent restoration attempts continue after returned failure, without store retries or overwriting changed foreign bits. Failed cleanup overrides a match. Raw output uses exact vendor `out >> 12`, compared directly to MDL byte PA; no guessed PFN shift manufactures success. Raw CB0/global/CB2 FSRs are separate from filtered FSR excluding bit400.

Every result is terminal and retains hardware/code/table/MDL/clock resources. Existing namespace exit releases software exclusion after cleanup; active-owner failure paths prevent allocation destruction and clock disconnect. Captured callbacks are valid only during this synchronous operation and cannot run after namespace exit. The retained report is data only; entry refuses replay. No healthy GMU state or successful power-down is inferred.

## Evidence limits

A matching walk qualifies only this injected request's attributes and observed translation state. It does not prove real GPU attributes, instruction-data fetch or execution. Faults/timeouts remain diagnostic evidence; the vendor post-failure erratum makes a single failure potentially inconclusive.

See [VALIDATION.md](VALIDATION.md) and [CREDITS.md](CREDITS.md). Native link, independent compiled review, firmware build/table admission and any future activation remain separate review steps.
