# G1325: pre-release witness completed without starting SQE

One normal-Windows activation of the reviewed, signed G1325 owner completed
the intended diagnostic stop. Both native broker and owner PnP calls returned,
Windows remained available, and no SQE release was attempted. This is a
successful witness experiment, not GPU command completion or acceleration.

The receipt reports `result=0`, `GX=0`, `AHB=0`, both complete
25-item validity masks, no configuration mismatches or instability, and no
fault under the selected predicate. Both passes read identical values for all 25 items. The
CPU backing comparison checked all 77,824 bytes with no mismatch against the
retained previously pinned SQE input after its four-byte removal and zero tail;
each SQE CPU page also matched its locked-MDL PFN.

The raw context fault-status register was **0x400**, the admitted AArch64 format
value, rather than literal zero. Raw FAR and some syndrome registers were
nonzero. These values are preserved in private evidence. They are not attributed
to an active GPU fault because the sampled status did not indicate one under
the selected predicate. The result does not establish an absence of historical
faults or exclude a concurrent IRQ/status-ACK race.

The original release callback returned STATUS_NOT_SUPPORTED with `attempt=0`.
The existing CP wrapper then reported its generic failure, zero issued/completed
commands and zero first-use attempts. The retained owner subsequently had PnP problem 10, as expected
for that intentional failure path. Owner and broker remained loaded/running;
their future startup was fenced at Start 4 and owner once options 0. Registry
fencing does not retire their loaded ownership or authorize a restart.

## What this establishes

On this activation, the measured CB0 configuration/root and selected route and
namespace state survived power acquisition and setup through the pre-release
point. The measured registers were stable across two passes. The CPU-visible
SQE copy, tail and page/MDL correspondence matched. Setup before the refused
release completed without the fatal behavior seen in earlier start attempts.

It does **not** establish that the GPU can fetch that SQE, that the SMMU walks
the intended descriptors, that the published page-table graph remained intact,
or that GPU security attributes/firewall permissions match those required for
the fetch. It does not establish secure-aperture persistence, firmware
compatibility, a post-release fault PC or instruction retirement. The CPU
readbacks cannot resolve those device-side questions.

The next useful discriminator is the actual retained GPU page-table graph
against the observed root and independently captured locked-MDL PFNs. A bounded
CPU-memory capture of already retained objects can provide that evidence
without another SQE release. It must use freshly qualified object locations
and preserve retained ownership. An intact CPU graph would still leave actual
SMMU fetch/security/visibility unproved. No new activation is authorized here.

## Build and evidence boundary

Subsequent real 35-object ARM64 COFF qualification found every default-off
object identical to the prior G1318 build; enabling G1325 changed only
43_gpu_cp_native.obj. The selected owner was then linked with native MSVC,
compiled-reviewed, signed-content-reviewed and selected for the activation
above. This supersedes the implementation proposal's earlier "native build not
run" checkpoint; it does not turn scalar tests into GPU execution evidence.

Captured runtime pointers, fault-address values, device/session identities,
firmware bytes and operator infrastructure are intentionally absent here.
