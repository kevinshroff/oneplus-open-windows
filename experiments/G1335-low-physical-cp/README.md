# G1335: default-off low physical allocation candidate

This is an unselected source candidate after G1334's negative low-SQE trial.
It tests physical placement independently of GPU virtual placement. It does
not assert a hardware4GiB limit, a security-window fix or GPU fetch success.
The [candidate is now signed and selected while disabled](SIGNED-DISABLED-RESULT.json).
No GPU driver load, live GPU trial or allocation inventory was performed.

The authoritative G1287/G1311 closure remains unchanged. `source.patch`,
`ogo_gpu_allocation.h` and `prepare.py` produce a fresh external copy after
checking BASE-PINS.json. The diff changes only CP BO allocation/validation,
CP-specific inactive table allocation/validation, and the compiler's explicit selector.
`OGO_GPU_LOW_PHYSICAL` defaults0 and accepts only0/1. Explicit1 sets the
exclusive allocation limit to1<<32 and highest physical address0xffffffff.
All four existing GPU BO MDL allocations and the contiguous table pool use
that bound. Every returned MDL PFN and the pool's complete physical interval
are checked. NULL/insufficient storage fails through existing pre-publication
CP paths before CP table publication; no higher-memory fallback or reserved-memory selection is introduced.

IOVAs, configured OAS36/input39, table descriptors and permissions, cache
policy, streams, firmware, trusted ordering, first-use admission, CP release,
real-fence checks and retained ownership remain unchanged. Candidate settings
retain G1325's original nonsecure64 IOVAs, SECVID1, GPUWC0 and witness0.
Low-SQE IOVA is OFF: SQE remains0x4000010000. The original generic
OsmiBuildInactive API remains36-bit for GMU/bootstrap. Only the CP call uses
OsmiBuildInactiveGpu; default-off aliases the original function. No firmware
or GMU BO allocation changes.
The two allocation caps are one physical-placement factor; a successful future
result would not distinguish table-walk placement from BO placement.

## Memory precheck and limits

The retained public platform map includes conventional DXE heap memory
0xBAB00000..0xC7CC0000 (209.75MiB), below4GiB. Historical native OAPF captures
also report PHIT memory_bottom BAB00000/free_bottom BAB018F8. These establish
a low RAM source/firmware range, not current Windows free/allocatable pages.
No current Windows physical-memory inventory was retained. Root explicitly
authorized a fail-closed source candidate on that basis, without a new live
inventory. Windows allocation may return NULL; that is a bounded refusal,
not permission to change firmware reservations or borrow another owner's RAM.

Boot166's captured29 BO pages and three table pages were above4GiB. G1334's
actual physical pages are unknown. The inspected NativeAdreno reference itself
allocates BO/table backing using ID2-derived output widths up to40bits, so it
does not establish a32-bit requirement. See the private postfailure source
review for pinned evidence and the opaque Sahara-diagnostic limitation.

## Offline build and verification

1. `python3 experiments/G1335-low-physical-cp/prepare.py --out /external/source-tree`
2. `python3 experiments/G1335-low-physical-cp/test.py --source-tree /external/source-tree --out /external/tests`
3. Invoke `/external/source-tree/experiments/G1311-gpu-nonsecure-va/compile_owner.py`
   with Clang ARM64-COFF support, the five real Microsoft include roots,
   `--layout nonsecure64 --secvid-zero-stores`, and a fresh
   output outside source-tree. Add `--gpu-low-physical` only for the candidate.
   Omit low-SQE, WC and pre-release-witness flags.

The actual inactive allocator, real table builder/auditor and a bounded CPU
allocation shim pass nine boundary cases with the option off and on under
ASan/UBSan. Checks include last valid PFN, first invalid PFN, huge PFN,
pool ending exactly at the limit, pool crossing/starting at the limit,
misaligned pool, allocator NULL and the precise4GiB PFN boundary. Rejected
allocations retain no published root; cleanup balances allocations. This is a
CPU model of allocation outcomes, not a Windows ABI/runtime result. An additional actual-source test keeps the original generic/GMU API
accepting a high PFN/high table pool even with the GPU-low option enabled.
Both invalid selector values fail preprocessing.

Both complete35-object ARM64 COFF compiles pass with real Microsoft headers.
Default-off matches all35 G1325 original-layout/witness0 COFF hashes; explicit low physical changes
only11_open_smmu_inactive.obj and43_gpu_cp_native.obj. Configured OAS remains36
in the actual allocator test. The exact35-object candidate also [linked with native MSVC](NATIVE-LINK-RESULT.json)
to an unsigned ARM64 PE. A bounded compiled review confirmed the CP allocation
bounds, unchanged generic GMU limit, original SQE IOVA and normal release/fence
paths. It was subsequently signed with the existing project certificate and selected
with Start4, Stopped and all once flags zero. Independent PE/CMS/RSA checks
verified the original payload is unchanged. No trust-store change or GPU
activation occurred; actual allocation availability, fetch and fences remain
untested.

The existing G1334 native packager/profile must not be used to classify this
new candidate. Any future packet needs an explicitly named profile and its
own review; none is generated or activation-selected here.
