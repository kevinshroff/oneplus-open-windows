# G1334: SQE-only 1 MiB IOVA discriminator

Default-off source option `OGO_GPU_SQE_LOW_IOVA=1` moves only the 19-page SQE
microcode BO to `0x00100000`. The selected candidate retains nonsecure64
ring `0x4000000000`, shadow `0x4000008000`, and power-up `0x4000030000`.
SQE backing, firmware bytes, permissions, SID0/CB0/ASID0, lower39/36-bit
translation, NC mappings, aperture/trusted-firmware ordering and ownership
checks are unchanged. The existing normal release/CP-init/fence sequence runs;
the G1325 intentional pre-release witness is off. No completion is fabricated.

This is a fetch-address discriminator, not an established hardware fix.
[The inspected reference](https://github.com/UniXNU/Adreno740/commit/1030485546ef7ebb9abbfb7c17fbca93cca40971)
uses `GpuSqeIova=0x100000` in `NativeAdrenoGpuContext.h` and places its fixed CP
buffers below the 16 MiB GMEM window. Its startup files are unchanged from the
previously inspected pin. This selects a concrete low address without changing
trusted-firmware calls, streams, privilege or cache policy. The architectural
39-bit input range alone does not establish that the previous high SQE address
caused the recurring fatal first release. G1325's exact CPU graph and SQE-byte
checks passed; they did not prove GPU fetch visibility.

A bounded search of 1,297 existing JSON/text/Markdown files in the owned recent
trial evidence found no recorded consumed 1 MiB SQE address. The inspected
baseline and nonsecure64 trials used `0xf0010000` and `0x4000010000` respectively.
This is not a claim about every external or unrecorded trial.

The existing `OsmiBuildInactive` sorts the four inputs before extracting MDL
PFNs and calculates table storage dynamically. Low SQE requires five table
pages (root plus two L2 and two L3), with the same 29 leaves. No allocator,
MDL-validation, retained-lifetime, admission or runtime guard is relaxed.

## Offline validation

Run `python3 experiments/G1334-low-sqe-iova/test.py --out /external/results`.
ASan/UBSan exercise both old layouts with low SQE off/on. The actual table
builder/auditor and an independent walker check all 29 scattered physical
mappings, all unused entries, the unmapped old SQE address, insufficient storage
without mutation, raw-unsorted-input rejection, and graph/permission corruption.
The existing CP model passes 21 cases per combination, including real-fence
requirements and failure paths; its modeled completion is not hardware evidence.
Both selectors reject values other than zero/one at compile time.

Compile with the existing G1311 35-object compiler and real external Microsoft
headers, adding `--layout nonsecure64 --secvid-zero-stores --sqe-low-iova`.
Omit `--gpu-mmio-writecombine` and `--pre-release-witness`. Compile a second
identical command without `--sqe-low-iova` into a separate fresh directory.
The reviewed default-off build matches all 35 G1325 default-off COFF hashes;
the low-SQE build changes only `43_gpu_cp_native.obj`.

Package with `package_native.py --build-dir /external/low --default-off-build
/external/default --out /external/G1334-native-inputs.zip`. The packager checks
exact settings, source/object hashes and the one-object comparison, then includes
the default-off compile receipt. Existing G1318/G1322/G1325 packagers explicitly
reject the new selector so their profile names cannot silently classify this
candidate. SDK libraries remain external; link policy is the existing owner
policy. No native link, signing, staging, driver load or hardware test was
performed for this experiment during preparation. GPU acceleration remains
unproved and the WDDM provider remains closed.

The next decisive result is an authenticated first CP fetch/fence from the
existing admitted normal CP sequence. Another fatal release would reject this
isolated low-address candidate; a CPU map pass alone cannot accept it.
