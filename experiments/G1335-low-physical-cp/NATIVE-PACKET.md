# Explicit G1335 native input packet

`package_native.py` packages only the named G1335 candidate. It requires actual
candidate/default-off/source-copy/G1325-baseline directories and a fresh ZIP
outside the public repository. It verifies lowphysical1, lowSQE0, witness0,
SECVID1, GPUWC0 and nonsecure64. It verifies default-off source/compiler parity,
35 unique objects, the precise two-object candidate delta, actual G1325
baseline COFF correspondence, source-copy patch/base pins, object/source hashes,
and exact unchanged owner response/link-policy files. No SDK libraries are
included. It records the original SQE IOVA0x4000010000, allocation high0xffffffff,
unchanged GMU policy and activation_selected=false.

Example: `python3 package_native.py --build-dir /external/coff-v2-low-physical
--default-off-build /external/coff-v2-default-off --source-tree
/external/source-tree-v2 --baseline-build /external/G1325-coff-default-off
--out /external/G1335-native-inputs.zip`.

Root's private source-only native link script reuses the proven G1334 mechanics
with explicit G1335 archive/schema/setting checks, fresh G1335 input/output
directories, the same hash-pinned MSVC linker and five external ARM64 libraries,
and exact existing ARM64/native/DriverEntry/no-default-library link policy.
It hashes every manifest input before linking and saves the unsigned SYS, map
and raw link log. Existing input/output paths cause refusal; failure is never
authority to replay. No signing, driver staging, loading or activation is part
of that script. Native link itself remains pending root selection.
