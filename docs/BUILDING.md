# Build and publication boundaries

This publication contains source and research interfaces, not the private lab environment or a verified installation bundle. Historical source is preserved for investigation; some old recipes require adaptation. Read SOURCE_MAP.md to choose a current source closure.

## Required external inputs

- An ARM64-capable C/C++ toolchain and, for Windows kernel builds, locally installed Microsoft SDK/WDK/MSVC tools. Keep Microsoft libraries and installation packages outside this repository.
- Python and Go for the relevant source builders, decoders and portable models; consult each component's imports and recipe.
- The pinned Project Mu/Project-Aloha, Linux/OnePlus, UniXNU/NativeAdreno and Mesa dependencies identified in CREDITS.md and local source notices.
- Independently obtained stock firmware/driver inputs for your exact device. Extract locally; do not commit the results.
- Your own development signing configuration. No published certificate or signature authorizes this snapshot on a device.

## Deliberate exclusions

Private machine-control agents, live activation capsules, raw logs, transcripts, GPT/BCD sector captures, memory dumps, saved sessions, network profiles, signing bundles and generated binaries are excluded. Historical hashes can describe unavailable inputs and do not authenticate redacted source. Rebuild and generate fresh local manifests; do not interpret a historical verifier as proof about this export.

Device-specific boot repair data must be generated locally. The captured-data header is replaced with a compile-stopping placeholder. Never replace it with somebody else's disk/partition identifiers or boot sectors.

Public paths and identifiers are placeholders. Hardware MMIO constants and protocol definitions are intentionally retained; placeholder operator identities and documentation network addresses are not live configuration. Review every helper and create fresh, explicit device-local authority before any hardware operation. Reading the handoff does not authorize an experiment.
