# Credits, adaptation and provenance

This port combines original board-support/driver work with existing operating-system, firmware and open-source foundations. Credit here describes what was reused; it does not claim that every upstream component runs on this phone or that upstream authors support this port.

| Foundation | How it was used | Licensing boundary |
|---|---|---|
| [OnePlusOSS SM8550 kernel](https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550), Oplus and Qualcomm/Linux contributors | Device-tree resources, Goodix protocol, GENI/RPMh/SPMI, GPUCC/KGSL/GMU/SMMU and WLAN references guided Windows-specific implementation and hardware sequencing. | Individual SPDX/copyright notices apply, including GPL-2.0-only references. |
| [Linux DRM/MSM and MHI](https://github.com/torvalds/linux) | Independent Adreno startup and Qualcomm SCM/MHI semantics, register definitions and transport/error handling references. | Keep the exact source's GPL/BSD or dual-license notices. |
| [UniXNU](https://github.com/UniXNU/UniXNU), NativeAdreno and related SM8550 work | Adapted firmware/HFI/PM4/SMMU components and compared working Adreno 740 sequencing. Windows resource ownership, lifetime, DMA and driver interfaces required separate integration. | NativeAdreno/ArmSmmu4K/AdrenoPM4 MIT notices and AdrenoFirmware BSD-2-Clause-Patent notices are retained beside the code. |
| [Project-Aloha](https://github.com/Project-Aloha/mu_aloha_platforms), [Microsoft Project Mu](https://github.com/microsoft/mu_basecore), [TianoCore EDK II](https://github.com/tianocore/edk2) | Foundation/tooling for authored standalone DXE and ACPI overlays, rather than a claim that the entire OEM firmware was rebuilt. | Module-specific BSD and BSD-2-Clause-Patent notices apply. OEM firmware inputs are excluded. |
| [Mesa / Freedreno](https://gitlab.freedesktop.org/mesa/mesa) | ARM64 userspace graphics build/integration work and graphics interfaces. A built DLL is not a working accelerated adapter. | Mesa has component-specific licenses; retain its source notices and license documentation. |
| [MakrSas/topaz-woa](https://github.com/MakrSas/topaz-woa) | Donor WDDM/UMD integration and porting references. Its A610 hardware assumptions require adaptation for A740. | Upstream component licenses remain separate. Topaz's working peripherals are not evidence that those peripherals work here. |
| Microsoft Windows ARM64, SDK/WDK/MSVC, WinDbg | Existing CPU/storage/USB operating-system stacks, driver-development interfaces, linking/catalog tooling and kernel debugging. | External proprietary dependencies; no Windows binaries, SDK/WDK libraries or installation media are distributed. |
| LLVM/Clang/lld, Go, Python, Meson/Ninja and reverse-engineering tooling including REA | Cross-compilation, source builders, decoders, models and compiled-code investigation. | External tools; their installation trees and caches are excluded. |

## What was developed for this device

Project work includes device-specific firmware/ACPI overlays, native touch acquisition/reporting and HID integration, cold-start/shared-clock handling, cover-framebuffer blanking, storage/boot recovery fixes, kernel resource/interrupt/lifetime ownership and experimental GPU/WLAN diagnostics. GPU work adapts upstream firmware/HFI/PM4 concepts while supplying Windows-specific ownership and memory plumbing. It is incomplete and should not be attributed wholesale to either this project or any single donor.

## Source pins

The DXE build closure used Project-Aloha `mu_aloha_platforms` at `68ae12fafdcd873240d8635afecac542c2c4c563`. Its exact submodule pins are in [UPSTREAM_PINS.json](UPSTREAM_PINS.json); fetch them recursively rather than substituting arbitrary current heads. The retained Goodix protocol provenance identifies OnePlus commit `46cfd06fc4c0e12dbe294badb924a533f1d9fb06`. The Mesa integration reference used commit `62f1e49a1eb3a408f748725326fe53447887f97d`; the Adreno 740 comparison reference used `a9a2cbb43b89d672e2921e19721a6438b738b17f`. These pins belong to their specific components, not every file in the repository.

Historical reference-only Topaz UI trees are not shipped wholesale. If importing them later, retain their Mu-Silicium/Project Silicium, BootGraphicsLib and NTDEV/exynos9810-woa credits and any applicable MS-PL, BSD-2-Clause-Patent or SIL OFL font notices. Nothing here grants redistribution rights for Qualcomm/OEM firmware or vendor Windows drivers.
