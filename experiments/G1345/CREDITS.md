# Sources and notices

The authored overlay preserves the baseline files' individual notices. It adds no blanket license over upstream or OEM material.

The request encoding, QTB fence/ACK, register widths, output extraction and ordering were reviewed against OnePlus's published [Qualcomm SMMUv500 implementation](https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550/blob/c87f74901db572a762241d6dfcacc42dbdd9f798/drivers/iommu/arm/arm-smmu/arm-smmu-qcom.c) and [power implementation](https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550/blob/c87f74901db572a762241d6dfcacc42dbdd9f798/drivers/iommu/arm/arm-smmu/arm-smmu-qcom-pm.c). The upstream kernel files are reference evidence, not compiled or copied into this overlay. [PRIMARY-PINS.json](PRIMARY-PINS.json) records exact reviewed source hashes and the chip-matched Kalama device-tree identity.

The firmware adapter reuses the project's [G289 NPA ABI](../../firmware/abi7/G289Pkg/Wlan/g289_boot_votes.h), including its corrected function offsets and retained-client policy. Exact provider route196→0 was established from retained artifacts; those artifacts and compiled analysis databases are not distributed here. Raw request units remain the documented family inference.

The existing GPU owner/broker foundation credits Linux/Qualcomm/OnePlus and UniXNU/NativeAdreno work in the baseline source tree and project credits. This experiment changes neither firmware payloads nor the existing translation descriptor implementation.
