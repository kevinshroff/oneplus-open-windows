[PcdsFixedAtBuild.common]
gAndromedaPkgTokenSpaceGuid.PcdOpenBringupMode|16
gAndromedaPkgTokenSpaceGuid.PcdMipiFrameBufferWidth|2440
gAndromedaPkgTokenSpaceGuid.PcdMipiFrameBufferHeight|2268

# Smbios Info
gAndromedaPkgTokenSpaceGuid.PcdSmbiosSystemBrand|"Oneplus"
gAndromedaPkgTokenSpaceGuid.PcdSmbiosSystemModel|"Open"
gAndromedaPkgTokenSpaceGuid.PcdSmbiosSystemRetailModel|"CPH2551"
gAndromedaPkgTokenSpaceGuid.PcdSmbiosSystemRetailSku|"1"
gAndromedaPkgTokenSpaceGuid.PcdABLProduct|"Oneplus Open"

# Display Caller
gAndromedaPkgTokenSpaceGuid.PcdDisplayCallerExitDisableDisplay|FALSE
gAndromedaPkgTokenSpaceGuid.PcdDisplayCallerStallBeforeEnable|2000

[PcdsDynamicDefault.common]
gEfiMdeModulePkgTokenSpaceGuid.PcdVideoHorizontalResolution|2440
gEfiMdeModulePkgTokenSpaceGuid.PcdVideoVerticalResolution|2268
gEfiMdeModulePkgTokenSpaceGuid.PcdSetupVideoHorizontalResolution|2440
gEfiMdeModulePkgTokenSpaceGuid.PcdSetupVideoVerticalResolution|2268
gEfiMdeModulePkgTokenSpaceGuid.PcdSetupConOutColumn|305     # = 2440 / EFI_GLYPH_WIDTH(8)
gEfiMdeModulePkgTokenSpaceGuid.PcdSetupConOutRow|119        # = 2268 / EFI_GLYPH_HEIGHT(19)
gEfiMdeModulePkgTokenSpaceGuid.PcdConOutColumn|305          # = 2440 / EFI_GLYPH_WIDTH(8)
gEfiMdeModulePkgTokenSpaceGuid.PcdConOutRow|119             # = 2268 / EFI_GLYPH_HEIGHT(19)
