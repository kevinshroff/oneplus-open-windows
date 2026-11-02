[Defines]
 PLATFORM_NAME = G203CoverStandalone
 PLATFORM_GUID = 8a35ae20-16df-4530-9492-1636f424102f
 PLATFORM_VERSION = 203.1
 DSC_SPECIFICATION = 0x0001001C
 OUTPUT_DIRECTORY = Build/G203Cover
 SUPPORTED_ARCHITECTURES = AARCH64
 BUILD_TARGETS = DEBUG|RELEASE|NOOPT
 SKUID_IDENTIFIER = DEFAULT
[LibraryClasses]
 UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
 UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
 UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
 DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
 BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
 BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
 DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
 PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
 PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
 MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
 UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
 DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
 StackCheckLib|MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf
 RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
 CompilerIntrinsicsLib|MdePkg/Library/CompilerIntrinsicsLib/CompilerIntrinsicsLib.inf
 ArmLib|ArmPkg/Library/ArmLib/ArmBaseLib.inf
 PlatformMemoryMapLib|G203Pkg/MemoryMap/PlatformMemoryMapLib.inf
[PcdsFixedAtBuild]
 gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x00
[Components]
 G203Pkg/CoverHandoff/CoverHandoffG203.inf
