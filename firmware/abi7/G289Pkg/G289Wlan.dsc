[Defines]
 PLATFORM_NAME = G289WlanStandalone
 PLATFORM_GUID = c8430289-8486-4d09-b26f-ce2c7f30d29f
 PLATFORM_VERSION = 289.1
 DSC_SPECIFICATION = 0x0001001C
 OUTPUT_DIRECTORY = Build/G289Wlan
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
 ArmGenericTimerCounterLib|ArmPkg/Library/ArmGenericTimerPhyCounterLib/ArmGenericTimerPhyCounterLib.inf
 TimerLib|ArmPkg/Library/ArmArchTimerLib/ArmArchTimerLib.inf
 IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
[PcdsFixedAtBuild]
 gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x00
[Components]
 G289Pkg/Wlan/G289Wlan.inf
