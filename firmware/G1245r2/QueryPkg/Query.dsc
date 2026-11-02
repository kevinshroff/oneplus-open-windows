[Defines]
 PLATFORM_NAME = OpenScmQueryG1245
 PLATFORM_GUID = f88e8458-a238-4c1c-b1d0-d3583b4d1245
 PLATFORM_VERSION = 1.0
 DSC_SPECIFICATION = 0x0001001C
 OUTPUT_DIRECTORY = Build/OpenScmQueryG1245
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
 QueryPkg/Query.inf
