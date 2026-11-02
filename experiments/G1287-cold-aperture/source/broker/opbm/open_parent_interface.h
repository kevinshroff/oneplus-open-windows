/* Project kernel-only ABI, not a Qualcomm/Windows stock interface. */
#ifndef OPEN_PARENT_INTERFACE_H
#define OPEN_PARENT_INTERFACE_H
#include <ntddk.h>
static const GUID OpenParentQueryGuid={0x774f0d01,0xe218,0x4af0,{0x96,0x16,0x4b,0x24,0x81,0x52,0x00,0x18}};
static const GUID OpenOpbmDeviceGuid={0x8fa58184,0xfd04,0x4f21,{0x9f,0x08,0xa3,0x04,0xc1,0xbd,0x01,0x84}};
#define OPEN_PARENT_VERSION 1
#define OPEN_PARENT_MAGIC 0x3151504fUL
typedef struct {
 ULONG Size,Version,Magic,Reserved;ULONGLONG Instance,PrepareEpoch,D0Epoch,At100ns;
 ULONG ExternalVote,ApVote;NTSTATUS Status;
} OPEN_PARENT_SNAPSHOT;
typedef NTSTATUS (*OPEN_PARENT_READ)(PVOID,OPEN_PARENT_SNAPSHOT*);
typedef struct {
 INTERFACE Interface;PDEVICE_OBJECT ProviderPdo;ULONGLONG PhysicalBase;ULONG Bytes,ReadOnly;
 OPEN_PARENT_READ ReadCurrent;
} OPEN_PARENT_INTERFACE;
#endif
