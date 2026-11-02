/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G55_PROTOCOL_H
#define OPEN_G55_PROTOCOL_H
#define G55_MAGIC 0x314448353547504fULL
#define G55_ABI 1u
#define G55_IOCTL_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,FILE_READ_ACCESS)
#define G55_IOCTL_REPLAY CTL_CODE(FILE_DEVICE_UNKNOWN,0x901,METHOD_BUFFERED,FILE_READ_ACCESS|FILE_WRITE_ACCESS)
static const GUID G55Interface={0x5f9cc9b4,0xb53a,0x4ec2,{0xa8,0x79,0xb5,0x8e,0xfe,0xdf,0x00,0x55}};
typedef struct {ULONG Size,Version;ULONGLONG Magic;} G55_REQUEST;
typedef struct {
 ULONG Size,Version;ULONGLONG Magic;
 ULONG KernelBuild,Processors,Irql,FirmwareBytes,FirmwareMatch,D0,Started,CreateStatus,StartStatus,Entries,Exits,Features,ReplayAttempts,ReplayAccepted,LastSubmit,MaxContacts,MaxX,MaxY,ReportBytes,DescriptorBytes,MappingQualified;
 ULONGLONG Sequence;UCHAR BuildId[16];
 ULONG ReplayComplete,ReplayError,CleanupAttempted,CleanupAccepted,AcceptedMask,AcceptedGeneration,ReplaySubmitted,Reserved;
} G55_STATUS;
C_ASSERT(sizeof(G55_REQUEST)==16);
C_ASSERT(sizeof(G55_STATUS)==160);
C_ASSERT(FIELD_OFFSET(G55_STATUS,Sequence)==104);
C_ASSERT(FIELD_OFFSET(G55_STATUS,BuildId)==112);
#endif
