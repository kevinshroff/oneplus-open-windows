/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G51_PROTOCOL_H
#define OPEN_G51_PROTOCOL_H
#define G51_MAGIC 0x314448313547504fULL
#define G51_ABI 1u
#define G51_IOCTL_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,FILE_READ_ACCESS)
#define G51_IOCTL_EMPTY CTL_CODE(FILE_DEVICE_UNKNOWN,0x901,METHOD_BUFFERED,FILE_READ_ACCESS|FILE_WRITE_ACCESS)
static const GUID G51Interface={0x936ac5d4,0xb53a,0x4ec2,{0xa8,0x79,0xb5,0x8e,0xfe,0xdf,0x00,0x0e}};
typedef struct {ULONG Size,Version;ULONGLONG Magic;} G51_REQUEST;
typedef struct {
 ULONG Size,Version;ULONGLONG Magic;
 ULONG KernelBuild,Processors,Irql,FirmwareBytes,FirmwareMatch,D0,Started,CreateStatus,StartStatus,Entries,Exits,Features,EmptyAttempts,EmptyAccepted,LastSubmit,MaxContacts,MaxX,MaxY,ReportBytes,DescriptorBytes,MappingQualified;
 ULONGLONG Sequence;UCHAR BuildId[16];
} G51_STATUS;
C_ASSERT(sizeof(G51_REQUEST)==16);
C_ASSERT(sizeof(G51_STATUS)==128);
C_ASSERT(FIELD_OFFSET(G51_STATUS,Sequence)==104);
C_ASSERT(FIELD_OFFSET(G51_STATUS,BuildId)==112);
#endif
