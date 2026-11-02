/* SPDX-License-Identifier: MIT */
#ifndef OPEN_G56HID_PROTOCOL_H
#define OPEN_G56HID_PROTOCOL_H
#define G56HID_MAGIC 0x314448363547504fULL
#define G56HID_ABI 1u
#define G56HID_IOCTL_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN,0x900,METHOD_BUFFERED,FILE_READ_ACCESS)
static const GUID G56HIDInterface={0x5f9cc9b6,0xb53a,0x4ec2,{0xa8,0x79,0xb5,0x8e,0xfe,0xdf,0x00,0x56}};
typedef struct {ULONG Size,Version;ULONGLONG Magic;} G56HID_REQUEST;
typedef struct {
 ULONG Size,Version;ULONGLONG Magic;
 ULONG KernelBuild,Processors,Irql,FirmwareBytes,FirmwareMatch,D0,Started,CreateStatus,StartStatus,Entries,Exits,Features,LiveAttempts,ReportsAccepted,LastSubmit,MaxContacts,MaxX,MaxY,ReportBytes,DescriptorBytes,MappingQualified;
 ULONGLONG Sequence;UCHAR BuildId[16];
 ULONG LiveComplete,LiveError,StopAttempts,StopAccepted,AcceptedMask,AcceptedGeneration,ReportsSubmitted,Reserved;
} G56HID_STATUS;
C_ASSERT(sizeof(G56HID_REQUEST)==16);
C_ASSERT(sizeof(G56HID_STATUS)==160);
C_ASSERT(FIELD_OFFSET(G56HID_STATUS,Sequence)==104);
C_ASSERT(FIELD_OFFSET(G56HID_STATUS,BuildId)==112);
#endif
