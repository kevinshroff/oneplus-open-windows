/* SPDX-License-Identifier: MIT. Cached read-only status; never hardware access. */
#ifndef PROTOCOL293_H
#define PROTOCOL293_H
#define G293_IOCTL_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN,0x908,METHOD_BUFFERED,FILE_READ_ACCESS)
#define G293_MAGIC 0x314b33393247504fULL
typedef struct {
 ULONG Size,Version;ULONGLONG Magic;
 ULONGLONG Epoch,Sequence,Samples,AtUs,PowerDowns,LastDownUs;
 ULONG ReportsEnabled,LastStatus,CoreCode,StreamCode,LastRaw,StablePower;
 ULONG LastSubmit,AcceptedDown,DeliveryUncertain,Running;
}G293_STATUS;
C_ASSERT(sizeof(G293_STATUS)==104);
#define G308_IOCTL_FAILURE CTL_CODE(FILE_DEVICE_UNKNOWN,0x909,METHOD_BUFFERED,FILE_READ_ACCESS)
typedef struct {
 ULONG Size,Version;ULONGLONG Magic,Epoch,AtUs;
 ULONG Code,Stage,Reads,Writes,Polls,TraceCount,Guard,NtStatus;
 G99_TRACE Trace;
} G308_FAILURE;
C_ASSERT(sizeof(G308_FAILURE)==104);
#endif
