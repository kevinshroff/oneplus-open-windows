/* SPDX-License-Identifier: MIT */
#ifndef G179_PROTOCOL_H
#define G179_PROTOCOL_H
#define G179_MAGIC UINT64_C(0x314b48393731474f)
#define G179_ABI 1u
#define G179_IOCTL_STATUS CTL_CODE(FILE_DEVICE_UNKNOWN,0xac0,METHOD_BUFFERED,FILE_READ_ACCESS)
#define G179_IOCTL_READ CTL_CODE(FILE_DEVICE_UNKNOWN,0xac1,METHOD_BUFFERED,FILE_READ_ACCESS|FILE_WRITE_ACCESS)
#define G179_IOCTL_RESULT CTL_CODE(FILE_DEVICE_UNKNOWN,0xac2,METHOD_BUFFERED,FILE_READ_ACCESS)
typedef struct{ULONG Size,Version;ULONGLONG Magic,Nonce;ULONG Count,Reserved;}G179_REQUEST;
typedef struct{ULONG Size,Version;ULONGLONG Magic;ULONG KernelBuild,Processors,Irql,FirmwareBytes,FirmwareMatch,FirmwareStatus,MapCalls,Attempts,Ready,Fault;ULONGLONG InterruptTime,Frequency,Sequence;ULONG SafeToUnload,TransportUncertain,Reserved[2];}G179_STATUS;
typedef struct{G179_STATUS Status;ULONGLONG Nonce;ULONG Admission,Reserved;CH_IO_RESULT Result;}G179_CAPTURE;
C_ASSERT(sizeof(G179_REQUEST)==32);C_ASSERT(sizeof(G179_STATUS)==96);
#endif
