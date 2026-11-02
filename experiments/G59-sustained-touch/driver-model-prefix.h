#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
typedef size_t SIZE_T;typedef uint8_t*PUCHAR;
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef uint8_t UCHAR;typedef int32_t LONG,NTSTATUS;typedef int64_t LONG64;typedef uintptr_t ULONG_PTR;
typedef void VOID,*PVOID,*WDFDEVICE,*WDFQUEUE,*WDFOBJECT,*WDFFILEOBJECT,*VHFHANDLE,*VHFOPERATIONHANDLE,*HANDLE;
typedef int WDF_POWER_DEVICE_STATE;typedef pthread_mutex_t KMUTEX;
typedef struct{unsigned Flags;}OBJECT_ATTRIBUTES;
typedef struct{uint32_t a;uint16_t b,c;uint8_t d[8];}GUID;
typedef struct{ULONG dwOSVersionInfoSize,dwBuildNumber;}RTL_OSVERSIONINFOW;
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define PASSIVE_LEVEL 0
#define TRUE 1
#define FALSE 0
#define KernelMode 0
#define Executive 0
#define ALL_PROCESSOR_GROUPS 0xffff
#define NT_ASSERT(x) assert(x)
#define SYNCHRONIZE 0x100000
#define OBJ_KERNEL_HANDLE 0x200
#define InitializeObjectAttributes(a,n,f,r,s) ((a)->Flags=(f))
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xc0000010)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)
#define STATUS_QUOTA_EXCEEDED ((NTSTATUS)0xc0000044)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define NT_SUCCESS(s) ((s)>=0)
#define RtlZeroMemory(p,n) memset(p,0,n)
#define RtlCopyMemory(p,q,n) memcpy(p,q,n)
#define RtlCompareMemory(p,q,n) (memcmp(p,q,n)?0:(n))
#include "g59hid_baseline.h"
#include "g59hid_protocol.h"
#include "g59hid_report.h"
#include "g59_input.h"
#include "g59_hwapi.h"
#include "test-fixtures.h"
typedef struct{UCHAR*reportBuffer;ULONG reportBufferLen;UCHAR reportId;}HID_XFER_PACKET,*PHID_XFER_PACKET;
typedef struct{void*In;void*Out;WDFFILEOBJECT File;NTSTATUS InStatus,OutStatus,Completed;ULONG_PTR Information;}Request,*WDFREQUEST;
static LONG InterlockedCompareExchange(volatile LONG*p,LONG v,LONG cmp){__atomic_compare_exchange_n(p,&cmp,v,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return cmp;}
static LONG64 InterlockedCompareExchange64(volatile LONG64*p,LONG64 v,LONG64 cmp){__atomic_compare_exchange_n(p,&cmp,v,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return cmp;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){return __atomic_exchange_n(p,v,__ATOMIC_SEQ_CST);}
static LONG64 InterlockedExchange64(volatile LONG64*p,LONG64 v){return __atomic_exchange_n(p,v,__ATOMIC_SEQ_CST);}
static LONG InterlockedIncrement(volatile LONG*p){return __atomic_add_fetch(p,1,__ATOMIC_SEQ_CST);}
static LONG64 InterlockedIncrement64(volatile LONG64*p){return __atomic_add_fetch(p,1,__ATOMIC_SEQ_CST);}
