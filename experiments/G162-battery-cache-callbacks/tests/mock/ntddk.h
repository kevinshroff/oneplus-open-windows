/* Host test shim only. Does not emulate Windows PnP, lifetime or resources. */
#ifndef G162_MOCK_NTDDK_H
#define G162_MOCK_NTDDK_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint32_t ULONG; typedef int32_t LONG,NTSTATUS;
typedef void *PVOID; typedef ULONG *PULONG; typedef wchar_t WCHAR;
typedef struct { uintptr_t Opaque[7]; } FAST_MUTEX;
#define PASSIVE_LEVEL 0
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_NO_SUCH_DEVICE ((NTSTATUS)0xc000000e)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xc0000010)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define RtlZeroMemory(p,n) memset((p),0,(n))
#define RtlCopyMemory(p,q,n) memcpy((p),(q),(n))
#define FIELD_OFFSET(t,f) ((ULONG)offsetof(t,f))
unsigned KeGetCurrentIrql(void);
uint64_t KeQueryInterruptTime(void);
void ExInitializeFastMutex(FAST_MUTEX *);
void ExAcquireFastMutex(FAST_MUTEX *);
void ExReleaseFastMutex(FAST_MUTEX *);
void MockSetTimeUs(uint64_t);
void MockSetIrql(unsigned);
unsigned MockLockDepth(void);
void MockDestroyMutex(FAST_MUTEX *);
#endif
