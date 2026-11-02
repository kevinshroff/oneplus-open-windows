/* CPU test shim for actual inactive allocation source; no Windows ABI claim. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
typedef unsigned char *PUCHAR;typedef void VOID,*PVOID;typedef uint8_t UCHAR,BOOLEAN;typedef uint32_t ULONG;typedef uint64_t UINT64,*PPFN_NUMBER;typedef int64_t LONGLONG;typedef size_t SIZE_T,ULONG_PTR;typedef int32_t NTSTATUS;typedef int MEMORY_CACHING_TYPE;
typedef struct {LONGLONG QuadPart;} PHYSICAL_ADDRESS;
typedef struct {unsigned MdlFlags,offset;size_t bytes;uint64_t pfns[32];} MDL,*PMDL;
#define TRUE 1
#define FALSE 0
#define PAGE_SIZE 4096
#define PASSIVE_LEVEL 0
#define MDL_PAGES_LOCKED 2
#define POOL_FLAG_NON_PAGED 0x40
#define MmNonCached 0
#define MAXULONGLONG UINT64_MAX
#define STATUS_SUCCESS 0
#define STATUS_INVALID_PARAMETER -1
#define STATUS_CONFLICTING_ADDRESSES -2
#define STATUS_INSUFFICIENT_RESOURCES -3
#define STATUS_DATA_ERROR -4
#define STATUS_INVALID_DEVICE_STATE -5
#define STATUS_DEVICE_BUSY -6
#define RtlZeroMemory(p,n) memset(p,0,n)
#define MmGetMdlByteOffset(m) ((m)->offset)
#define MmGetMdlByteCount(m) ((m)->bytes)
#define MmGetMdlPfnArray(m) ((m)->pfns)
int KeGetCurrentIrql(void);
void *ExAllocatePool2(unsigned,size_t,unsigned);
void ExFreePoolWithTag(void*,unsigned);
void *MmAllocateContiguousMemorySpecifyCache(size_t,PHYSICAL_ADDRESS,PHYSICAL_ADDRESS,PHYSICAL_ADDRESS,int);
void MmFreeContiguousMemory(void*);
PHYSICAL_ADDRESS MmGetPhysicalAddress(void*);
