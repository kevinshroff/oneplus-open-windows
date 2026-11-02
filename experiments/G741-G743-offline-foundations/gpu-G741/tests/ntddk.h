/* Host HAL service model; deliberately not Windows ABI evidence. */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <pthread.h>
typedef void VOID;typedef void *PVOID,*PDEVICE_OBJECT;typedef uint8_t BOOLEAN;
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef size_t SIZE_T;
typedef int32_t NTSTATUS;typedef struct {ULONG Bytes,Offset;} MDL,*PMDL;
typedef struct LIST_ENTRY {struct LIST_ENTRY *Flink,*Blink;} LIST_ENTRY;
typedef struct {const wchar_t *Text;} UNICODE_STRING;
#define InitializeListHead(p) ((p)->Flink=(p)->Blink=(p))
#define RtlZeroMemory(p,n) memset(p,0,n)
#define MmGetMdlByteCount(m) ((m)->Bytes)
#define MmGetMdlByteOffset(m) ((m)->Offset)
#define TRUE 1
#define FALSE 0
#define PAGE_SIZE 4096
#define PASSIVE_LEVEL 0
#define MAXULONG UINT32_MAX
#define POOL_FLAG_NON_PAGED 1
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_PROCEDURE_NOT_FOUND ((NTSTATUS)0xc000007a)
#define STATUS_DEVICE_CONFIGURATION_ERROR ((NTSTATUS)0xc0000182)
#define STATUS_NOT_FOUND ((NTSTATUS)0xc0000225)
#define STATUS_CONFLICTING_ADDRESSES ((NTSTATUS)0xc0000018)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
typedef void *PIOMMU_DMA_DEVICE,*PIOMMU_DMA_DOMAIN;
typedef enum {DomainTypeTranslate=1,DomainTypeTranslateS1=2} IOMMU_DMA_DOMAIN_TYPE;
typedef struct {ULONG Dummy;} IOMMU_DMA_DOMAIN_CREATION_FLAGS;
typedef struct {LIST_ENTRY NextConfiguration;ULONG ConfigType;struct {ULONG InputMappingBase,MappingsCount;} Acpi;} IOMMU_DEVICE_CREATION_CONFIGURATION;
#define IommuDeviceCreationConfigTypeAcpi 1
typedef struct {ULONG InputMappingId;} INPUT_MAPPING_ELEMENT;
typedef ULONGLONG IOMMU_DMA_LOGICAL_ADDRESS;
typedef struct {ULONG MapType;struct {PMDL Mdl;} Mdl;} IOMMU_MAP_PHYSICAL_ADDRESS;
#define MapPhysicalAddressTypeMdl 1
#define DMA_IOMMU_INTERFACE_EX_VERSION_2 2
typedef struct {
 ULONG Size,Version;
 struct {
  NTSTATUS (*QueryInputMappings)(PDEVICE_OBJECT,INPUT_MAPPING_ELEMENT*,ULONG,ULONG*);
  NTSTATUS (*CreateDevice)(PDEVICE_OBJECT,IOMMU_DEVICE_CREATION_CONFIGURATION*,PIOMMU_DMA_DEVICE*);
  NTSTATUS (*DeleteDevice)(PIOMMU_DMA_DEVICE);
  VOID (*QueryAvailableDomainTypes)(PIOMMU_DMA_DEVICE,ULONG*);
  NTSTATUS (*CreateDomainEx)(IOMMU_DMA_DOMAIN_TYPE,IOMMU_DMA_DOMAIN_CREATION_FLAGS,PVOID,PVOID,PIOMMU_DMA_DOMAIN*);
  NTSTATUS (*DeleteDomain)(PIOMMU_DMA_DOMAIN);
  NTSTATUS (*AttachDeviceEx)(PIOMMU_DMA_DOMAIN,PIOMMU_DMA_DEVICE);
  NTSTATUS (*DetachDeviceEx)(PIOMMU_DMA_DEVICE);
  NTSTATUS (*MapLogicalRangeEx)(PIOMMU_DMA_DOMAIN,ULONG,IOMMU_MAP_PHYSICAL_ADDRESS*,ULONGLONG*,PVOID,PVOID,IOMMU_DMA_LOGICAL_ADDRESS*);
  NTSTATUS (*UnmapLogicalRange)(PIOMMU_DMA_DOMAIN,ULONGLONG,SIZE_T);
  NTSTATUS (*FlushDomain)(PIOMMU_DMA_DOMAIN);
 } V2;
} DMA_IOMMU_INTERFACE_EX,*PDMA_IOMMU_INTERFACE_EX;
ULONG KeGetCurrentIrql(VOID);
VOID RtlInitUnicodeString(UNICODE_STRING*,const wchar_t*);
PVOID MmGetSystemRoutineAddress(UNICODE_STRING*);
PVOID ExAllocatePool2(ULONGLONG,SIZE_T,ULONG);
VOID ExFreePoolWithTag(PVOID,ULONG);

typedef pthread_mutex_t KMUTEX;
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define Executive 0
#define KernelMode 0
VOID KeInitializeMutex(KMUTEX*,ULONG);
NTSTATUS KeWaitForSingleObject(KMUTEX*,int,int,BOOLEAN,PVOID);
VOID KeReleaseMutex(KMUTEX*,BOOLEAN);
