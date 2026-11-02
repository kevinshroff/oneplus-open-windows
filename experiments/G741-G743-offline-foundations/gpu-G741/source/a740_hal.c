/* SPDX-License-Identifier: MIT */
#include "a740_hal.h"
typedef NTSTATUS (*A740_GET_IOMMU)(ULONG, ULONGLONG, PDMA_IOMMU_INTERFACE_EX);
static BOOLEAN Passive(VOID) { return KeGetCurrentIrql()==PASSIVE_LEVEL; }
static VOID Config(IOMMU_DEVICE_CREATION_CONFIGURATION *C, ULONG Id)
{
    RtlZeroMemory(C,sizeof(*C)); InitializeListHead(&C->NextConfiguration);
    C->ConfigType=IommuDeviceCreationConfigTypeAcpi;
    C->Acpi.InputMappingBase=Id; C->Acpi.MappingsCount=1;
}
NTSTATUS A740HalDiscover(A740_HAL *H, PDEVICE_OBJECT Pdo)
{
    UNICODE_STRING name;
    INPUT_MAPPING_ELEMENT ids[A740_HAL_MAX_INPUTS]; ULONG bytes=0;
    A740_GET_IOMMU get; NTSTATUS st;
    if(!H||!Pdo||!Passive()) return STATUS_INVALID_PARAMETER;
    if(H->Pdo||H->ProbeRetained) return STATUS_INVALID_DEVICE_STATE;
    RtlZeroMemory(H,sizeof(*H)); H->Pdo=Pdo;
    H->Report.Phase=1; RtlInitUnicodeString(&name,L"IoGetIommuInterfaceEx");
    get=(A740_GET_IOMMU)MmGetSystemRoutineAddress(&name);
    if(!get) return H->Report.Status=STATUS_PROCEDURE_NOT_FOUND;
    H->Api.Size=sizeof(H->Api); H->Api.Version=DMA_IOMMU_INTERFACE_EX_VERSION_2;
    st=get(DMA_IOMMU_INTERFACE_EX_VERSION_2,0,&H->Api);
    if(!NT_SUCCESS(st)) return H->Report.Status=st;
    if(H->Api.Version!=DMA_IOMMU_INTERFACE_EX_VERSION_2||
       !H->Api.V2.QueryInputMappings||!H->Api.V2.CreateDevice||
       !H->Api.V2.DeleteDevice||!H->Api.V2.QueryAvailableDomainTypes||
       !H->Api.V2.CreateDomainEx||!H->Api.V2.DeleteDomain||
       !H->Api.V2.AttachDeviceEx||!H->Api.V2.DetachDeviceEx||
       !H->Api.V2.MapLogicalRangeEx||!H->Api.V2.UnmapLogicalRange||
       !H->Api.V2.FlushDomain) return H->Report.Status=STATUS_NOT_SUPPORTED;
    H->Report.Phase=2;
    RtlZeroMemory(ids,sizeof(ids));
    st=H->Api.V2.QueryInputMappings(Pdo,ids,sizeof(ids),&bytes);
    if(!NT_SUCCESS(st)) return H->Report.Status=st;
    if(!bytes||bytes>sizeof(ids)||bytes%sizeof(ids[0]))
        return H->Report.Status=STATUS_DEVICE_CONFIGURATION_ERROR;
    H->Report.Count=bytes/sizeof(ids[0]);
    for(ULONG i=0;i<H->Report.Count;++i) {
        A740_HAL_INPUT *r=&H->Report.Input[i];r->InputId=ids[i].InputMappingId;
        r->CreateStatus=STATUS_NOT_FOUND;r->DeleteStatus=STATUS_NOT_FOUND;
        for(ULONG j=0;j<i;++j) if(r->InputId==H->Report.Input[j].InputId)
            return H->Report.Status=STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    for(ULONG i=0;i<H->Report.Count;++i) {
        IOMMU_DEVICE_CREATION_CONFIGURATION cfg; PIOMMU_DMA_DEVICE dev=NULL;
        A740_HAL_INPUT *r=&H->Report.Input[i];r->Attempted=1;
        Config(&cfg,r->InputId); r->DeleteStatus=STATUS_NOT_FOUND;
        r->CreateStatus=H->Api.V2.CreateDevice(Pdo,&cfg,&dev);
        if(!NT_SUCCESS(r->CreateStatus)) continue;
        if(!dev) return H->Report.Status=STATUS_DEVICE_CONFIGURATION_ERROR;
        H->Api.V2.QueryAvailableDomainTypes(dev,&r->AvailableDomainTypes);
        r->DeleteStatus=H->Api.V2.DeleteDevice(dev);
        if(!NT_SUCCESS(r->DeleteStatus)) {
            H->ProbeRetained=dev; return H->Report.Status=r->DeleteStatus;
        }
    }
    H->Report.Phase=3; return H->Report.Status=STATUS_SUCCESS;
}
static A740_HAL_INPUT *Find(A740_HAL *H, ULONG Id)
{
    for(ULONG i=0;i<H->Report.Count;++i) if(H->Report.Input[i].InputId==Id)
        return &H->Report.Input[i];
    return NULL;
}
NTSTATUS A740HalOpenRole(A740_HAL_ROLE *R,A740_HAL *H,const ULONG *Ids,
                         ULONG N,IOMMU_DMA_DOMAIN_TYPE Type)
{
    IOMMU_DMA_DOMAIN_CREATION_FLAGS flags={0}; NTSTATUS st;
    if(!R||!H||!Ids||!N||N>A740_HAL_MAX_ROLE_INPUTS||!Passive()||
       H->Report.Phase!=3||H->ProbeRetained||R->Hal||R->Domain||
       (Type!=DomainTypeTranslate && Type!=DomainTypeTranslateS1))
        return STATUS_INVALID_PARAMETER;
    for(ULONG i=0;i<N;++i) {
        A740_HAL_INPUT *f=Find(H,Ids[i]);
        if(!f||!NT_SUCCESS(f->CreateStatus)||!(f->AvailableDomainTypes&(1u<<Type)))
            return STATUS_NOT_SUPPORTED;
        for(ULONG j=0;j<i;++j) if(Ids[i]==Ids[j]) return STATUS_INVALID_PARAMETER;
    }
    KeInitializeMutex(&R->MapLock,0);
    R->Hal=H;R->Type=Type;R->Count=N;
    /* No registered allocator: each subsequent mapping supplies exact IOVA. */
    st=H->Api.V2.CreateDomainEx(Type,flags,NULL,NULL,&R->Domain);
    if(!NT_SUCCESS(st)||!R->Domain) goto failed;
    for(ULONG i=0;i<N;++i) {
        IOMMU_DEVICE_CREATION_CONFIGURATION cfg; Config(&cfg,Ids[i]);
        st=H->Api.V2.CreateDevice(H->Pdo,&cfg,&R->Device[i]);
        if(!NT_SUCCESS(st)||!R->Device[i]) goto failed;
        st=H->Api.V2.AttachDeviceEx(R->Domain,R->Device[i]);
        if(!NT_SUCCESS(st)) goto failed;
        R->Attached++;
    }
    return STATUS_SUCCESS;
failed:
    R->Poisoned=TRUE;
    return NT_SUCCESS(st)?STATUS_DEVICE_CONFIGURATION_ERROR:st;
}
static BOOLEAN ValidRange(ULONGLONG Va, SIZE_T Bytes)
{
    return Bytes && !(Bytes & (PAGE_SIZE-1)) && !(Va & (PAGE_SIZE-1)) &&
           Va + Bytes > Va;
}
static NTSTATUS MapLocked(A740_HAL_ROLE *R,PMDL M,ULONGLONG Va,SIZE_T Bytes,ULONG P)
{
    IOMMU_MAP_PHYSICAL_ADDRESS physical={0};IOMMU_DMA_LOGICAL_ADDRESS actual=0;
    A740_HAL_MAPPING *entry, *it; NTSTATUS st;
    if(!R||!M||!Passive()||R->Poisoned||!R->Hal||!R->Domain||
       !R->Count||R->Attached!=R->Count||R->Mappings==MAXULONG||
       !ValidRange(Va,Bytes)||MmGetMdlByteOffset(M)||
       MmGetMdlByteCount(M)!=Bytes||!(P&3)||(P&~3u))
        return STATUS_INVALID_PARAMETER;
    for(it=R->MapHead;it;it=it->Next)
        if(Va<it->Iova+it->Bytes && it->Iova<Va+Bytes)
            return STATUS_CONFLICTING_ADDRESSES;
    entry=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*entry),A740_HAL_TAG);
    if(!entry) return STATUS_INSUFFICIENT_RESOURCES;
    entry->Mdl=M;entry->Iova=Va;entry->ActualIova=0;
    entry->Bytes=Bytes;entry->Permissions=P;
    entry->Next=R->MapHead;R->MapHead=entry;R->Mappings++;
    physical.MapType=MapPhysicalAddressTypeMdl;physical.Mdl.Mdl=M;
    st=R->Hal->Api.V2.MapLogicalRangeEx(R->Domain,P,&physical,&Va,NULL,NULL,&actual);
    entry->ActualIova=actual;
    /* Do not infer from a failed HAL status that no translation was installed.
     * Retain the MDL identity and freeze this domain until explicit recovery. */
    if(!NT_SUCCESS(st)||actual!=entry->Iova) {
        R->Poisoned=TRUE;
        return NT_SUCCESS(st)?STATUS_DEVICE_CONFIGURATION_ERROR:st;
    }
    return st;
}
static NTSTATUS UnmapLocked(A740_HAL_ROLE *R,ULONGLONG Va,SIZE_T Bytes)
{
    A740_HAL_MAPPING **link,*entry;NTSTATUS st;
    if(!R||!Passive()||R->Poisoned||!R->Hal||!R->Domain||
       !R->Mappings||!ValidRange(Va,Bytes)) return STATUS_INVALID_PARAMETER;
    for(link=&R->MapHead;*link;link=&(*link)->Next)
        if((*link)->Iova==Va && (*link)->Bytes==Bytes) break;
    entry=*link;
    if(!entry) return STATUS_NOT_FOUND;
    st=R->Hal->Api.V2.UnmapLogicalRange(R->Domain,Va,Bytes/PAGE_SIZE);
    if(NT_SUCCESS(st)) st=R->Hal->Api.V2.FlushDomain(R->Domain);
    if(!NT_SUCCESS(st)) R->Poisoned=TRUE;
    else {
        *link=entry->Next;R->Mappings--;
        ExFreePoolWithTag(entry,A740_HAL_TAG);
    }
    return st;
}
static NTSTATUS CloseStoppedLocked(A740_HAL_ROLE *R)
{
    NTSTATUS st;A740_HAL *H;
    if(!R||!Passive()||!R->Hal||R->Poisoned||R->Mappings||R->MapHead) return STATUS_INVALID_DEVICE_STATE;
    H=R->Hal;
    while(R->Attached) {
        ULONG i=R->Attached-1;
        st=H->Api.V2.DetachDeviceEx(R->Device[i]);
        if(!NT_SUCCESS(st)) {R->Poisoned=TRUE;return st;} R->Attached--;
    }
    for(ULONG i=0;i<R->Count;++i) if(R->Device[i]) {
        st=H->Api.V2.DeleteDevice(R->Device[i]);
        if(!NT_SUCCESS(st)) {R->Poisoned=TRUE;return st;} R->Device[i]=NULL;
    }
    if(R->Domain) {
        st=H->Api.V2.DeleteDomain(R->Domain);
        if(!NT_SUCCESS(st)) {R->Poisoned=TRUE;return st;}
    }
    RtlZeroMemory(R,FIELD_OFFSET(A740_HAL_ROLE,MapLock));return STATUS_SUCCESS;
}

/* A kernel mutex preserves PASSIVE_LEVEL, unlike FAST_MUTEX. Open/discover and
 * device lifetime changes require external serialization. MapLock is initialized
 * before OpenRole publishes Hal and is preserved by successful close. */
NTSTATUS A740HalMap(A740_HAL_ROLE *R,PMDL M,ULONGLONG Va,SIZE_T Bytes,ULONG P)
{
    NTSTATUS st;
    if(!R||!Passive()||!R->Hal) return STATUS_INVALID_PARAMETER;
    KeWaitForSingleObject(&R->MapLock,Executive,KernelMode,FALSE,NULL);
    st=MapLocked(R,M,Va,Bytes,P);
    KeReleaseMutex(&R->MapLock,FALSE);return st;
}
NTSTATUS A740HalUnmap(A740_HAL_ROLE *R,ULONGLONG Va,SIZE_T Bytes)
{
    NTSTATUS st;
    if(!R||!Passive()||!R->Hal) return STATUS_INVALID_PARAMETER;
    KeWaitForSingleObject(&R->MapLock,Executive,KernelMode,FALSE,NULL);
    st=UnmapLocked(R,Va,Bytes);
    KeReleaseMutex(&R->MapLock,FALSE);return st;
}
NTSTATUS A740HalCloseStopped(A740_HAL_ROLE *R)
{
    NTSTATUS st;
    if(!R||!Passive()||!R->Hal) return STATUS_INVALID_DEVICE_STATE;
    KeWaitForSingleObject(&R->MapLock,Executive,KernelMode,FALSE,NULL);
    st=CloseStoppedLocked(R);
    KeReleaseMutex(&R->MapLock,FALSE);return st;
}
