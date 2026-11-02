/* SPDX-License-Identifier: MIT
 * Current post-EBS recheck before HAL may access a powered SMMU. No writes.
 */
#include <ntddk.h>
#include <aux_klib.h>
#include "g290_power_report.h"
#include "g323_clock_policy.h"
VOID LogPrint(PCSTR Fmt,...);
C_ASSERT(sizeof(G290_POWER_REPORT)==216);
static const ULONGLONG Addresses[G290_GATES]={0x00171004,0x03d99108,0x03d9953c,
    0x00171010,0x00171018,0x03d9911c,0x03d97000};
static const ULONGLONG Pages[3]={0x00171000,0x03d97000,0x03d99000};
static NTSTATUS ReadAssigned(PCM_RESOURCE_LIST Resources,ULONGLONG Pa,PULONG Value)
{
    PCM_PARTIAL_RESOURCE_LIST list=&Resources->List[0].PartialResourceList;
    for(ULONG i=0;i<list->Count;++i) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR r=&list->PartialDescriptors[i];
        ULONGLONG start=(ULONGLONG)r->u.Memory.Start.QuadPart;PHYSICAL_ADDRESS at;
        if(Pa<start||Pa-start>0xffc) continue;
        at.QuadPart=(LONGLONG)Pa;
        PULONG p=MmMapIoSpaceEx(at,4,PAGE_READONLY|PAGE_NOCACHE);
        if(!p) return STATUS_INSUFFICIENT_RESOURCES;
        *Value=READ_REGISTER_ULONG(p);MmUnmapIoSpace(p,4);return STATUS_SUCCESS;
    }
    return STATUS_RESOURCE_TYPE_NOT_FOUND;
}
NTSTATUS A740ValidatePowerReport(G290_POWER_REPORT *report)
{
    ULONG bytes=0;NTSTATUS st;UCHAR sum=0;
    if(!report)return STATUS_INVALID_PARAMETER;
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
    /* Access the ACPI copy through the OS table API, never by guessed PA. */
    st=AuxKlibInitialize();if(st!=STATUS_SUCCESS) return st;
    st=AuxKlibGetSystemFirmwareTable(0x41435049u,G290_POWER_SIGNATURE,
                                    report,sizeof(*report),&bytes);
    if(st!=STATUS_SUCCESS) {LogPrint("A740 OGPR missing/status %08x; HAL query withheld\n",st);return st;}
    if(bytes!=sizeof(*report)||report->Header.Length!=sizeof(*report)||
       report->Header.Signature!=G290_POWER_SIGNATURE||report->Version!=G290_POWER_VERSION||
       report->Stage!=G290_POWER_STAGE_READY||report->Status||report->ReadyBeforeEbs!=1||
       report->PostEbsPersistenceProven||report->CreatedMask!=3||report->IssuedMask!=3||
       report->ReturnedMask!=3||report->ObservedMask!=3)
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    for(ULONG i=0;i<sizeof(*report);++i) sum=(UCHAR)(sum+((PUCHAR)report)[i]);
    if(sum||report->CornerAfter[0]<G290_GPU_CORNER||report->CornerAfter[1]<G290_GPU_CORNER)
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    for(ULONG i=0;i<G290_GATES;++i)
        if(report->Gate[i].Pa!=Addresses[i]) return STATUS_DEVICE_CONFIGURATION_ERROR;
    return STATUS_SUCCESS;
}
NTSTATUS A740RequirePoweredHandoff(PCM_RESOURCE_LIST Resources)
{
    G290_POWER_REPORT report;ULONG value;NTSTATUS st;ULONG seen=0;
    st=A740ValidatePowerReport(&report);if(st!=STATUS_SUCCESS)return st;
    /* Exact three read-only source pages; no shared broad GCC/GPU aperture. */
    if(!Resources||Resources->Count!=1||Resources->List[0].PartialResourceList.Count!=3)
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    for(ULONG i=0;i<3;++i) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR r=&Resources->List[0].PartialResourceList.PartialDescriptors[i];
        ULONG match=3;
        if(r->Type!=CmResourceTypeMemory||r->u.Memory.Length!=PAGE_SIZE||
           !(r->Flags&CM_RESOURCE_MEMORY_READ_ONLY)) return STATUS_DEVICE_CONFIGURATION_ERROR;
        for(ULONG j=0;j<3;++j) if((ULONGLONG)r->u.Memory.Start.QuadPart==Pages[j]) match=j;
        if(match==3||(seen&(1u<<match))) return STATUS_DEVICE_CONFIGURATION_ERROR;
        seen|=1u<<match;
    }
    /* Recheck CURRENT values in source order. No SMMU ID or API call before
     * cfg-AHB -> software-held CX -> actual four running branches. */
    for(ULONG i=0;i<G290_GATES;++i) {
        st=ReadAssigned(Resources,Addresses[i],&value);if(!NT_SUCCESS(st)) return st;
        LogPrint("A740 post-EBS clock %llx %08x (pre-EBS %08x)\n",Addresses[i],value,report.Gate[i].After);
        if(value==MAXULONG) return STATUS_DEVICE_POWER_FAILURE;
        if(i==0 && !(value&1)) return STATUS_DEVICE_POWER_FAILURE;
        if(i==1 && (value&3)) return STATUS_DEVICE_POWER_FAILURE;
        if(i==2 && !(value&0x80000000u)) return STATUS_DEVICE_POWER_FAILURE;
        if(i>=3 && !G323BranchReady(i,value)) return STATUS_DEVICE_POWER_FAILURE;
    }
    LogPrint("A740 current source branch admission passes; pre-EBS IDs %08x/%08x/%08x; no persistence/Sx claim\n",
        report.SmmuId[0],report.SmmuId[1],report.SmmuId[2]);
    return STATUS_SUCCESS;
}
