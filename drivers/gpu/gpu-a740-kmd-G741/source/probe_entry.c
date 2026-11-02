/* SPDX-License-Identifier: MIT
 * ACPI-PDO-only HAL capability query. Shares a740_hal.c with the WDDM backend.
 * No public device interface, domain attachment, firmware loading or DMA action.
 * Source-bound read-only clock checks precede HAL calls; no SMMU MMIO writes.
 */
#include <ntddk.h>
#include "a740_hal.h"
NTSTATUS A740RequirePoweredHandoff(PCM_RESOURCE_LIST Resources);
VOID LogOpen(VOID);VOID LogClose(VOID);VOID LogPrint(PCSTR Fmt,...);
typedef struct {
    PDEVICE_OBJECT Pdo,Lower;A740_HAL Hal;BOOLEAN Started;
} A740_PROBE;
static NTSTATUS Forward(PDEVICE_OBJECT Device,PIRP Irp)
{
    A740_PROBE *p=Device->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);return IoCallDriver(p->Lower,Irp);
}
static NTSTATUS Power(PDEVICE_OBJECT Device,PIRP Irp)
{
    A740_PROBE *p=Device->DeviceExtension;
    IoSkipCurrentIrpStackLocation(Irp);return PoCallDriver(p->Lower,Irp);
}
static VOID Report(A740_PROBE *p,NTSTATUS st)
{
    LogPrint("A740 HAL query phase %u status %08x count %u; no attach/private-SMMU-write\n",
        p->Hal.Report.Phase,st,p->Hal.Report.Count);
    for(ULONG i=0;i<p->Hal.Report.Count;++i) {
        const A740_HAL_INPUT *r=&p->Hal.Report.Input[i];
        LogPrint("A740 input %08x attempted %u types %08x create %08x delete %08x\n",
            r->InputId,r->Attempted,r->AvailableDomainTypes,r->CreateStatus,r->DeleteStatus);
    }
}
static NTSTATUS Pnp(PDEVICE_OBJECT Device,PIRP Irp)
{
    A740_PROBE *p=Device->DeviceExtension;
    PIO_STACK_LOCATION sp=IoGetCurrentIrpStackLocation(Irp);NTSTATUS st;
    switch(sp->MinorFunction) {
    case IRP_MN_START_DEVICE:
        if(!IoForwardIrpSynchronously(p->Lower,Irp)) st=STATUS_UNSUCCESSFUL;
        else st=Irp->IoStatus.Status;
        if(NT_SUCCESS(st)) {
            if(!p->Started) {
                NTSTATUS query=A740RequirePoweredHandoff(sp->Parameters.StartDevice.AllocatedResourcesTranslated);
                if(NT_SUCCESS(query)) query=A740HalDiscover(&p->Hal,p->Pdo);
                p->Started=TRUE;Report(p,query);
            }
            /* Probe's PnP start succeeded; its separately logged query may
             * report unsupported hardware/domain policy. No rendering claim. */
            st=STATUS_SUCCESS;
        }
        Irp->IoStatus.Status=st;IoCompleteRequest(Irp,IO_NO_INCREMENT);return st;
    case IRP_MN_REMOVE_DEVICE:
        if(p->Hal.ProbeRetained) {
            NTSTATUS release=p->Hal.Api.V2.DeleteDevice(p->Hal.ProbeRetained);
            LogPrint("A740 retained probe-token final delete %08x; reset recovery if failed\n",release);
            if(NT_SUCCESS(release)) p->Hal.ProbeRetained=NULL;
        }
        IoSkipCurrentIrpStackLocation(Irp);st=IoCallDriver(p->Lower,Irp);
        IoDetachDevice(p->Lower);IoDeleteDevice(Device);return st;
    default:return Forward(Device,Irp);
    }
}
static NTSTATUS AddDevice(PDRIVER_OBJECT Driver,PDEVICE_OBJECT Pdo)
{
    PDEVICE_OBJECT fdo=NULL;A740_PROBE *p;
    NTSTATUS st=IoCreateDevice(Driver,sizeof(A740_PROBE),NULL,FILE_DEVICE_UNKNOWN,
                              FILE_DEVICE_SECURE_OPEN,FALSE,&fdo);
    if(!NT_SUCCESS(st)) return st;
    p=fdo->DeviceExtension;RtlZeroMemory(p,sizeof(*p));p->Pdo=Pdo;
    p->Lower=IoAttachDeviceToDeviceStack(fdo,Pdo);
    if(!p->Lower) {IoDeleteDevice(fdo);return STATUS_NO_SUCH_DEVICE;}
    fdo->Flags|=DO_POWER_PAGABLE;fdo->Flags&=~DO_DEVICE_INITIALIZING;
    LogPrint("A740 capability probe attached to actual ACPI PDO %p\n",Pdo);
    return STATUS_SUCCESS;
}
static VOID Unload(PDRIVER_OBJECT Driver)
{UNREFERENCED_PARAMETER(Driver);LogClose();}
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver,PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);LogOpen();
    LogPrint("==== Open A740 HAL ACPI capability query G290; IORT retained; no rendering ====\n");
    for(ULONG i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;++i) Driver->MajorFunction[i]=Forward;
    Driver->MajorFunction[IRP_MJ_PNP]=Pnp;Driver->MajorFunction[IRP_MJ_POWER]=Power;
    Driver->DriverExtension->AddDevice=AddDevice;Driver->DriverUnload=Unload;
    return STATUS_SUCCESS;
}
