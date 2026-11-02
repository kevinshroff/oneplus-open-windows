/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Actual driver/DDI/PDO lifetime and awake scope. No hardware stop or power
 * provider success stubs: full native clauses remain explicitly unsupported. */
#include <ntifs.h>
#include "g515_lifecycle.h"
#include "g290_power_report.h"
#include "g323_clock_policy.h"
#include <aux_klib.h>
#include <devpkey.h>
#include "tgpu.h"
#include <ntddvdeo.h>
#include <video.h>
static const ULONGLONG Pa[7]={0x171004,0x03d99108,0x03d9953c,0x171010,0x171018,0x03d9911c,0x03d97000};
static NTSTATUS Lock(G515_LIFE*l){LARGE_INTEGER t;t.QuadPart=-500000;if(!l||!l->Initialized||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;return KeWaitForSingleObject(&l->Lock,Executive,KernelMode,FALSE,&t);}
static NTSTATUS Bootstrap(void){
 G290_POWER_REPORT b;ULONG bytes=0;UCHAR sum=0;NTSTATUS s=AuxKlibInitialize();if(s!=STATUS_SUCCESS)return s;
 RtlZeroMemory(&b,sizeof(b));s=AuxKlibGetSystemFirmwareTable(0x41435049u,G290_POWER_SIGNATURE,&b,sizeof(b),&bytes);if(s!=STATUS_SUCCESS)return s;
 if(bytes!=sizeof(b)||b.Header.Length!=sizeof(b)||b.Header.Signature!=G290_POWER_SIGNATURE||b.Version!=3||b.CreatedMask!=3||b.IssuedMask!=3||b.ReturnedMask!=3||b.ObservedMask!=3||b.CornerAfter[0]<256||b.CornerAfter[1]<256)return STATUS_DEVICE_CONFIGURATION_ERROR;
 for(ULONG i=0;i<sizeof(b);i++)sum=(UCHAR)(sum+((PUCHAR)&b)[i]);if(sum)return STATUS_DEVICE_CONFIGURATION_ERROR;
 for(ULONG i=0;i<7;i++)if(b.Gate[i].Pa!=Pa[i])return STATUS_DEVICE_CONFIGURATION_ERROR;
 /* Only bootstrap retained-client evidence. Never demand or trust a firmware
  * claim about future post-EBS persistence; current samples below establish
  * this Windows observation, including after a firmware checkpoint stop. */
 return STATUS_SUCCESS;
}
static NTSTATUS Current(G515_LIFE*l){
 NTSTATUS s;ULONGLONG counter;
 l->PostEbsObserved=FALSE;l->SampleMask=0;
 if(InterlockedCompareExchange(&l->Inhibit,0,0)||!l->StartObserved||!l->OsD0Candidate||l->Removed||!l->Io||!l->Io->Bound||l->Io->Pdo!=l->Pdo)return STATUS_DEVICE_NOT_READY;
 s=Bootstrap();if(s!=STATUS_SUCCESS)return s;
 for(ULONG i=0;i<7;i++){
  ULONG v=0;s=G482ReadClock(l->Io,Pa[i],&v);if(s!=STATUS_SUCCESS)return s;
  l->Value[i]=v;l->SampleMask|=1u<<i;
  if(v==MAXULONG||(i==0&&!(v&1))||(i==1&&(v&3))||(i==2&&!(v&0x80000000u))||(i>=3&&!G323BranchReady(i,v)))return STATUS_DEVICE_POWER_FAILURE;
 }
 l->SampleTime=KeQueryInterruptTimePrecise(&counter);l->ObservationGeneration=l->Generation;l->PostEbsObserved=TRUE;return STATUS_SUCCESS;
}
NTSTATUS G515Initialize(G515_LIFE*l,PDEVICE_OBJECT pdo){
 if(!l||!pdo||KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_PARAMETER;
 RtlZeroMemory(l,sizeof(*l));KeInitializeMutex(&l->Lock,0);l->Initialized=TRUE;l->Inhibit=1;l->Pdo=pdo;ObReferenceObject(pdo);
 l->Requested=PowerDeviceUnspecified;l->Missing=31;l->Status=STATUS_DEVICE_NOT_READY;return STATUS_SUCCESS;
}
static VOID PdoD0(G515_LIFE*l){
 CM_POWER_DATA data;ULONG bytes=0;DEVPROPTYPE type=0;
 l->PropertyStatus=STATUS_NOT_SUPPORTED;
 /* IoGetDevicePropertyData requires system-thread context, not merely a
  * constructor default or an assumption that StartDevice implies D0. */
 if(!PsIsSystemThread(PsGetCurrentThread()))return;
 RtlZeroMemory(&data,sizeof(data));l->PropertyStatus=IoGetDevicePropertyData(l->Pdo,&DEVPKEY_Device_PowerData,LOCALE_NEUTRAL,0,sizeof(data),&data,&bytes,&type);
 if(l->PropertyStatus==STATUS_SUCCESS&&type==DEVPROP_TYPE_BINARY&&bytes==sizeof(data)&&data.PD_Size==sizeof(data)&&data.PD_MostRecentPowerState==PowerDeviceD0){l->OsD0Candidate=TRUE;l->PowerSource=1;l->Requested=PowerDeviceD0;}
}
NTSTATUS G515StartObserved(G515_LIFE*l,G482_BINDING*io){
 NTSTATUS s=Lock(l);if(s!=STATUS_SUCCESS)return s;
 if(l->Removed||l->HeldThread||l->Generation==MAXULONGLONG){s=STATUS_INVALID_DEVICE_STATE;goto done;}
 l->Generation++;l->Io=io;l->StartObserved=TRUE;l->OsD0Candidate=FALSE;l->PostEbsObserved=FALSE;l->PowerSource=0;l->Requested=PowerDeviceUnspecified;
 InterlockedExchange(&l->Inhibit,0);PdoD0(l);
 s=Current(l);
done:l->Status=s;KeReleaseMutex(&l->Lock,FALSE);return s;
}
NTSTATUS G515EnterAwake(G515_LIFE*l,ULONGLONG gen){
 NTSTATUS s=Lock(l);if(s!=STATUS_SUCCESS)return s;
 if(l->HeldThread||gen!=l->Generation){s=STATUS_INVALID_DEVICE_STATE;goto fail;}
 s=Current(l);if(s!=STATUS_SUCCESS)goto fail;
 l->HeldThread=PsGetCurrentThread();l->Status=STATUS_SUCCESS;return STATUS_SUCCESS;
fail:l->Status=s;KeReleaseMutex(&l->Lock,FALSE);return s;
}
NTSTATUS G515CheckAwake(G515_LIFE*l,ULONGLONG gen){
 if(!l||l->HeldThread!=PsGetCurrentThread()||gen!=l->Generation)return STATUS_INVALID_DEVICE_STATE;
 return l->Status=Current(l);
}
VOID G515LeaveAwake(G515_LIFE*l){if(l&&l->HeldThread==PsGetCurrentThread()){l->HeldThread=NULL;KeReleaseMutex(&l->Lock,FALSE);}}
NTSTATUS G515Revoke(G515_LIFE*l,BOOLEAN remove){
 if(!l||!l->Initialized)return STATUS_INVALID_DEVICE_STATE;
 InterlockedExchange(&l->Inhibit,1);NTSTATUS s=Lock(l);if(s!=STATUS_SUCCESS)return s;
 if(l->HeldThread){KeReleaseMutex(&l->Lock,FALSE);return STATUS_DEVICE_BUSY;}
 /* The mutex joins an actual outstanding scope. Generation changes only
  * after its owner leaves. No physical/DMA stop is inferred from this join. */
 l->StartObserved=FALSE;l->OsD0Candidate=FALSE;l->PostEbsObserved=FALSE;if(remove)l->Removed=TRUE;
 if(l->Generation!=MAXULONGLONG)l->Generation++;else s=STATUS_INTEGER_OVERFLOW;
 l->Status=s;KeReleaseMutex(&l->Lock,FALSE);return s;
}
NTSTATUS G515PowerObserved(G515_LIFE*l,ULONG uid,DEVICE_POWER_STATE state){
 NTSTATUS s;
 if(!l||!l->Initialized)return STATUS_INVALID_DEVICE_STATE;
 if(uid!=DISPLAY_ADAPTER_HW_ID){s=Lock(l);if(s!=STATUS_SUCCESS)return s;l->ChildRequests++;l->LastChildUid=uid;KeReleaseMutex(&l->Lock,FALSE);return STATUS_SUCCESS;}
 if(state!=PowerDeviceD0){
  if(state<PowerDeviceD1||state>PowerDeviceD3)return STATUS_INVALID_PARAMETER;
  InterlockedExchange(&l->Inhibit,1);s=Lock(l);if(s!=STATUS_SUCCESS)return s;
  if(l->HeldThread){KeReleaseMutex(&l->Lock,FALSE);return STATUS_DEVICE_BUSY;}
  l->OsD0Candidate=FALSE;l->PostEbsObserved=FALSE;l->Requested=state;
  if(l->Generation!=MAXULONGLONG)l->Generation++;else{s=STATUS_INTEGER_OVERFLOW;}
  l->Status=s;KeReleaseMutex(&l->Lock,FALSE);return s;
 }
 s=Lock(l);if(s!=STATUS_SUCCESS)return s;
 if(l->Removed||!l->StartObserved||l->Generation==MAXULONGLONG){s=STATUS_DEVICE_NOT_READY;goto done;}
 if(!l->OsD0Candidate||l->Requested!=PowerDeviceD0)l->Generation++;l->Requested=PowerDeviceD0;l->OsD0Candidate=TRUE;l->PowerSource=2;InterlockedExchange(&l->Inhibit,0);
 /* DDI request + actual fresh hardware observation, not request alone. */
 s=Current(l);
done:l->Status=s;KeReleaseMutex(&l->Lock,FALSE);return s;
}
NTSTATUS G515Dispose(G515_LIFE*l){NTSTATUS s=G515Revoke(l,TRUE);if(s!=STATUS_SUCCESS)return s;if(l->Pdo)ObDereferenceObject(l->Pdo);l->Pdo=NULL;return STATUS_SUCCESS;}
static NTSTATUS Enter(void*p,ULONGLONG g){return G515EnterAwake(p,g);}static VOID Leave(void*p){G515LeaveAwake(p);}
static NTSTATUS Lease(void*p,ULONGLONG g){G515_LIFE*l=p;NTSTATUS s=G515CheckAwake(l,g);if(s!=STATUS_SUCCESS)return s;l->Missing|=G515_MISSING_NATIVE_POWER;return STATUS_NOT_SUPPORTED;}
static NTSTATUS Stopped(void*p,ULONGLONG serial,ULONGLONG gen){G515_LIFE*l=p;UNREFERENCED_PARAMETER(serial);UNREFERENCED_PARAMETER(gen);l->Missing|=G515_MISSING_PHYSICAL_STOP;return STATUS_NOT_SUPPORTED;}
static NTSTATUS Backing(void*p,PMDL m,PVOID c,ULONGLONG v,SIZE_T n){G515_LIFE*l=p;UNREFERENCED_PARAMETER(m);UNREFERENCED_PARAMETER(c);UNREFERENCED_PARAMETER(v);UNREFERENCED_PARAMETER(n);l->Missing|=G515_MISSING_BACKING;return STATUS_NOT_SUPPORTED;}
VOID G515BuildOwner(G515_LIFE*l,G321_OWNER*o){RtlZeroMemory(o,sizeof(*o));o->Cookie=l;o->Enter=Enter;o->Leave=Leave;o->Lease=Lease;o->Stopped=Stopped;o->ValidateBacking=Backing;}
