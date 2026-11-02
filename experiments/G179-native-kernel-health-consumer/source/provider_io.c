/* SPDX-License-Identifier: MIT; no raw device, IOCTL, value or duration API. */
#include <ntifs.h>
#include <wdf.h>
#include "provider_io.h"
typedef struct{uint32_t Size,Version;uint64_t Magic,Nonce;uint32_t Count,Reserved;}CH_PROVIDER_REQUEST;
C_ASSERT(sizeof(CH_PROVIDER_REQUEST)==32);
NTSTATUS ChReadKernelHealth(WDFDEVICE parent,uint64_t nonce,uint64_t oldNonce,
 uint64_t oldTime,uint32_t role,CH_IO_RESULT*out)
{
 WDFIOTARGET targets[2]={NULL,NULL};WDFMEMORY input[2]={NULL,NULL},output[2]={NULL,NULL};
 PVOID buffers[2]={NULL,NULL};NTSTATUS status=STATUS_INVALID_PARAMETER;
 const ULONG bytes[2]={CH_CONFIG_BYTES,CH_GAUGE_BYTES};
 const ULONG codes[2]={2255368u,2255304u}; /* only G167/G160 RESULT, read access */
 const uint64_t magics[2]={UINT64_C(0x314d50373631474f),UINT64_C(0x315147303631474f)};
 DECLARE_CONST_UNICODE_STRING(configName,L"\\Device\\OpenG167");
 DECLARE_CONST_UNICODE_STRING(gaugeName,L"\\Device\\OpenG160");
 const UNICODE_STRING*names[2]={&configName,&gaugeName};
 if(!out)return STATUS_INVALID_PARAMETER;RtlZeroMemory(out,sizeof(*out));out->HealthCode=CH_ARGUMENT;
 if(!parent||!nonce||role>CH_RENEW||KeGetCurrentIrql()!=PASSIVE_LEVEL){out->LastStatus=(uint32_t)status;return status;}
 out->Begin100ns=KeQueryInterruptTime();
 for(unsigned i=0;i<2;i++){
  WDF_OBJECT_ATTRIBUTES attributes;WDF_IO_TARGET_OPEN_PARAMS open;
  WDF_MEMORY_DESCRIPTOR inDesc,outDesc;WDF_REQUEST_SEND_OPTIONS options;
  PVOID requestBytes=NULL;ULONG_PTR got=0;
  out->Stage=10+10*i;
  status=WdfIoTargetCreate(parent,WDF_NO_OBJECT_ATTRIBUTES,&targets[i]);if(!NT_SUCCESS(status))goto done;
  out->CreatedMask|=1u<<i;
  out->Stage=11+10*i;
  WDF_IO_TARGET_OPEN_PARAMS_INIT_OPEN_BY_NAME(&open,names[i],GENERIC_READ);
  open.ShareAccess=0;status=WdfIoTargetOpen(targets[i],&open);if(!NT_SUCCESS(status))goto done;
  out->OpenedMask|=1u<<i;
  WDF_OBJECT_ATTRIBUTES_INIT(&attributes);attributes.ParentObject=targets[i];
  out->Stage=12+10*i;
  status=WdfMemoryCreate(&attributes,NonPagedPoolNx,'97HC',sizeof(CH_PROVIDER_REQUEST),&input[i],&requestBytes);if(!NT_SUCCESS(status))goto done;
  out->ManagedBuffers++;
  *(CH_PROVIDER_REQUEST*)requestBytes=(CH_PROVIDER_REQUEST){32,1,magics[i],nonce,0,0};
  out->Stage=13+10*i;
  status=WdfMemoryCreate(&attributes,NonPagedPoolNx,'97HC',bytes[i],&output[i],&buffers[i]);if(!NT_SUCCESS(status))goto done;
  out->ManagedBuffers++;
  WDF_MEMORY_DESCRIPTOR_INIT_HANDLE(&inDesc,input[i],NULL);
  WDF_MEMORY_DESCRIPTOR_INIT_HANDLE(&outDesc,output[i],NULL);
  WDF_REQUEST_SEND_OPTIONS_INIT(&options,WDF_REQUEST_SEND_OPTION_TIMEOUT);
  WDF_REQUEST_SEND_OPTIONS_SET_TIMEOUT(&options,WDF_REL_TIMEOUT_IN_MS(2000));
  out->Stage=14+10*i;out->SentMask|=1u<<i;
  status=WdfIoTargetSendIoctlSynchronously(targets[i],NULL,codes[i],&inDesc,&outDesc,&options,&got);
  out->SendStatus[i]=(uint32_t)status;out->ReceivedBytes[i]=(uint32_t)got;
  if(!NT_SUCCESS(status))goto done;
  out->Stage=15+10*i;
  if(got!=bytes[i]){status=STATUS_INFO_LENGTH_MISMATCH;goto done;}
  out->ReceivedMask|=1u<<i;
 }
 out->Stage=30;out->Validation100ns=KeQueryInterruptTime();out->ValidationAttempted=1;
 out->HealthCode=CHValidate(buffers[0],bytes[0],buffers[1],bytes[1],nonce,
  out->Validation100ns,oldNonce,oldTime,role,&out->Health);
 status=out->HealthCode==CH_OK?STATUS_SUCCESS:STATUS_DEVICE_NOT_READY;
 done:
 if(!NT_SUCCESS(status))out->FailedStage=out->Stage;
 /* Always close before delete, including a timed-out internal request.
  * Buffers are target children and their WDF memory references outlive a
  * still-cancelling request; no stack or manually freed buffer is exposed. */
 for(unsigned n=2;n;n--){unsigned i=n-1;if(targets[i]){
  if(out->OpenedMask&(1u<<i)){WdfIoTargetClose(targets[i]);out->ClosedMask|=1u<<i;}
  WdfObjectDelete(targets[i]);out->DeletedMask|=1u<<i;
 }}
 out->End100ns=KeQueryInterruptTime();
 if(NT_SUCCESS(status)){
  /* Cleanup can itself take time. Never relabel an aged result as fresh. */
  if(out->End100ns<out->Health.GaugeEnd100ns||out->End100ns-out->Health.ConfigBegin100ns>CH_FRESH_100NS){
   out->HealthCode=CH_FRESHNESS;out->FailedStage=31;status=STATUS_DEVICE_NOT_READY;
  }else {out->Valid=1;out->Stage=100;}
 }
 if(!out->Valid)RtlZeroMemory(&out->Health,sizeof(out->Health));
 out->LastStatus=(uint32_t)status;return status;
}
