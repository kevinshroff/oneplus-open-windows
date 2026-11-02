/* SPDX-License-Identifier: MIT */
#include "vhf291.h"
static int Submit(void*x,const uint8_t report[2])
{
 VHF291*v=x;HID_XFER_PACKET packet;UCHAR copy[2];
 copy[0]=report[0];copy[1]=report[1];RtlZeroMemory(&packet,sizeof(packet));
 packet.reportBuffer=copy;packet.reportBufferLen=sizeof(copy);packet.reportId=1;
 v->LastSubmit=VhfReadReportSubmit(v->Vhf,&packet);
 return NT_SUCCESS(v->LastSubmit);
}
NTSTATUS Vhf291Create(VHF291*v,WDFDEVICE device,uint64_t epoch)
{
 VHF_CONFIG config;NTSTATUS status;
 static WCHAR instance[]=L"OpenPowerG293";
 static WCHAR hardwareIds[]=L"OPENLAB\\ONEPLUSOPENPOWERG293\0";
 if(!v||!device||!epoch)return STATUS_INVALID_PARAMETER;
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 if(v->Vhf)return STATUS_INVALID_DEVICE_STATE;
 RtlZeroMemory(v,sizeof(*v));
 VHF_CONFIG_INIT(&config,WdfDeviceWdmGetDeviceObject(device),
  (USHORT)P291DescriptorBytes,(PUCHAR)P291Descriptor);
 /* Default VHF buffering: local transfer bytes reusable after submit returns. */
 config.VhfClientContext=v;
 config.InstanceID=instance;config.InstanceIDLength=(USHORT)(sizeof(instance)-sizeof(WCHAR));
 config.HardwareIDs=hardwareIds;config.HardwareIDsLength=(USHORT)sizeof(hardwareIds);
 status=VhfCreate(&config,&v->Vhf);if(!NT_SUCCESS(status))return status;
 status=VhfStart(v->Vhf);
 if(!NT_SUCCESS(status)){VhfDelete(v->Vhf,TRUE);v->Vhf=NULL;return status;}
 P291Init(&v->Power,epoch,Submit,v);return STATUS_SUCCESS;
}
int Vhf291StopDelete(VHF291*v)
{
 int released;
 if(!v||KeGetCurrentIrql()!=PASSIVE_LEVEL)return 0;
 if(!v->Vhf)return !v->Power.DeliveryUncertain&&!v->Power.AcceptedDown;
 released=P291Stop(&v->Power);VhfDelete(v->Vhf,TRUE);v->Vhf=NULL;
 return released;
}
