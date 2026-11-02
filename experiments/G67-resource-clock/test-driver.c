/* SPDX-License-Identifier: MIT -- actual adapter, modeled Windows/MMIO APIs. */
#include "g67_driver.c"
#include <stdio.h>
static unsigned Cases,Maps,Unmaps,FailMap,Reads,Writes,Waits,StuckStopped,StuckRunning,SeenOn;
static ULONG Pages[3][1024];static unsigned Mapped[3],UnmapOrder[12];
static const ULONG Original[6]={0x40002380,0x80004000,0x80000000,0x100000,0,0x80000002};
static NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG p,ULONG id,void*b,ULONG n,ULONG*out){assert(p==0x41435049u&&id==0x54445344u);*out=FirmwareBytes;if(FirmwareStatus)return FirmwareStatus;if(FirmwareBytes>n)return STATUS_BUFFER_TOO_SMALL;memcpy(b,G67ExpectedDsdt,FirmwareBytes);if(FirmwareFlip&&FirmwareBytes)((UCHAR*)b)[FirmwareBytes-1]^=1;return 0;}
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS at,size_t n,ULONG flags)
{
 unsigned i;assert(n==4096&&flags==(PAGE_READWRITE|PAGE_NOCACHE));for(i=0;i<3&&at.QuadPart!=G67PageBase[i];i++){}assert(i<3&&!Mapped[i]);Maps++;if(Maps==FailMap)return NULL;Mapped[i]=1;return Pages[i];
}
static void MmUnmapIoSpace(void*p,size_t n){unsigned i;assert(n==4096);for(i=0;i<3&&p!=Pages[i];i++){}assert(i<3&&Mapped[i]);Mapped[i]=0;UnmapOrder[Unmaps++]=i;}
static unsigned Register(volatile ULONG*p)
{
 unsigned reg;for(reg=0;reg<6;reg++)if(p==&Pages[G67RegisterPage[reg]][G67RegisterOffset[reg]/4])break;
 assert(reg<6&&Mapped[G67RegisterPage[reg]]&&Available(G67Context(Device)));return reg;
}
static ULONG ModelRead(volatile ULONG*p)
{
 unsigned reg=Register(p);ULONG v=*p;Reads++;
 if(reg==1){if(Pages[2][2]&0x4000000){if(!StuckStopped)v&=~0x80000000u;}else if(StuckRunning&&SeenOn)v&=~0x80000000u;}return v;
}
static void ModelWrite(volatile ULONG*p,ULONG v){assert(Register(p)==0&&!((v^*p)&~G67_VOTE_MASK));Writes++;*p=v;if(v&0x4000000)SeenOn=1;}
static void KeStallExecutionProcessor(ULONG n){assert(n==1&&Available(G67Context(Device)));Waits++;}
static void FreeDevice(void)
{
 if(Device){G67_CONTEXT*c=G67Context(Device);assert(!c->Report.MappingMask);if(c->Lock){assert(!pthread_mutex_destroy(c->Lock));free(c->Lock);}free(Device);Device=NULL;}
}
static void Reset(void)
{
 FreeDevice();Build=26100;Processors=8;Irql=0;FirmwareBytes=sizeof(G67ExpectedDsdt);FirmwareStatus=AuxStatus=QueueStatus=WaitLockStatus=0;FirmwareFlip=0;DeviceCreates=DriverCreates=Interfaces=0;
 Maps=Unmaps=FailMap=Reads=Writes=Waits=StuckStopped=StuckRunning=SeenOn=0;memset(Pages,0,sizeof(Pages));memset(Mapped,0,sizeof(Mapped));memset(UnmapOrder,0,sizeof(UnmapOrder));memset(&Callbacks,0,sizeof(Callbacks));
 for(unsigned i=0;i<6;i++)Pages[G67RegisterPage[i]][G67RegisterOffset[i]/4]=Original[i];
}
static void AddOK(void)
{
 assert(!G67Add((void*)1,(void*)2)&&Device&&DeviceCreates==1&&Interfaces==1&&Queue.EvtIoDeviceControl==G67Control&&Files.Create==G67FileCreate);
 assert(Callbacks.EvtDevicePrepareHardware==G67Prepare&&Callbacks.EvtDeviceReleaseHardware==G67Release&&Callbacks.EvtDeviceD0Entry==G67D0Entry&&Callbacks.EvtDeviceD0Exit==G67D0Exit&&Callbacks.EvtDeviceSurpriseRemoval==G67Surprise);assert(Interface.Data1==0x2f1df03e&&Interface.Data2==0xa4ab);
}
static void Resources(CM_PARTIAL_RESOURCE_DESCRIPTOR rows[3],ModelList*l)
{
 memset(rows,0,3*sizeof(*rows));memset(l,0,sizeof(*l));l->Count=3;for(unsigned i=0;i<3;i++){rows[i].Type=3;rows[i].ShareDisposition=1;rows[i].u.Memory.Start.QuadPart=G67PageBase[i];rows[i].u.Memory.Length=4096;l->Rows[i]=&rows[i];}
}
static ModelRequest Call(ULONG code,size_t input,size_t output,G67_REQUEST*in,G67_REPORT*out,int fi,int fo)
{
 ModelRequest q={.Input=in,.Output=out,.InputBytes=input,.OutputBytes=output,.FailInput=fi,.FailOutput=fo};G67Control(Device,&q,output,input,code);assert(q.Completed);return q;
}
static void Release(ModelList*l){if(G67Context(Device)->Report.InD0)G67D0Exit(Device,0);assert(!G67Release(Device,l));assert(!G67Context(Device)->Report.MappingMask);}
static void PrepareD0(ModelList*raw,ModelList*tr){assert(!G67Prepare(Device,raw,tr)&&Maps==3&&Unmaps==0&&!Reads&&!Writes);assert(!G67D0Entry(Device,0)&&Available(G67Context(Device)));}
int main(int argc,char**argv)
{
 CM_PARTIAL_RESOURCE_DESCRIPTOR a[3],b[3];ModelList raw,tr;G67_REQUEST in={24,1,G67_MAGIC,0};G67_REPORT out;ModelRequest request;
 for(unsigned scenario=0;scenario<8;scenario++){Reset();switch(scenario){case 0:Build=26000;break;case 1:Processors=4;break;case 2:Irql=2;break;case 3:FirmwareBytes=576;break;case 4:FirmwareBytes=sizeof(G67ExpectedDsdt)+1;break;case 5:FirmwareBytes=0;break;case 6:FirmwareFlip=1;break;case 7:FirmwareStatus=STATUS_NOT_SUPPORTED;break;}assert(G67Add((void*)1,(void*)2)==STATUS_NOT_SUPPORTED&&!Device&&!DeviceCreates&&!Interfaces&&!Maps&&!Reads&&!Writes);Cases++;}
 Reset();AuxStatus=STATUS_NOT_SUPPORTED;assert(DriverEntry((void*)1,NULL)==STATUS_NOT_SUPPORTED&&!DriverCreates);Cases++;Reset();assert(!DriverEntry((void*)1,NULL)&&DriverCreates==1);Cases++;
 Reset();WaitLockStatus=STATUS_INSUFFICIENT_RESOURCES;assert(G67Add((void*)1,(void*)2)==WaitLockStatus&&Device&&!Interfaces&&!Maps);Cases++;
 for(unsigned scenario=0;scenario<7;scenario++){
  Reset();AddOK();Resources(a,&raw);Resources(b,&tr);switch(scenario){case 0:raw.Count=0;break;case 1:raw.Count=2;break;case 2:tr.Count=4;break;case 3:raw.Rows[1]=NULL;break;case 4:tr.Rows[2]=NULL;break;case 5:a[0].Type=2;break;case 6:b[0].u.Memory.Start.QuadPart+=4096;break;}
  assert(G67Prepare(Device,&raw,&tr)==STATUS_DEVICE_CONFIGURATION_ERROR&&!Maps&&!Reads&&!Writes&&!G67Context(Device)->Report.ResourceOK);Release(&tr);Cases++;
 }
 for(unsigned fail=1;fail<=3;fail++){Reset();AddOK();Resources(a,&raw);Resources(b,&tr);FailMap=fail;assert(G67Prepare(Device,&raw,&tr)==STATUS_INSUFFICIENT_RESOURCES&&Maps==fail&&Unmaps==fail-1&&!Reads&&!Writes);for(unsigned i=0;i<fail-1;i++)assert(UnmapOrder[i]==fail-2-i);assert(!G67Context(Device)->Report.MappingMask);Release(&tr);assert(Unmaps==fail-1);Cases++;}
 Reset();AddOK();Resources(a,&raw);Resources(b,&tr);PrepareD0(&raw,&tr);
 for(unsigned scenario=0;scenario<15;scenario++){
  G67_REQUEST q=in;size_t n=24,m=sizeof(out);ULONG code=G67_IOCTL_QUERY;int fi=0,fo=0;
  switch(scenario){case 0:code^=4;break;case 1:n=23;break;case 2:n=25;break;case 3:m--;break;case 4:m++;break;case 5:q.Size=0;break;case 6:q.Version=0;break;case 7:q.Magic=0;break;case 8:fi=1;break;case 9:fo=1;break;case 10:n=0;m=0;break;case 11:q.Nonce=1;break;case 12:code=G67_IOCTL_CYCLE;break;case 13:code=G67_IOCTL_CYCLE;q.Nonce=1;m--;break;case 14:code=G67_IOCTL_CYCLE;q.Nonce=1;fo=1;break;}
  memset(&out,0xa5,sizeof(out));request=Call(code,n,m,&q,&out,fi,fo);assert(request.Complete<0&&!request.Information&&!G67Context(Device)->Report.CycleAttempts&&!Reads&&!Writes);for(size_t i=0;i<sizeof(out);i++)assert(((UCHAR*)&out)[i]==0xa5);Cases++;
 }
 request=Call(G67_IOCTL_QUERY,24,sizeof(out),&in,&out,0,0);assert(!request.Complete&&request.Information==1872&&out.ResourceOK&&out.MappingMask==7&&out.RawCount==3&&!out.CycleAttempts&&!Reads&&!Writes);Cases++;
 UCHAR alias[sizeof(out)];memcpy(alias,&in,24);request=Call(G67_IOCTL_QUERY,24,sizeof(alias),(void*)alias,(void*)alias,0,0);assert(!request.Complete&&!memcmp(alias,&out,sizeof(out)));Cases++;
 UNICODE_STRING name={0};ModelRequest file={0};G67FileCreate(Device,&file,&name);assert(!file.Complete&&file.Completed);name.Length=2;memset(&file,0,sizeof(file));G67FileCreate(Device,&file,&name);assert(file.Complete==STATUS_OBJECT_NAME_INVALID);Cases+=2;
 in.Nonce=42;request=Call(G67_IOCTL_CYCLE,24,sizeof(out),&in,&out,0,0);assert(!request.Complete&&out.CycleAttempts==1&&out.Clock.Nonce==42&&out.Clock.Restored&&!out.Clock.Code&&!out.Clock.RestoreError&&Reads==33&&Writes==6);Cases++;
 if(argc==2){FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(&out,1,sizeof(out),f)==sizeof(out)&&!fclose(f));}
 unsigned reads=Reads,writes=Writes;request=Call(G67_IOCTL_CYCLE,24,sizeof(out),&in,&out,0,0);assert(request.Complete==STATUS_QUOTA_EXCEEDED&&Reads==reads&&Writes==writes);Cases++;
 Release(&tr);assert(Unmaps==3&&UnmapOrder[0]==2&&UnmapOrder[1]==1&&UnmapOrder[2]==0&&Reads==reads&&Writes==writes);Cases++;
 assert(!G67Prepare(Device,&raw,&tr)&&!G67D0Entry(Device,0));request=Call(G67_IOCTL_CYCLE,24,sizeof(out),&in,&out,0,0);assert(request.Complete==STATUS_QUOTA_EXCEEDED&&Reads==reads&&Writes==writes);Release(&tr);Cases++;
 Reset();AddOK();Resources(a,&raw);Resources(b,&tr);PrepareD0(&raw,&tr);G67Surprise(Device);request=Call(G67_IOCTL_CYCLE,24,sizeof(out),&in,&out,0,0);assert(request.Complete==STATUS_DEVICE_NOT_READY&&!Reads&&!Writes);assert(G67D0Entry(Device,0)==STATUS_DEVICE_NOT_READY);Release(&tr);assert(!Reads&&!Writes&&Unmaps==3);Cases++;
 Reset();AddOK();Resources(a,&raw);Resources(b,&tr);PrepareD0(&raw,&tr);Pages[2][2]|=0x10;request=Call(G67_IOCTL_CYCLE,24,sizeof(out),&in,&out,0,0);assert(!request.Complete&&out.Clock.Code==1&&!Writes&&out.CycleAttempts==1);Release(&tr);Cases++;
 Reset();AddOK();Resources(a,&raw);Resources(b,&tr);PrepareD0(&raw,&tr);StuckRunning=1;request=Call(G67_IOCTL_CYCLE,24,sizeof(out),&in,&out,0,0);assert(!request.Complete&&out.Clock.RestoreError==5&&!out.Clock.Restored);reads=Reads;writes=Writes;assert(G67D0Exit(Device,0)==STATUS_DEVICE_HARDWARE_ERROR);Release(&tr);assert(Reads==reads&&Writes==writes&&Unmaps==3);Cases++;
 FreeDevice();printf("{\"passed\":true,\"cases\":%u,\"actual_adapter_source_included\":true,\"native_operations\":0,\"native_resource_handoff_or_clock_vote_qualified\":false}\n",Cases);return 0;
}
