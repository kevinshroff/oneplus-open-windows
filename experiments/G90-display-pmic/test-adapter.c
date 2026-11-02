/* SPDX-License-Identifier: MIT -- actual adapter, modeled kernel/WDF/MMIO. */
#define main G90CoreModelMain
#include "test-power.c"
#undef main
#include "g90_driver.c"
static Model Hardware;
static ULONG Memory[10][2048],Mapped[10],MapFlags[10];
static uint32_t ObservedReadAddresses[45];
static int ObservedRead(uint32_t at){for(unsigned i=0;i<45;i++)if(ObservedReadAddresses[i]==at)return 1;return 0;}
static NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG p,ULONG id,void*b,ULONG n,ULONG*out)
{assert(!Irql&&p==0x41435049u&&id==0x54445344u);FirmwareQueries++;*out=FirmwareBytes;if(FirmwareStatus)return FirmwareStatus;if(FirmwareBytes>n)return STATUS_BUFFER_TOO_SMALL;memcpy(b,G90ExpectedDsdt,FirmwareBytes);if(FirmwareFlip&&FirmwareBytes)((UCHAR*)b)[FirmwareBytes-1]^=1;return 0;}
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS a,size_t n,ULONG flags)
{
 unsigned i;for(i=0;i<10&&G90IoRanges[i].Base!=(uint64_t)a.QuadPart;i++){}assert(i<10&&n==G90IoRanges[i].Bytes&&!Mapped[i]);
 assert(flags==(PAGE_READONLY|PAGE_NOCACHE)||(G90IoRanges[i].Writable&&flags==(PAGE_READWRITE|PAGE_NOCACHE)));
 Maps++;if(Maps==FailMap)return NULL;Mapped[i]=1;MapFlags[i]=flags;return Memory[i];
}
static void MmUnmapIoSpace(void*p,size_t n)
{unsigned i;for(i=0;i<10&&p!=Memory[i];i++){}assert(i<10&&Mapped[i]&&n==G90IoRanges[i].Bytes);Mapped[i]=0;MapFlags[i]=0;Unmaps++;}
static ULONG Address(volatile ULONG*p,unsigned*range)
{
 uintptr_t ptr=(uintptr_t)p;for(unsigned i=0;i<10;i++){uintptr_t base=(uintptr_t)Memory[i];if(ptr>=base&&ptr<base+G90IoRanges[i].Bytes){assert(Mapped[i]&&!((ptr-base)&3));*range=i;return G90IoRanges[i].Base+(ULONG)(ptr-base);}}
 assert(0);return 0;
}
static ULONG ModelRead(volatile ULONG*p)
{
 unsigned i;ULONG at=Address(p,&i),v;UNREFERENCED_PARAMETER(i);
 if(G90IoReadAllowed(at)){assert(Read(&Hardware,at,&v));return v;}
 int fixed=0;for(unsigned j=0;j<50;j++)if(at==G90Ranges[G90Fields[j].Range].Base+G90Fields[j].Offset)fixed=1;
 assert(fixed);Hardware.Reads++;return*p;
}
static void ModelWrite(volatile ULONG*p,ULONG v)
{unsigned i;ULONG at=Address(p,&i);assert(MapFlags[i]==(PAGE_READWRITE|PAGE_NOCACHE)&&G90IoWriteAllowed(at,v));assert(Write(&Hardware,at,v));}
static void KeStallExecutionProcessor(ULONG n){assert(n==1||n==1000);Ticks+=(uint64_t)n*192/10;if(n==1)Hardware.WaitUs++;else Hardware.WaitMs++;}
static NTSTATUS KeDelayExecutionThread(ULONG mode,ULONG alert,LARGE_INTEGER*wait)
{assert(!Irql&&mode==KernelMode&&!alert&&wait&&(wait->QuadPart==-10000||wait->QuadPart==-100000));Ticks+=(uint64_t)(-wait->QuadPart)*192/100;if(wait->QuadPart==-10000)Hardware.WaitMs++;else{Hardware.WaitTen++;Hardware.PhysicalOn=Hardware.TargetOn;}return STATUS_SUCCESS;}
static void Reset(int scenario)
{
 if(G90Frozen)G90Unload((void*)1);assert(!Allocation&&Allocations==Frees);for(unsigned i=0;i<10;i++)assert(!Mapped[i]);
 memset(&Hardware,0,sizeof(Hardware));memcpy(Hardware.Reg,B,sizeof(B));Hardware.Voltage=1800;Hardware.Mode=7;Hardware.Scenario=scenario;
 for(unsigned i=0;i<3;i++)Hardware.Obs[i]=0x08000007;
 memset(Memory,0,sizeof(Memory));for(unsigned j=0;j<50;j++)Memory[G90Fields[j].Range][G90Fields[j].Offset/4]=G90ExpectedValues[j];
 Build=26300;Processors=8;Irql=0;FirmwareBytes=576;FirmwareFlip=0;FirmwareStatus=0;EntryFail=0;Maps=Unmaps=FailMap=Allocations=Frees=InitFrees=Finished=DriverCreates=0;Ticks=0;AllocationBytes=0;memset(&Init,0,sizeof(Init));memset(&Queue,0,sizeof(Queue));
 FirmwareQueries=VersionCalls=0;G90Sequence=G90MapCalls=G90ObserverAttempts=G90ObserverFault=G90RunUsed=G90PmicVerified=G90TotalObservers=0;
}
static void Load(void)
{UNICODE_STRING registry={2,4,L"x"};assert(!DriverEntry((void*)1,&registry)&&Finished==1&&AllocationBytes==44848&&!Maps&&!Hardware.Reads&&!Hardware.Writes);Hardware.Result=&G90Frozen->Power;}
static ModelRequest Call(ULONG code,G90_REQUEST*in,void*out,size_t bytes,int alias,int badInput,int badOutput)
{
 unsigned char*buffer=calloc(1,44848);assert(buffer);if(alias)memcpy(buffer,in,24);
 ModelRequest q={.Input=alias?(void*)buffer:in,.Output=buffer,.InputBytes=24,.OutputBytes=bytes,.FailInput=badInput,.FailOutput=badOutput};G90Control((void*)2,&q,bytes,24,code);assert(q.Complete);if(q.Info){assert(q.Info==bytes);memcpy(out,buffer,q.Info);}free(buffer);return q;
}
static void Before(void)
{G90_REQUEST in={24,1,G90_MAGIC,0};G90_PMIC out;ModelRequest q=Call(G90_IOCTL_PMIC,&in,&out,sizeof(out),1,0,0);assert(!q.Status&&out.Observer.Code==0&&out.FixedRegistersUnchanged&&out.Attempt==1&&out.Status.ObserverCaptures==1&&out.Status.OffPmicVerified);}
static void NoMapsLeft(void){assert(Maps==Unmaps);for(unsigned i=0;i<10;i++)assert(!Mapped[i]);}
int main(void){
 Cases=0;Reset(0);Load();G90_REQUEST in={24,1,G90_MAGIC,0};G90_PMIC pm;G90_STATUS st;
 ModelRequest q=Call(G90_IOCTL_STATUS,&in,&st,sizeof(st),0,0,0);assert(!q.Status&&!Maps&&!Hardware.Writes);Cases++;
 q=Call(G90_IOCTL_PMIC,&in,&pm,sizeof(pm),1,0,0);assert(!q.Status&&!pm.Observer.Code&&pm.FixedRegistersUnchanged&&pm.Attempt==1);Cases++;
 q=Call(G90_IOCTL_PMIC,&in,&pm,sizeof(pm),0,0,0);assert(!q.Status&&!pm.Observer.Code&&pm.FixedRegistersUnchanged&&pm.Attempt==2);Cases++;
 unsigned reads=Hardware.Reads,writes=Hardware.Writes,maps=Maps;
 q=Call(G90_IOCTL_PMIC,&in,&pm,sizeof(pm),0,0,0);assert(!q.Status&&pm.Observer.Code==1002&&Hardware.Reads==reads&&Hardware.Writes==writes&&Maps==maps);Cases++;
 G90_RUN unused;for(int i=0;i<2;i++){q=Call(i?G90_IOCTL_RESULT:G90_IOCTL_RUN,&in,&unused,sizeof(unused),0,0,0);assert(q.Status==STATUS_INVALID_DEVICE_REQUEST&&Hardware.Reads==reads&&Hardware.Writes==writes);Cases++;}
 for(unsigned at=0x17a20d00;at<0x17a20d50;at+=4)for(unsigned v=0;v<4;v++){assert(!G90IoWriteAllowed(at,v));Cases++;}
 NoMapsLeft();assert(!Hardware.SupplyWrites&&!G90RunUsed);G90Unload((void*)1);
 printf("{\"observer_contract_checks\":%u,\"passed\":true}\n",Cases);return 0;
}
