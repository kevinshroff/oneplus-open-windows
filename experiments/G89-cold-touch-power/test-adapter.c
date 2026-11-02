/* SPDX-License-Identifier: MIT -- actual adapter, modeled kernel/WDF/MMIO. */
#define main G89CoreModelMain
#include "test-power.c"
#undef main
#include "g89_driver.c"
static Model Hardware;
static ULONG Memory[10][2048],Mapped[10],MapFlags[10];
static uint32_t ObservedReadAddresses[45];static unsigned PermissionCases;
static int ObservedRead(uint32_t at){for(unsigned i=0;i<45;i++)if(ObservedReadAddresses[i]==at)return 1;return 0;}
static NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG p,ULONG id,void*b,ULONG n,ULONG*out)
{assert(!Irql&&p==0x41435049u&&id==0x54445344u);FirmwareQueries++;*out=FirmwareBytes;if(FirmwareStatus)return FirmwareStatus;if(FirmwareBytes>n)return STATUS_BUFFER_TOO_SMALL;memcpy(b,G89ExpectedDsdt,FirmwareBytes);if(FirmwareFlip&&FirmwareBytes)((UCHAR*)b)[FirmwareBytes-1]^=1;return 0;}
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS a,size_t n,ULONG flags)
{
 unsigned i;for(i=0;i<10&&G89IoRanges[i].Base!=(uint64_t)a.QuadPart;i++){}assert(i<10&&n==G89IoRanges[i].Bytes&&!Mapped[i]);
 assert(flags==(PAGE_READONLY|PAGE_NOCACHE)||(G89IoRanges[i].Writable&&flags==(PAGE_READWRITE|PAGE_NOCACHE)));
 Maps++;if(Maps==FailMap)return NULL;Mapped[i]=1;MapFlags[i]=flags;return Memory[i];
}
static void MmUnmapIoSpace(void*p,size_t n)
{unsigned i;for(i=0;i<10&&p!=Memory[i];i++){}assert(i<10&&Mapped[i]&&n==G89IoRanges[i].Bytes);Mapped[i]=0;MapFlags[i]=0;Unmaps++;}
static ULONG Address(volatile ULONG*p,unsigned*range)
{
 uintptr_t ptr=(uintptr_t)p;for(unsigned i=0;i<10;i++){uintptr_t base=(uintptr_t)Memory[i];if(ptr>=base&&ptr<base+G89IoRanges[i].Bytes){assert(Mapped[i]&&!((ptr-base)&3));*range=i;return G89IoRanges[i].Base+(ULONG)(ptr-base);}}
 assert(0);return 0;
}
static ULONG ModelRead(volatile ULONG*p)
{
 unsigned i;ULONG at=Address(p,&i),v;UNREFERENCED_PARAMETER(i);
 if(G89IoReadAllowed(at)){assert(Read(&Hardware,at,&v));return v;}
 int fixed=0;for(unsigned j=0;j<50;j++)if(at==G89Ranges[G89Fields[j].Range].Base+G89Fields[j].Offset)fixed=1;
 assert(fixed);Hardware.Reads++;return*p;
}
static void ModelWrite(volatile ULONG*p,ULONG v)
{unsigned i;ULONG at=Address(p,&i);assert(MapFlags[i]==(PAGE_READWRITE|PAGE_NOCACHE)&&G89IoWriteAllowed(at,v));assert(Write(&Hardware,at,v));}
static void KeStallExecutionProcessor(ULONG n){assert(n==1||n==1000);Ticks+=(uint64_t)n*192/10;if(n==1)Hardware.WaitUs++;else Hardware.WaitMs++;}
static NTSTATUS KeDelayExecutionThread(ULONG mode,ULONG alert,LARGE_INTEGER*wait)
{assert(!Irql&&mode==KernelMode&&!alert&&wait&&(wait->QuadPart==-10000||wait->QuadPart==-100000));Ticks+=(uint64_t)(-wait->QuadPart)*192/100;if(wait->QuadPart==-10000)Hardware.WaitMs++;else{Hardware.WaitTen++;Hardware.PhysicalOn=Hardware.TargetOn;}return STATUS_SUCCESS;}
static void Reset(int scenario)
{
 if(G89Frozen)G89Unload((void*)1);assert(!Allocation&&Allocations==Frees);for(unsigned i=0;i<10;i++)assert(!Mapped[i]);
 memset(&Hardware,0,sizeof(Hardware));memcpy(Hardware.Reg,B,sizeof(B));Hardware.Voltage=1800;Hardware.Mode=7;Hardware.Scenario=scenario;
 for(unsigned i=0;i<3;i++)Hardware.Obs[i]=0x08000007;
 memset(Memory,0,sizeof(Memory));for(unsigned j=0;j<50;j++)Memory[G89Fields[j].Range][G89Fields[j].Offset/4]=G89ExpectedValues[j];
 Build=26300;Processors=8;Irql=0;FirmwareBytes=576;FirmwareFlip=0;FirmwareStatus=0;EntryFail=0;Maps=Unmaps=FailMap=Allocations=Frees=InitFrees=Finished=DriverCreates=0;Ticks=0;AllocationBytes=0;memset(&Init,0,sizeof(Init));memset(&Queue,0,sizeof(Queue));
 FirmwareQueries=VersionCalls=0;G89Sequence=G89MapCalls=G89ObserverAttempts=G89ObserverFault=G89RunUsed=G89PmicVerified=G89TotalObservers=G89RunReady=0;
}
static void Load(void)
{UNICODE_STRING registry={2,4,L"x"};assert(!DriverEntry((void*)1,&registry)&&Finished==1&&AllocationBytes==44848&&!Maps&&!Hardware.Reads&&!Hardware.Writes);Hardware.Result=&G89Frozen->Power;}
static ModelRequest Call(ULONG code,G89_REQUEST*in,void*out,size_t bytes,int alias,int badInput,int badOutput)
{
 unsigned char*buffer=calloc(1,44848);assert(buffer);if(alias)memcpy(buffer,in,24);
 ModelRequest q={.Input=alias?(void*)buffer:in,.Output=buffer,.InputBytes=24,.OutputBytes=bytes,.FailInput=badInput,.FailOutput=badOutput};G89Control((void*)2,&q,bytes,24,code);assert(q.Complete);if(q.Info){assert(q.Info==bytes);memcpy(out,buffer,q.Info);}free(buffer);return q;
}
static void Before(void)
{G89_REQUEST in={24,1,G89_MAGIC,0};G89_PMIC out;ModelRequest q=Call(G89_IOCTL_PMIC,&in,&out,sizeof(out),1,0,0);assert(!q.Status&&out.Observer.Code==0&&out.FixedRegistersUnchanged&&out.Attempt==1&&out.Status.ObserverCaptures==1&&out.Status.OffPmicVerified);}
static void NoMapsLeft(void){assert(Maps==Unmaps);for(unsigned i=0;i<10;i++)assert(!Mapped[i]);}
int main(int argc,char**argv)
{
 assert(argc==3);Cases=0;FILE*contract=fopen(argv[2],"rb");assert(contract&&fread(ObservedReadAddresses,4,45,contract)==45&&fgetc(contract)==EOF&&!fclose(contract));
 for(int fail=1;fail<=8;fail++){
  Reset(0);EntryFail=fail;UNICODE_STRING p={2,4,L"x"};assert(DriverEntry((void*)1,&p)<0&&!Allocation&&!G89Frozen&&!Maps&&!Hardware.Reads&&!Hardware.Writes&&Allocations==Frees&&!Init.Live);Cases++;
 }
 Reset(0);Load();G89_REQUEST in={24,1,G89_MAGIC,0};G89_STATUS status;ModelRequest q=Call(G89_IOCTL_STATUS,&in,&status,sizeof(status),1,0,0);assert(!q.Status&&status.Size==96&&status.FirmwareMatch&&status.Processors==8&&!status.MapCalls&&!status.RunAttempts);Cases++;
 for(unsigned kind=0;kind<9;kind++){
  G89_REQUEST bad=in;size_t ib=24,ob=96;ULONG code=G89_IOCTL_STATUS;switch(kind){case 0:bad.Size=16;break;case 1:bad.Version=2;break;case 2:bad.Magic^=1;break;case 3:bad.Nonce=1;break;case 4:ib=23;break;case 5:ob=95;break;case 6:ob=97;break;case 7:code^=0x100;break;case 8:code=G89_IOCTL_RUN;ob=44848;break;}
  ModelRequest r={.Input=&bad,.Output=&status,.InputBytes=ib,.OutputBytes=ob};G89Control((void*)2,&r,ob,ib,code);assert(r.Complete&&r.Status<0&&!r.Info&&!Maps&&!Hardware.Reads&&!Hardware.Writes&&!G89RunUsed);Cases++;
 }
 for(int failure=0;failure<2;failure++){q=Call(G89_IOCTL_STATUS,&in,&status,96,1,failure==0,failure==1);assert(q.Status==STATUS_BUFFER_TOO_SMALL&&!q.Info&&!Maps);Cases++;}
 ModelFile file={0};ModelRequest f={0};G89FileCreate(NULL,&f,&file);assert(!f.Status);file.Name.Length=2;f=(ModelRequest){0};G89FileCreate(NULL,&f,&file);assert(f.Status==STATUS_OBJECT_NAME_INVALID&&!Maps);Cases++;
 for(unsigned bad=0;bad<7;bad++){
  Reset(0);Load();switch(bad){case 0:Build=26000;break;case 1:Processors=4;break;case 2:Irql=2;break;case 3:FirmwareBytes=575;break;case 4:FirmwareBytes=577;break;case 5:FirmwareFlip=1;break;case 6:FirmwareStatus=STATUS_NOT_SUPPORTED;break;}
  unsigned fw=FirmwareQueries,ver=VersionCalls;G89_SNAPSHOT snap;q=Call(G89_IOCTL_SNAPSHOT,&in,&snap,sizeof(snap),0,0,0);assert(q.Status==STATUS_NOT_SUPPORTED&&!Maps&&!Hardware.Reads&&!Hardware.Writes);if(bad==2)assert(FirmwareQueries==fw&&VersionCalls==ver);Cases++;
 }
 for(unsigned fail=1;fail<=4;fail++){
  Reset(0);Load();FailMap=fail;G89_SNAPSHOT snap;q=Call(G89_IOCTL_SNAPSHOT,&in,&snap,sizeof(snap),0,0,0);assert(q.Status==STATUS_INSUFFICIENT_RESOURCES&&Maps==fail&&Unmaps==fail-1&&!Hardware.Reads&&!Hardware.Writes);Cases++;
 }
 for(unsigned fail=1;fail<=14;fail++){
  Reset(0);Load();FailMap=fail;G89_PMIC pm;q=Call(G89_IOCTL_PMIC,&in,&pm,sizeof(pm),0,0,0);assert(!q.Status&&pm.Observer.Code&&Maps==fail&&Unmaps==fail-1&&!Hardware.Writes&&!G89PmicVerified);for(unsigned i=0;i<10;i++)assert(!Mapped[i]);Cases++;
 }
 Reset(0);Load();Before();G89_RUN run,cached;in.Nonce=42;q=Call(G89_IOCTL_RUN,&in,&run,sizeof(run),1,0,0);assert(!q.Status&&run.Nonce==42&&run.Attempt==1&&run.BaselineValid&&run.FixedRegistersUnchanged&&!run.Power.Code&&run.Power.Restored&&run.Power.TxnCount==12&&Hardware.SupplyWrites==2&&Hardware.Raw==0&&G89RunReady&&G89RunUsed);NoMapsLeft();Cases++;
 FILE*save=fopen(argv[1],"wb");assert(save&&fwrite(&run,1,sizeof(run),save)==sizeof(run)&&!fclose(save));
 unsigned reads=Hardware.Reads,writes=Hardware.Writes,maps=Maps;
 q=Call(G89_IOCTL_RUN,&in,&cached,sizeof(cached),0,0,0);assert(q.Status==STATUS_QUOTA_EXCEEDED&&!q.Info&&Hardware.Reads==reads&&Hardware.Writes==writes&&Maps==maps);Cases++;
 in.Nonce=43;q=Call(G89_IOCTL_RESULT,&in,&cached,sizeof(cached),0,0,0);assert(q.Status==STATUS_NOT_FOUND&&!q.Info&&Hardware.Reads==reads&&Hardware.Writes==writes);Cases++;
 in.Nonce=0;q=Call(G89_IOCTL_STATUS,&in,&status,sizeof(status),0,0,0);assert(!q.Status&&status.RunAttempts==1&&status.ObserverCaptures==4);Cases++;
 in.Nonce=42;q=Call(G89_IOCTL_RESULT,&in,&cached,sizeof(cached),1,0,0);assert(!q.Status&&!memcmp(&run,&cached,sizeof(run))&&Hardware.Reads==reads&&Hardware.Writes==writes&&Maps==maps);Cases++;
 in.Nonce=0;G89_PMIC pm;q=Call(G89_IOCTL_PMIC,&in,&pm,sizeof(pm),0,0,0);assert(!q.Status&&pm.Attempt==2&&!pm.Observer.Code&&pm.FixedRegistersUnchanged&&pm.Status.ObserverCaptures==5&&pm.Status.OffPmicVerified);NoMapsLeft();Cases++;
 reads=Hardware.Reads;writes=Hardware.Writes;maps=Maps;q=Call(G89_IOCTL_PMIC,&in,&pm,sizeof(pm),0,0,0);assert(!q.Status&&pm.Observer.Code==1002&&Hardware.Reads==reads&&Hardware.Writes==writes&&Maps==maps);Cases++;
 in.Nonce=42;q=Call(G89_IOCTL_RESULT,&in,&cached,sizeof(cached),0,0,0);assert(!q.Status&&!memcmp(&run,&cached,sizeof(run))&&Hardware.Reads==reads&&Hardware.Writes==writes&&Maps==maps);Cases++;
 /* Two preflight captures cannot consume the separate post-run check. */
 Reset(0);Load();Before();in.Nonce=0;q=Call(G89_IOCTL_PMIC,&in,&pm,sizeof(pm),0,0,0);assert(!q.Status&&!pm.Observer.Code);reads=Hardware.Reads;writes=Hardware.Writes;maps=Maps;
 in.Nonce=42;q=Call(G89_IOCTL_RUN,&in,&run,sizeof(run),0,0,0);assert(!q.Status&&run.Power.Code==1005&&!Hardware.SupplyWrites&&Hardware.Reads==reads&&Hardware.Writes==writes&&Maps==maps);Cases++;
 for(unsigned kind=0;kind<3;kind++){
  Reset(kind==0?7:kind==1?19:0);Load();if(kind!=2)Before();in.Nonce=42;q=Call(G89_IOCTL_RUN,&in,&run,sizeof(run),0,0,0);assert(!q.Status&&(run.Power.Code||run.Power.RestoreError||!run.Power.Restored)&&G89RunReady&&G89RunUsed);if(kind==0)assert(run.Power.RestoreError&&!run.Power.Restored&&!run.Status.OffPmicVerified);reads=Hardware.Reads;writes=Hardware.Writes;maps=Maps;
  q=Call(G89_IOCTL_RESULT,&in,&cached,sizeof(cached),0,0,0);assert(!q.Status&&!memcmp(&run,&cached,sizeof(run))&&Hardware.Reads==reads&&Hardware.Writes==writes&&Maps==maps);NoMapsLeft();Cases++;
 }
 for(unsigned fail=1;fail<=14;fail++){
  Reset(0);Load();Before();FailMap=Maps+fail;in.Nonce=42;q=Call(G89_IOCTL_RUN,&in,&run,sizeof(run),0,0,0);assert(!q.Status&&run.Power.Code&&G89RunReady&&G89RunUsed&&!Hardware.SupplyWrites&&Maps==Unmaps+1);for(unsigned i=0;i<10;i++)assert(!Mapped[i]);
  reads=Hardware.Reads;writes=Hardware.Writes;maps=Maps;q=Call(G89_IOCTL_RESULT,&in,&cached,sizeof(cached),0,0,0);assert(!q.Status&&!memcmp(&run,&cached,sizeof(run))&&Hardware.Reads==reads&&Hardware.Writes==writes&&Maps==maps);Cases++;
 }
 Reset(0);Load();G89_IO_CONTEXT io;assert(G89Map(&io));
 for(unsigned range=0;range<10;range++)for(unsigned off=0;off<G89IoRanges[range].Bytes;off+=4){
  uint32_t at=G89IoRanges[range].Base+off,v;reads=Hardware.Reads;
  if(ObservedRead(at))assert(G89NativeRead(&io,at,&v)&&Hardware.Reads==reads+1);
  else assert(!G89NativeRead(&io,at,&v)&&Hardware.Reads==reads);
  PermissionCases++;Cases++;
 }
 const uint32_t forbidden[8]={0xc7b7000,0xc7b7008,0xb000000,0x17100104,0xf10a000,0xf118000,0xa90000,0x40804};
 for(unsigned i=0;i<8;i++){writes=Hardware.Writes;assert(!G89NativeWrite(&io,forbidden[i],0)&&Hardware.Writes==writes);Cases++;}
 writes=Hardware.Writes;assert(!G89NativeWrite(&io,0x17a20d3c,2)&&Hardware.Writes==writes);Cases++;
 assert(G89NativeWrite(&io,0x17a20d3c,1)&&G89NativeWrite(&io,0x17a20d3c,0x60000001u)&&Hardware.Writes==writes+2&&!Hardware.SupplyWrites);writes=Hardware.Writes;Cases++;
 io.Reads=3000;uint32_t v;reads=Hardware.Reads;assert(!G89NativeRead(&io,0x17a20000,&v)&&Hardware.Reads==reads);io.Writes=183;assert(!G89NativeWrite(&io,0x17a20d34,0x108)&&Hardware.Writes==writes);Cases++;
 io.Writes=0;G89TotalObservers=5;assert(!G89NativeWrite(&io,0xc440ea0,0x08000007)&&Hardware.Writes==writes);G89ObserverFault=1;assert(!G89NativeWrite(&io,0xc441220,0x08000007)&&Hardware.Writes==writes);Cases++;
 G89Unmap(&io);NoMapsLeft();G89Unload((void*)1);assert(!Allocation&&Allocations==Frees);Cases++;
 printf("{\"passed\":true,\"cases\":%u,\"permission_word_cases\":%u,\"lifecycle_fault_result_and_other_guard_cases\":%u,\"independent_G72_read_contract_addresses\":45,\"actual_native_adapter_source\":true,\"kernel_WDF_MMIO_modeled\":true,\"frozen_result_retrieval_no_MMIO\":true,\"one_run_quota\":true,\"preserves_failed_results\":true,\"native_operations\":0}\n",Cases,PermissionCases,Cases-PermissionCases);return 0;
}
