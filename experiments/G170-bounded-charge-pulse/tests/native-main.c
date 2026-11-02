/* SPDX-License-Identifier: MIT; appended after the actual driver by run-native.py */
static unsigned NativeCases;
static const char*ResultFolder;
static void Save(const char*name){char path[4096];assert(snprintf(path,sizeof(path),"%s/%s",ResultFolder,name)>0);FILE*f=fopen(path,"wbx");assert(f);WdfObjectAcquireLock(Device);Identity(&Owner->Data);assert(fwrite(&Owner->Data,1,sizeof(Owner->Data),f)==sizeof(Owner->Data));WdfObjectReleaseLock(Device);fclose(f);}
static void File(const char*p,void*b,size_t n){FILE*f=fopen(p,"rb");assert(f&&fread(b,1,n,f)==n&&fgetc(f)==EOF);fclose(f);}
static void Tick(void){WdfObjectAcquireLock(Device);ClnTimer(Timer);WdfObjectReleaseLock(Device);}
static CLN_SNAPSHOT_DATA*Response;
static NTSTATUS Call(ULONG code,uint64_t cookie,uint64_t id,size_t inSize,size_t outSize)
{
 memset(Response,0,sizeof(*Response));CLN_REQUEST*r=(void*)Response;
 *r=(CLN_REQUEST){sizeof(*r),CLN_ABI,CLN_MAGIC,cookie,id,0,0};
 MODEL_REQUEST req={Response,sizeof(*Response),0,0,-99,999};
 WdfObjectAcquireLock(Device);ClnControl(NULL,&req,outSize,inSize,code);WdfObjectReleaseLock(Device);
 assert(req.Bytes==(NT_SUCCESS(req.Status)?sizeof(*Response):0));return req.Status;
}
static NTSTATUS Cmd(ULONG code,uint64_t id){return Call(code,code==CLN_STATUS||code==CLN_SNAPSHOT?0:Owner->Data.Cookie,id,40,sizeof(*Response));}
static void Reset(void)
{
 assert(!Owner&&!Timer&&!Device&&!LockHeld&&!ThreadActive);
 Build=26100;Cpus=8;Irql=0;FullOS=FirmwareMatch=1;RangesMissing=OverlappingRam=MutatePart=Mutated=0;
 MapCount=UnmapCount=FailMap=FailEntry=EntryStep=Freed=TimerStarts=TimerStops=Armed=0;Clock=1000000;
 memcpy(Fdt,OriginalFdt,sizeof(Fdt));memcpy(Toc,OriginalToc,sizeof(Toc));memcpy(Part,OriginalPart,sizeof(Part));memset(Irq,0,sizeof(Irq));
 memset(&Peer,0,sizeof(Peer));Peer.RemoteCid=8;Peer.RemoteClose=1;atomic_store(&StopThread,0);
 assert(DriverEntry((void*)1,(void*)1)==0&&Owner&&Timer&&Device&&MapCount==0);
 assert(G158FindSlots(Part,sizeof(Part),&Locations));Peer.State=&Owner->Data.State;
}
static void Finish(void){ClnUnload((void*)1);assert(!Owner&&!Timer&&!Device&&Freed==1&&MapCount==UnmapCount);NativeCases++;}
static void Ready(void)
{
 assert(Cmd(CLN_START,1)==0&&Response->Attempted&&Response->LastResult==1);
 for(unsigned i=0;i<100&&Owner->Data.State.Phase!=CL_READY;i++)Tick();
 assert(Owner->Data.State.Phase==CL_READY&&Owner->Data.Running&&Owner->Data.MapsLive==2&&!Owner->Data.SafeToUnload);
}
static void Sample(uint64_t id)
{
 uint64_t gen=Owner->Data.State.BatchesStarted+1;assert(Cmd(CLN_SAMPLE,id)==0&&Response->LastResult==1);
 for(unsigned i=0;i<100&&Owner->Data.State.BatchesCompleted<gen;i++)Tick();
 assert(Owner->Data.State.BatchesCompleted==gen&&Owner->Data.State.LastBatch.Complete&&Owner->Data.State.Phase==CL_READY);
}
static void Closed(uint64_t id)
{
 assert(Cmd(CLN_CLOSE,id)==0);
 for(unsigned i=0;i<1000&&Owner->Data.Running;i++)Tick();
 assert(Owner->Data.State.Phase==CL_CLOSED&&Owner->Data.Stopped&&Owner->Data.SafeToUnload&&!Owner->Data.MapsLive&&MapCount==UnmapCount);
 unsigned starts=TimerStarts,kicks=Peer.Kicks;Tick();assert(starts==TimerStarts&&kicks==Peer.Kicks);
}
static void Lifecycle(void)
{
 Reset();assert(Cmd(CLN_STATUS,0)==0&&Response->SafeToUnload&&!Response->Attempted&&!Response->MapCalls);
 Ready();Save("open.bin");for(uint64_t i=2;i<102;i++)Sample(i);Save("read-batch.bin");
 uint64_t tx=Owner->Data.State.TxFrames,started=Owner->Data.State.BatchesStarted;
 assert(Cmd(CLN_SAMPLE,101)==0&&Owner->Data.State.BatchesStarted==started); /* exact duplicate */
 assert(Cmd(CLN_CLOSE,101)==STATUS_INVALID_DEVICE_STATE); /* ID rebound to another action */
 assert(Cmd(CLN_SAMPLE,100)==STATUS_INVALID_DEVICE_STATE&&Cmd(CLN_SAMPLE,103)==STATUS_INVALID_DEVICE_STATE);
 assert(Call(CLN_SAMPLE,Owner->Data.Cookie^1,102,40,sizeof(*Response))==STATUS_INVALID_DEVICE_STATE);
 for(unsigned i=0;i<10000;i++)Tick(); /* no client handle or transport deadline */
 assert(Owner->Data.Running&&!Owner->Data.NativeFault&&Owner->Data.State.TxFrames<=tx+1);
 Sample(102);Closed(103);Save("closed.bin");assert(Cmd(CLN_CLOSE,103)==0&&Cmd(CLN_SAMPLE,104)==STATUS_INVALID_DEVICE_STATE);
 Finish();
 for(unsigned failure=1;failure<=4;failure++){
  Reset();FailMap=failure;assert(Cmd(CLN_START,1)==0&&Response->AdmissionCode&&Response->SafeToUnload&&!Response->MapsLive);
  assert(Peer.Kicks==0&&Owner->Data.State.TxWriteAttempts==0&&MapCount==UnmapCount+1);
  /* A failed map returned NULL; unmaps equal successful maps only. */
  MapCount--;Finish();
 }
 for(unsigned failure=0;failure<9;failure++){
  Reset();if(failure==0)FullOS=0;if(failure==1)FirmwareMatch=0;if(failure==2)Build=1;if(failure==3)Cpus=1;if(failure==4)Irql=1;
  if(failure==5)RangesMissing=1;if(failure==6)OverlappingRam=0x400000;if(failure==7)OverlappingRam=0x81a00000;if(failure==8)OverlappingRam=0x81d00000;
  assert(Cmd(CLN_START,1)==0&&Response->SafeToUnload&&Response->AdmissionCode&&MapCount==0);Finish();
 }
 for(unsigned failure=0;failure<5;failure++){
  Reset();if(failure==0)Fdt[0]^=1;if(failure==1)Toc[0]^=1;if(failure==2)Part[32]^=1;if(failure==3)Part[Locations.Descriptor+4]=8;if(failure==4)MutatePart=1;
  assert(Cmd(CLN_START,1)==0&&Response->SafeToUnload&&Response->AdmissionCode&&Peer.Kicks==0);if(!failure)Save("refused.bin");Finish();
 }
 Reset();Ready();Peer.Silent=1;assert(Cmd(CLN_SAMPLE,2)==0);
 for(unsigned i=0;i<5000&&Owner->Data.Running;i++)Tick();
 if(Owner->Data.State.Phase!=CL_CLOSED)fprintf(stderr,"timeout phase=%u fault=%u run=%u maps=%u ack=%u remoteClose=%u time=%llu since=%llu\n",Owner->Data.State.Phase,Owner->Data.State.Fault,Owner->Data.Running,Owner->Data.MapsLive,Owner->Data.State.CloseAcked,Owner->Data.State.RemoteClosed,(unsigned long long)Clock,(unsigned long long)Owner->Data.State.CloseSinceUs);
 assert(Owner->Data.State.Fault==CL_F_TIMEOUT&&Owner->Data.SafeToUnload&&Owner->Data.State.Phase==CL_CLOSED);Finish();
 Reset();Ready();Part[Locations.Descriptor+4]^=8;Tick();
 assert(Owner->Data.NativeFault&&Owner->Data.State.Phase==CL_FAILED&&Owner->Data.MapsLive==2&&!Owner->Data.SafeToUnload);Save("uncertain.bin");
 unsigned kicks=Peer.Kicks,reads=MapCount;for(unsigned i=0;i<10;i++)Tick();
 assert(kicks==Peer.Kicks&&reads==MapCount&&Cmd(CLN_SAMPLE,2)==STATUS_INVALID_DEVICE_STATE);Finish();
}
static void Dispatcher(void)
{
 Reset();uint64_t cookie=Owner->Data.Cookie;
 for(unsigned code=0;code<11;code++){
  ULONG c=(ULONG[]){CLN_STATUS,CLN_SNAPSHOT,CLN_START,CLN_SAMPLE,CLN_CLOSE,CLN_BOARD_FV,CLN_CHARGE_PULSE,CLN_STOP_PULSE,0x226a40,0x22eac0,0}[code];
  if(code>7){assert(Call(c,0,0,40,sizeof(*Response))==STATUS_INVALID_DEVICE_REQUEST);continue;}
  assert(Call(c,0,0,39,sizeof(*Response))==STATUS_INVALID_PARAMETER);
  assert(Call(c,0,0,41,sizeof(*Response))==STATUS_INVALID_PARAMETER);
  assert(Call(c,0,0,40,sizeof(*Response)-1)==STATUS_BUFFER_TOO_SMALL);
  assert(Call(c,0,0,40,sizeof(*Response)+1)==STATUS_BUFFER_TOO_SMALL);
 }
 assert(MapCount==0&&Owner->Data.Cookie==cookie&&!Owner->Data.LastCommandId);Finish();
 for(unsigned fail=1;fail<=9;fail++){
  FailEntry=fail;EntryStep=0;Freed=0;MapCount=UnmapCount=0;
  assert(DriverEntry((void*)1,(void*)1)<0&&!Owner&&!Timer&&!Device);
  assert(MapCount==0);NativeCases++;
 }
 FailEntry=0;
}
static void BoardControl(void)
{
 Reset();assert(Cmd(CLN_BOARD_FV,1)==STATUS_INVALID_DEVICE_STATE&&!Owner->Data.LastCommandId);
 Ready();Sample(2);uint64_t gen=Owner->Data.State.BatchesStarted+1;
 assert(Cmd(CLN_BOARD_FV,3)==0&&Response->LastResult==1);
 assert(Cmd(CLN_BOARD_FV,3)==0&&Owner->Data.State.BatchesStarted==gen); /* duplicate while pending */
 assert(Cmd(CLN_SAMPLE,3)==STATUS_INVALID_DEVICE_STATE);
 for(unsigned i=0;i<100&&Owner->Data.State.BatchesCompleted<gen;i++)Tick();
 CL_BATCH*b=&Owner->Data.State.LastBatch;
 assert(b->Kind==1&&b->Complete&&b->Battery.ControlAckMask==1024&&!b->Battery.ValueValidMask&&!b->Battery.VoltageMax&&Peer.Sets==1);
 Save("board-fv.bin");assert(Cmd(CLN_BOARD_FV,4)==0&&Response->LastResult==2&&Peer.Sets==1);
 Sample(5);assert(Owner->Data.State.LastBatch.Kind==0&&Peer.Sets==1);Closed(6);Finish();
 Reset();Ready();Peer.ServiceReject=1;assert(Cmd(CLN_BOARD_FV,2)==0);
 for(unsigned i=0;i<100&&!Owner->Data.State.LastBatch.Complete;i++)Tick();
 assert(Owner->Data.State.LastBatch.Battery.ServiceRejectedMask==1024&&!Owner->Data.State.LastBatch.Battery.ControlAckMask);
 assert(Cmd(CLN_BOARD_FV,3)==0&&Response->LastResult==2&&Peer.Sets==1);Closed(4);Finish();
 Reset();Ready();Peer.Silent=1;assert(Cmd(CLN_BOARD_FV,2)==0);
 for(unsigned i=0;i<5000&&Owner->Data.Running;i++)Tick();
 assert(Owner->Data.State.Fault==CL_F_TIMEOUT&&Owner->Data.State.RpcUncertain&&Peer.Sets==1);
 assert(Cmd(CLN_BOARD_FV,3)==STATUS_INVALID_DEVICE_STATE);Save("board-fv-timeout.bin");Finish();
}
static void NativeFv(uint64_t id)
{
 assert(Cmd(CLN_BOARD_FV,id)==0&&Response->LastResult==1);
 for(unsigned i=0;i<100&&!Owner->Data.State.BoardFvAcked;i++)Tick();
 assert(Owner->Data.State.BoardFvAcked&&!Owner->Data.State.BatchActive&&Peer.Sets==1);
}
static void NativeEnabled(uint64_t id)
{
 assert(Cmd(CLN_CHARGE_PULSE,id)==0&&Response->LastResult==1);
 assert(Cmd(CLN_CHARGE_PULSE,id)==0&&Peer.Enables<=1);
 for(unsigned i=0;i<100&&!Owner->Data.State.PulseEnableAcked;i++)Tick();
 assert(Owner->Data.State.PulseEnableAcked&&Owner->Data.State.BatchActive&&Peer.Enables==1&&!Peer.Disables);
}
static void PulseControl(void)
{
 Reset();assert(Cmd(CLN_CHARGE_PULSE,1)==STATUS_INVALID_DEVICE_STATE&&!Owner->Data.LastCommandId);
 Ready();assert(Cmd(CLN_CHARGE_PULSE,2)==0&&Response->LastResult==2&&!Peer.Enables);
 NativeFv(3);NativeEnabled(4);Save("pulse-active.bin");
 uint64_t until=Owner->Data.State.PulseUntilUs;
 Clock=(until-100000)*10;Tick();assert(!Peer.Disables&&Owner->Data.State.BatchActive);
 /* No user-mode request, client handle, USB or host timer drives normal off. */
 Clock=until*10;
 for(unsigned i=0;i<100&&Owner->Data.State.BatchActive;i++)Tick();
 assert(Peer.Enables==1&&Peer.Disables==1&&Peer.DisabledAt>=until&&Peer.Sets==3);
 assert(Owner->Data.State.LastBatch.Kind==2&&Owner->Data.State.LastBatch.Battery.ControlAckMask==6144&&Owner->Data.State.PulseDisableAcked);
 Save("pulse-complete.bin");assert(Cmd(CLN_CHARGE_PULSE,5)==0&&Response->LastResult==2&&Peer.Sets==3);
 Sample(6);Closed(7);Finish();
 Reset();Ready();NativeFv(2);NativeEnabled(3);until=Owner->Data.State.PulseUntilUs;
 Clock=(until+CL_BATCH_US*2)*10; /* delayed callback still sends off */
 for(unsigned i=0;i<100&&Owner->Data.State.BatchActive;i++)Tick();
 assert(Peer.Enables==1&&Peer.Disables==1&&Owner->Data.State.PulseDisableAcked&&!Owner->Data.State.Fault);
 Save("pulse-late-timer.bin");Closed(4);Finish();
 for(unsigned close=0;close<2;close++){
  Reset();Ready();NativeFv(2);NativeEnabled(3);until=Owner->Data.State.PulseUntilUs;
  assert(Cmd(close?CLN_CLOSE:CLN_STOP_PULSE,4)==0&&Response->LastResult==1);
  for(unsigned i=0;i<100&&(close?Owner->Data.Running:Owner->Data.State.BatchActive);i++)Tick();
  assert(Peer.Enables==1&&Peer.Disables==1&&Peer.DisabledAt<until&&Owner->Data.State.PulseDisableAcked);
  if(close){assert(Owner->Data.SafeToUnload&&!Owner->Data.MapsLive);Save("pulse-close.bin");}
  else {Save("pulse-stop.bin");Closed(5);}
  Finish();
 }
 for(unsigned disable=0;disable<2;disable++){
  Reset();Ready();NativeFv(2);Peer.RejectEnable=!disable;Peer.RejectDisable=disable;
  assert(Cmd(CLN_CHARGE_PULSE,3)==0);
  for(unsigned i=0;i<100&&!Owner->Data.State.PulseEnableAcked&&Owner->Data.State.BatchActive;i++)Tick();
  if(disable)Clock=Owner->Data.State.PulseUntilUs*10;
  for(unsigned i=0;i<100&&Owner->Data.State.BatchActive;i++)Tick();
  assert(Peer.Enables==1&&Peer.Disables==1&&Owner->Data.State.LastBatch.Complete);
  assert(Owner->Data.State.LastBatch.Battery.ServiceRejectedMask==(1u<<(disable?CL_DISABLE_QUERY:CL_ENABLE_QUERY)));
  Save(disable?"pulse-reject-disable.bin":"pulse-reject-enable.bin");Closed(4);Finish();
 }
 for(unsigned disable=0;disable<2;disable++){
  Reset();Ready();NativeFv(2);
  if(disable){NativeEnabled(3);Peer.Silent=1;Clock=Owner->Data.State.PulseUntilUs*10;}
  else {Peer.Silent=1;assert(Cmd(CLN_CHARGE_PULSE,3)==0);}
  for(unsigned i=0;i<5000&&Owner->Data.Running;i++)Tick();
  assert(Owner->Data.State.RpcUncertain&&Owner->Data.State.Fault==CL_F_TIMEOUT&&Peer.Enables==1&&Peer.Disables==disable);
  assert(Cmd(CLN_STOP_PULSE,4)==STATUS_INVALID_DEVICE_STATE);
  Save(disable?"pulse-disable-timeout.bin":"pulse-enable-timeout.bin");Finish();
 }
}
static void*Background(void*arg)
{
 (void)arg;while(!atomic_load(&StopThread)){WdfObjectAcquireLock((void*)3);if(Owner&&Timer)ClnTimer(Timer);WdfObjectReleaseLock((void*)3);sched_yield();}return NULL;
}
static void ConcurrentShutdown(void)
{
 for(unsigned round=0;round<50;round++){
  Reset();Ready();assert(!pthread_create(&TimerThread,NULL,Background,NULL));ThreadActive=1;
  for(unsigned i=0;i<30;i++){
   assert(Cmd(CLN_STATUS,0)==0); /* same actual control callback serialized with timer */
   sched_yield();
  }
  Finish();assert(TimerStops==1&&!ThreadActive);
 }
}
int main(int argc,char**argv)
{
 assert(argc==5);ResultFolder=argv[4];File(argv[1],OriginalFdt,sizeof(OriginalFdt));File(argv[2],OriginalToc,sizeof(OriginalToc));File(argv[3],OriginalPart,sizeof(OriginalPart));
 Response=calloc(1,sizeof(*Response));assert(Response);Lifecycle();Dispatcher();ConcurrentShutdown();BoardControl();PulseControl();free(Response);
 printf("{\"passed\":true,\"cases\":%u,\"actual_adapter_source\":true,\"threaded_shutdown_rounds\":50,\"native_operations\":0}\n",NativeCases);return 0;
}
