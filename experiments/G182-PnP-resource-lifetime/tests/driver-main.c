static unsigned Cases;
static MODEL_RESOURCES Raw,Translated;
static void Resources(void){memset(&Raw,0,sizeof(Raw));Raw.Count=20;Raw.NullIndex=UINT32_MAX;for(unsigned i=0;i<20;i++){Raw.Descriptors[i]=(CM_PARTIAL_RESOURCE_DESCRIPTOR){3,1,OP182Expected[i].Write?0:1,{{{(LONGLONG)OP182Expected[i].Base},OP182Expected[i].Bytes}}};}Translated=Raw;}
static void Reset(void){assert(!Device&&!LiveMaps&&!LockHeld);Build=26100;Cpus=8;Irql=VersionFailure=FirmwareFailure=BadFirmware=BadFirmwareSize=MissingRam=MalformedRam=OverflowRam=0;RamAt=0;MapAttempts=UnmapAttempts=FailMap=EntrySteps=FailEntry=0;Resources();}
static void Create(void){assert(DriverEntry((void*)1,(void*)1)==0);assert(Op182Add((void*)1,(void*)1)==0&&Device&&Device->Lock);}
static void Destroy(void){assert(!LiveMaps&&!LockHeld);if(Device){if(Device->Lock){assert(!pthread_mutex_destroy(&Device->Lock->Mutex));free(Device->Lock);}free(Device);Device=NULL;}}
static OP182_STATUS_DATA Status(void){MODEL_REQUEST r={0};r.Capacity=sizeof(r.Buffer);*(OP182_REQUEST*)r.Buffer=(OP182_REQUEST){32,1,OP182_MAGIC,0,0,0};Op182Control(Device,&r,112,32,OP182_STATUS);assert(r.Status==0&&r.Bytes==112);OP182_STATUS_DATA s;memcpy(&s,r.Buffer,sizeof(s));assert(s.Size==112&&s.Version==1&&s.Magic==OP182_MAGIC&&!s.ProducerQualified);assert(!s.D0Active||(s.Prepared&&s.MapCount==20));assert(s.Prepared||!s.MapCount);return s;}
static void Lifecycle(void){
 Reset();Create();assert(Op182D0Entry(Device,0)==STATUS_DEVICE_NOT_READY);assert(!Status().D0Active);
 assert(Op182Prepare(Device,&Raw,&Translated)==0);assert(Status().MapCount==20&&!Status().D0Active);unsigned before=MapAttempts;assert(Op182Prepare(Device,&Raw,&Translated)==STATUS_INVALID_DEVICE_STATE&&MapAttempts==before&&Status().Prepared);
 assert(Op182D0Entry(Device,0)==0&&Status().D0Epoch==1&&Status().D0Active);assert(Op182D0Exit(Device,0)==0&&!Status().D0Active&&Status().Prepared);assert(Op182D0Entry(Device,0)==0&&Status().D0Epoch==2);assert(Op182D0Exit(Device,0)==0);assert(Op182Release(Device,&Translated)==0);assert(Status().MapCount==0&&Status().ReleaseCalls==1&&MapAttempts==UnmapAttempts);
 assert(Op182Prepare(Device,&Raw,&Translated)==0&&Status().PrepareEpoch==2);assert(Op182D0Entry(Device,0)==0);assert(Op182Release(Device,&Translated)==0&&!Status().D0Active);Destroy();Cases++;
 for(unsigned n=1;n<=20;n++){Reset();Create();FailMap=n;assert(Op182Prepare(Device,&Raw,&Translated)==STATUS_INSUFFICIENT_RESOURCES);assert(!Status().Prepared&&!Status().D0Active&&!Status().MapCount&&!LiveMaps&&MapAttempts==n&&UnmapAttempts==n-1);assert(Op182Release(Device,&Translated)==0);Destroy();Cases++;}
 for(unsigned n=0;n<20;n++){Reset();Create();RamAt=OP182Expected[n].Base;assert(Op182Prepare(Device,&Raw,&Translated)<0&&!MapAttempts&&!Status().Prepared);Destroy();Cases++;}
 for(unsigned n=0;n<9;n++){Reset();Create();if(n==0)Build=1;if(n==1)Cpus=1;if(n==2)BadFirmware=1;if(n==3)BadFirmwareSize=1;if(n==4)FirmwareFailure=1;if(n==5)VersionFailure=1;if(n==6)MissingRam=1;if(n==7)MalformedRam=1;if(n==8)OverflowRam=1;assert(Op182Prepare(Device,&Raw,&Translated)<0&&!MapAttempts&&!LiveMaps);Destroy();Cases++;}
 /* A prior good prepare must not mask a subsequent failed version query. */
 Reset();Create();assert(Op182Prepare(Device,&Raw,&Translated)==0);assert(Op182Release(Device,&Translated)==0);VersionFailure=1;before=MapAttempts;assert(Op182Prepare(Device,&Raw,&Translated)<0&&MapAttempts==before&&!Status().Prepared);Destroy();Cases++;
 for(unsigned n=0;n<8;n++){Reset();Create();if(n==0)Raw.Count=19;if(n==1)Translated.Count=21;if(n==2)Raw.NullIndex=0;if(n==3)Translated.NullIndex=19;if(n==4)Raw.Descriptors[0].Type=1;if(n==5)Translated.Descriptors[0].Flags=16;if(n==6)Raw.Descriptors[0].u.Memory.Start.QuadPart++;if(n==7)Translated.Descriptors[9].u.Memory.Length--;assert(Op182Prepare(Device,&Raw,&Translated)<0&&!MapAttempts);Destroy();Cases++;}
 Reset();Create();OP182_CONTEXT*c=Op182Context(Device);c->Data.PrepareEpoch=UINT64_MAX;assert(Op182Prepare(Device,&Raw,&Translated)==STATUS_INTEGER_OVERFLOW&&!MapAttempts);Destroy();Cases++;
 Reset();Create();c=Op182Context(Device);c->Data.MapCalls=UINT64_MAX-10;assert(Op182Prepare(Device,&Raw,&Translated)==STATUS_INTEGER_OVERFLOW&&!MapAttempts);Destroy();Cases++;
 Reset();Create();c=Op182Context(Device);assert(Op182Prepare(Device,&Raw,&Translated)==0);c->Data.D0Epoch=UINT64_MAX;assert(Op182D0Entry(Device,0)<0&&!Status().D0Active);assert(Op182Release(Device,&Translated)==0);Destroy();Cases++;
}
static void Dispatcher(void){
 Reset();Create();
 for(unsigned n=0;n<11;n++){
  MODEL_REQUEST r={0};r.Capacity=sizeof(r.Buffer);OP182_REQUEST*q=(void*)r.Buffer;*q=(OP182_REQUEST){32,1,OP182_MAGIC,0,0,0};size_t in=32,out=112;ULONG code=OP182_STATUS;
  if(n==0)q->Size=31;if(n==1)q->Version=2;if(n==2)q->Magic^=1;if(n==3)q->Nonce=1;if(n==4)q->Count=1;if(n==5)q->Reserved=1;if(n==6)in=31;if(n==7)out=111;if(n==8)code++;if(n==9)r.InputStatus=-10;if(n==10)r.OutputStatus=-11;
  Op182Control(Device,&r,out,in,code);assert(r.Status<0&&r.Bytes==0&&!MapAttempts);Cases++;
 }
 UNICODE_STRING name={2,L"x"};MODEL_REQUEST r={0};Op182FileCreate(Device,&r,&name);assert(r.Status==STATUS_OBJECT_NAME_INVALID);name.Length=0;Op182FileCreate(Device,&r,&name);assert(r.Status==0);Cases++;Destroy();
 for(unsigned n=1;n<=6;n++){Reset();FailEntry=n;NTSTATUS s=DriverEntry((void*)1,(void*)1);if(NT_SUCCESS(s))s=Op182Add((void*)1,(void*)1);assert(s<0&&!MapAttempts);Destroy();Cases++;}
}
static atomic_int Finished;static uint64_t Reads;
static void*PowerThread(void*p){(void)p;for(unsigned i=0;i<500;i++){assert(Op182Prepare(Device,&Raw,&Translated)==0);assert(Op182D0Entry(Device,0)==0);assert(Op182D0Exit(Device,0)==0);assert(Op182Release(Device,&Translated)==0);}atomic_store(&Finished,1);return NULL;}
static void*StatusThread(void*p){(void)p;uint64_t prior=0;while(!atomic_load(&Finished)){OP182_STATUS_DATA s=Status();assert(s.D0Epoch>=prior);prior=s.D0Epoch;Reads++;}return NULL;}
int main(void){Lifecycle();Dispatcher();Reset();Create();pthread_t a,b;atomic_store(&Finished,0);assert(!pthread_create(&a,NULL,PowerThread,NULL)&&!pthread_create(&b,NULL,StatusThread,NULL));assert(!pthread_join(a,NULL)&&!pthread_join(b,NULL));assert(!LiveMaps&&MapAttempts==10000&&UnmapAttempts==10000);Destroy();Cases++;printf("{\"passed\":true,\"actual_driver_cases\":%u,\"concurrent_lifecycles\":500,\"status_reads\":%llu,\"mapping_writes\":0,\"native_operations\":0}\n",Cases,(unsigned long long)Reads);return 0;}
