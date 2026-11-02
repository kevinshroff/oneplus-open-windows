/* Test-only kernel services: every MMIO access aborts this refusal suite. */
#include "g58_hardware.c"
static ULONG FakeProcessors=8,FakeIrql,FirmwareOK=1,Maps,Unmaps,MMIO;
ULONG KeQueryActiveProcessorCountEx(ULONG g){assert(g==ALL_PROCESSOR_GROUPS);return FakeProcessors;}
ULONG KeGetCurrentIrql(void){return FakeIrql;}
NTSTATUS RtlGetVersion(RTL_OSVERSIONINFOW*v){v->dwBuildNumber=26100;return 0;}
NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG a,ULONG b,void*out,ULONG size,ULONG*n){assert(a==0x41435049&&b==0x54445344&&size==sizeof(G58ExpectedDsdt));memcpy(out,G58ExpectedDsdt,size);*n=size;if(!FirmwareOK)((uint8_t*)out)[0]^=1;return 0;}
ULONGLONG KeQueryInterruptTime(void){return 123456;}
LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER*f){LARGE_INTEGER n={123456789};if(f)f->QuadPart=19200000;return n;}
PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS a,SIZE_T n,ULONG mode){(void)a;(void)n;(void)mode;Maps++;return NULL;}
VOID MmUnmapIoSpace(PVOID p,SIZE_T n){(void)p;(void)n;Unmaps++;assert(!"unexpected mapping to unmap");}
ULONG TestRead(PULONG p){(void)p;MMIO++;assert(!"refusal path accessed MMIO");return 0;}
VOID TestWrite(PULONG p,ULONG v){(void)p;(void)v;MMIO++;assert(!"refusal path wrote MMIO");}
VOID KeStallExecutionProcessor(ULONG n){(void)n;assert(!"refusal path waited for hardware");}
NTSTATUS KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*t){(void)mode;(void)alert;(void)t;assert(!"refusal path delayed hardware");return 0;}
static unsigned Present,Cases;
static int DevicePresent(void*x){assert(x==&Present);return Present!=0;}
static int Stop(void*x){(void)x;return 0;}
static int Stage(void*x,const uint8_t*b,uint32_t n,uint64_t at){(void)x;(void)b;(void)n;(void)at;assert(!"refusal submitted input");return 0;}
static int Publish(void*x,const uint8_t*b,uint32_t n){(void)x;(void)b;(void)n;assert(!"refusal submitted input");return 0;}
static const G58_STREAM_IO Stream={&Present,Stage,Publish,Stop,DevicePresent};
static void Reset(void){FakeProcessors=8;FakeIrql=0;FirmwareOK=Present=1;Maps=Unmaps=MMIO=0;G58ObserverAttempts=G58ObserverFault=G58OffPmicVerified=G58TrialUsed=G58MapCalls=0;}
static void NoIO(unsigned maps){assert(!MMIO&&!Unmaps&&Maps==maps);Cases++;}
int main(void){G58_PMIC p;G58_SNAPSHOT s;static G58_TRIAL t;
 for(unsigned before=0;before<=2;before++)for(unsigned fault=0;fault<=1;fault++){
  Reset();Present=0;G58ObserverAttempts=before;G58ObserverFault=fault;G58HardwarePmic(&p,&Stream);assert(p.Observer.Code==1009&&!p.Attempt&&!p.FixedRegistersUnchanged&&G58ObserverAttempts==(LONG)before&&G58ObserverFault==(LONG)fault);NoIO(0);
 }
 Reset();Present=0;assert(G58HardwareSnapshot(&s,&Stream)==STATUS_DEVICE_REMOVED);NoIO(0);
 Reset();assert(G58HardwareSnapshot(&s,NULL)==STATUS_DEVICE_REMOVED);NoIO(0);
 for(unsigned bad=0;bad<3;bad++){
  Reset();if(bad==0)FirmwareOK=0;if(bad==1)FakeProcessors=7;if(bad==2)FakeIrql=2;assert(G58HardwareSnapshot(&s,&Stream)==STATUS_NOT_SUPPORTED);NoIO(0);
  G58HardwarePmic(&p,&Stream);assert(p.Observer.Code==1004&&p.Attempt==1&&G58ObserverFault==1);NoIO(0);
 }
 Reset();G58ObserverFault=1;G58HardwarePmic(&p,&Stream);assert(p.Observer.Code==1001&&!G58ObserverAttempts);NoIO(0);
 Reset();G58ObserverAttempts=2;G58HardwarePmic(&p,&Stream);assert(p.Observer.Code==1002&&G58ObserverAttempts==2);NoIO(0);
 Reset();Present=0;G58HardwareTrial(&t,&Stream);assert(t.Trial.Power.Code==1008&&!t.Attempt&&!G58TrialUsed);NoIO(0);
 Reset();G58HardwareTrial(&t,NULL);assert(t.Trial.Power.Code==1008&&!t.Attempt&&!G58TrialUsed);NoIO(0);
 Reset();G58TrialUsed=1;G58HardwareTrial(&t,&Stream);assert(t.Trial.Power.Code==1002&&!t.Attempt);NoIO(0);
 for(unsigned bad=0;bad<4;bad++){
  Reset();G58ObserverAttempts=1;G58OffPmicVerified=1;if(bad==0)G58ObserverAttempts=0;if(bad==1)G58ObserverAttempts=2;if(bad==2)G58OffPmicVerified=0;if(bad==3)G58ObserverFault=1;G58HardwareTrial(&t,&Stream);assert(t.Trial.Power.Code==1003&&t.Attempt==1);NoIO(0);
 }
 for(unsigned bad=0;bad<3;bad++){
  Reset();G58ObserverAttempts=1;G58OffPmicVerified=1;if(bad==0)FirmwareOK=0;if(bad==1)FakeProcessors=7;if(bad==2)FakeIrql=2;G58HardwareTrial(&t,&Stream);assert(t.Trial.Power.Code==1004&&t.Attempt==1);NoIO(0);
 }
 Reset();assert(G58HardwareSnapshot(&s,&Stream)==STATUS_INSUFFICIENT_RESOURCES);NoIO(1);
 Reset();G58HardwarePmic(&p,&Stream);assert(p.Observer.Code==1005&&p.Attempt==1&&G58ObserverFault==1);NoIO(1);
 Reset();G58ObserverAttempts=1;G58OffPmicVerified=1;G58HardwareTrial(&t,&Stream);assert(t.Trial.Power.Code==1005&&t.Attempt==1);NoIO(1);
 printf("{\"passed\":true,\"cases\":%u,\"actual_entire_native_adapter_compiled\":true,\"entry_snapshot_PMIC_refusals_no_MMIO\":true,\"gone_PMIC_preserves_attempt_budget_and_fault_state\":true,\"model_mapping_failure_before_register_access\":true}\n",Cases);return 0;
}
