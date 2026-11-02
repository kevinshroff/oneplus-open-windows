/* Calls the actual callback table. Hardware leases and power semantics remain
 * explicit models; this test never creates a Windows battery device. */
#include "battery_miniclass.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
static unsigned Checks;
#define CHECK(x) do {assert(x);Checks++;} while(0)
static OPEN_BATTERY_PAIR Pair;
static OPEN_BATTERY_DEVICE Device[2];
static BATTERY_MINIPORT_INFO Info[2];
static OB_BATCH Batch(uint64_t sequence) {
 OB_BATCH b={0};b.OwnerEpoch=1;b.Sequence=sequence;b.OwnerQualified=b.Complete=1;
 b.BeginUs=999900;b.EndUs=1000000;
 for(unsigned i=0;i<2;i++) {
  uint32_t w[10]={0x6002,0x602,0x200,3047+i*13,3500,0x181,500,2000,8,25};
  memcpy(b.Words[i],w,sizeof(w));b.PowerKnown[i]=1;b.PowerState[i]=OB_DISCHARGING;
 }
 return b;
}
static ULONG Tag(unsigned i) {
 ULONG tag=0;assert(Info[i].QueryTag(Info[i].Context,&tag)==STATUS_SUCCESS&&tag);return tag;
}
static void NotifyOutsideLock(ULONG bits) {
 CHECK(!MockLockDepth()&&KeGetCurrentIrql()==PASSIVE_LEVEL);
 for(unsigned i=0;i<2;i++)if(bits&(1u<<i)) {
  BATTERY_STATUS s;ULONG tag=Tag(i);
  CHECK(Info[i].QueryStatus(Info[i].Context,tag,&s)==STATUS_SUCCESS);
 }
}
static _Atomic int Start,Done;
static _Atomic unsigned ReaderCalls;
static void *Publisher(void *unused) {
 (void)unused;while(!atomic_load(&Start)){}
 for(unsigned k=0;k<25000;k++) {
  OB_BATCH b=Batch(100+k);ULONG n=0;
  for(unsigned i=0;i<2;i++){b.Words[i][6]=k%1000;b.Words[i][4]=3000+k%1000;}
  assert(OpenBatteryPublish(&Pair,&b,&n)==OB_OK&&!n);
 }
 atomic_store(&Done,1);return 0;
}
static void *Reader(void *arg) {
 unsigned i=(unsigned)(uintptr_t)arg,k=0;while(!atomic_load(&Start)){}
 do {
  BATTERY_STATUS s;ULONG tag=Tag(i);
  assert(Info[i].QueryStatus(Info[i].Context,tag,&s)==STATUS_SUCCESS);
  assert(s.PowerState==OB_DISCHARGING&&s.Capacity<1000&&s.Voltage==3000+s.Capacity&&s.Rate==(LONG)BATTERY_UNKNOWN_RATE);
  assert(!MockLockDepth()&&KeGetCurrentIrql()==PASSIVE_LEVEL);
  atomic_fetch_add(&ReaderCalls,1);k++;
 }while(k<10000||!atomic_load(&Done));return 0;
}
int main(void) {
 ULONG n=0,tag=9,returned=9;BATTERY_STATUS status;BATTERY_INFORMATION battery;
 OB_BATCH b=Batch(1);MockSetTimeUs(1000000);OpenBatteryInitialize(&Pair);
 for(unsigned i=0;i<2;i++) {
  Device[i]=(OPEN_BATTERY_DEVICE){&Pair,i};CHECK(OpenBatteryCallbacks(Device+i,Info+i)==STATUS_SUCCESS);
  CHECK(Info[i].MajorVersion==1&&Info[i].MinorVersion==0&&Info[i].Context==Device+i&&!Info[i].Pdo&&!Info[i].DeviceName);
 }
 CHECK(Info[0].QueryTag(Info[0].Context,&tag)==STATUS_NO_SUCH_DEVICE&&!tag);
 CHECK(OpenBatteryBeginOwner(&Pair,1,&n)==OB_OK&&!n);
 CHECK(OpenBatteryPublish(&Pair,&b,&n)==OB_OK&&n==3);tag=Tag(0);NotifyOutsideLock(n);
 CHECK(Info[0].QueryStatus(Info[0].Context,tag,&status)==STATUS_SUCCESS&&status.Capacity==500&&status.Voltage==3500&&status.Rate==(LONG)BATTERY_UNKNOWN_RATE);
 CHECK(Info[0].QueryInformation(Info[0].Context,tag,BatteryInformation,0,&battery,sizeof(battery),&returned)==STATUS_SUCCESS&&returned==sizeof(battery));
 CHECK(battery.Capabilities==(BATTERY_SYSTEM_BATTERY|BATTERY_CAPACITY_RELATIVE)&&battery.Technology==1&&!memcmp(battery.Chemistry,"UNKN",4)&&battery.DesignedCapacity==BATTERY_UNKNOWN_CAPACITY&&battery.FullChargedCapacity==2000&&battery.DefaultAlert1==BATTERY_UNKNOWN_CAPACITY);
 unsigned char buffer[128],before[128];memset(buffer,0x5a,sizeof(buffer));memcpy(before,buffer,sizeof(buffer));returned=9;
 CHECK(Info[0].QueryInformation(Info[0].Context,tag,BatteryInformation,0,buffer,sizeof(battery)-1,&returned)==STATUS_BUFFER_TOO_SMALL&&!returned&&!memcmp(buffer,before,sizeof(buffer)));
 CHECK(Info[0].QueryInformation(Info[0].Context,tag,BatteryInformation,0,0,sizeof(battery),&returned)==STATUS_INVALID_PARAMETER&&!returned);
 ULONG temperature=0;
 CHECK(Info[1].QueryInformation(Info[1].Context,tag,BatteryTemperature,0,&temperature,4,&returned)==STATUS_SUCCESS&&temperature==3060&&returned==4);
 CHECK(Info[0].QueryInformation(Info[0].Context,tag,BatteryEstimatedTime,-100,&temperature,4,&returned)==STATUS_SUCCESS&&temperature==BATTERY_UNKNOWN_TIME);
 WCHAR name[40];CHECK(Info[1].QueryInformation(Info[1].Context,tag,BatteryDeviceName,0,name,sizeof(name),&returned)==STATUS_SUCCESS&&returned==56&&name[26]=='1'&&!name[27]);
 CHECK(Info[0].QueryInformation(Info[0].Context,tag,BatteryGranularityInformation,0,buffer,sizeof(buffer),&returned)==STATUS_INVALID_DEVICE_REQUEST&&!returned);
 CHECK(Info[0].QueryInformation(Info[0].Context,tag,(BATTERY_QUERY_INFORMATION_LEVEL)999,0,buffer,sizeof(buffer),&returned)==STATUS_INVALID_PARAMETER&&!returned);
 CHECK(Info[0].SetInformation(Info[0].Context,tag,BatteryCharge,0)==STATUS_INVALID_DEVICE_REQUEST);
 memset(&status,0x5a,sizeof(status));CHECK(Info[0].QueryStatus(Info[0].Context,tag+1,&status)==STATUS_NO_SUCH_DEVICE&&!status.PowerState&&!status.Capacity&&!status.Voltage&&!status.Rate);
 BATTERY_NOTIFY threshold={OB_CHARGING,0,2000};CHECK(Info[0].SetStatusNotify(Info[0].Context,tag,&threshold)==STATUS_SUCCESS);
 CHECK(OpenBatteryTick(&Pair,&n)==OB_OK&&n==1);NotifyOutsideLock(n);
 CHECK(OpenBatteryTick(&Pair,&n)==OB_OK&&!n);
 b=Batch(2);b.PowerKnown[0]=b.PowerState[0]=0;CHECK(OpenBatteryPublish(&Pair,&b,&n)==OB_OK&&n==1);
 CHECK(Info[0].QueryStatus(Info[0].Context,tag,&status)==STATUS_DEVICE_NOT_READY);
 CHECK(Info[0].SetStatusNotify(Info[0].Context,tag,&threshold)==STATUS_NOT_SUPPORTED);
 b=Batch(3);b.RateKnown[0]=1;b.Words[0][8]=65536-123;CHECK(OpenBatteryPublish(&Pair,&b,&n)==OB_OK&&n==1);
 CHECK(Info[0].QueryStatus(Info[0].Context,tag,&status)==STATUS_SUCCESS&&status.Rate==-123);
 b=Batch(4);b.PowerState[0]=OB_CHARGING;b.RateKnown[0]=1;b.Words[0][8]=123;CHECK(OpenBatteryPublish(&Pair,&b,&n)==OB_OK&&n==1);
 CHECK(Info[0].QueryStatus(Info[0].Context,tag,&status)==STATUS_SUCCESS&&status.Rate==123);
 b=Batch(5);b.PowerState[0]=0;b.Words[0][8]=0;CHECK(OpenBatteryPublish(&Pair,&b,&n)==OB_OK&&n==1);NotifyOutsideLock(n);
 CHECK(Info[0].DisableStatusNotify(Info[0].Context)==STATUS_SUCCESS);
 MockSetIrql(DISPATCH_LEVEL);
 CHECK(Info[0].QueryTag(Info[0].Context,&returned)==STATUS_INVALID_PARAMETER&&!returned);
 CHECK(Info[0].QueryStatus(Info[0].Context,tag,&status)==STATUS_INVALID_PARAMETER);
 CHECK(Info[0].QueryInformation(Info[0].Context,tag,BatteryInformation,0,buffer,sizeof(buffer),&returned)==STATUS_INVALID_PARAMETER);
 CHECK(Info[0].SetStatusNotify(Info[0].Context,tag,&threshold)==STATUS_INVALID_PARAMETER);
 CHECK(Info[0].DisableStatusNotify(Info[0].Context)==STATUS_INVALID_PARAMETER);
 CHECK(Info[0].SetInformation(Info[0].Context,tag,BatteryCharge,0)==STATUS_INVALID_PARAMETER);
 CHECK(OpenBatteryPublish(&Pair,&b,&n)==OB_ARGUMENT&&!n);
 CHECK(OpenBatteryInvalidate(&Pair,&n)==OB_ARGUMENT&&!n);
 CHECK(OpenBatteryTick(&Pair,&n)==OB_ARGUMENT&&!n);
 MockSetIrql(PASSIVE_LEVEL);
 MockSetTimeUs(1000000+OB_MAX_AGE_US+1);CHECK(Info[0].QueryTag(Info[0].Context,&returned)==STATUS_NO_SUCH_DEVICE&&!returned);
 CHECK(OpenBatteryTick(&Pair,&n)==OB_NO_DEVICE&&n==3);
 MockSetTimeUs(1000000);b=Batch(6);CHECK(OpenBatteryPublish(&Pair,&b,&n)==OB_OK&&n==3&&Tag(0)!=tag);tag=Tag(0);
 CHECK(Info[0].QueryStatus(Info[0].Context,tag-1,&status)==STATUS_NO_SUCH_DEVICE);
 CHECK(OpenBatteryInvalidate(&Pair,&n)==OB_OK&&n==3);
 CHECK(Info[0].QueryStatus(Info[0].Context,tag,&status)==STATUS_NO_SUCH_DEVICE);
 CHECK(OpenBatteryBeginOwner(&Pair,2,&n)==OB_OK&&!n);
 b=Batch(1);b.OwnerEpoch=2;CHECK(OpenBatteryPublish(&Pair,&b,&n)==OB_OK&&n==3);
 CHECK(OpenBatteryBeginOwner(&Pair,1,&n)==OB_OLD_OWNER&&!n);
 CHECK(OpenBatteryBeginOwner(&Pair,3,&n)==OB_OK&&n==3);
 /* Use a fresh cache for the concurrent publish/query exercise. No object
  * destruction races are modeled or claimed here. */
 MockDestroyMutex(&Pair.Lock);OpenBatteryInitialize(&Pair);
 CHECK(OpenBatteryBeginOwner(&Pair,1,&n)==OB_OK);
 b=Batch(1);for(unsigned i=0;i<2;i++){b.Words[i][6]=0;b.Words[i][4]=3000;}
 CHECK(OpenBatteryPublish(&Pair,&b,&n)==OB_OK&&n==3);
 pthread_t publisher,readers[4];CHECK(!pthread_create(&publisher,0,Publisher,0));
 for(unsigned i=0;i<4;i++)CHECK(!pthread_create(readers+i,0,Reader,(void*)(uintptr_t)(i%2)));
 atomic_store(&Start,1);CHECK(!pthread_join(publisher,0));for(unsigned i=0;i<4;i++)CHECK(!pthread_join(readers[i],0));
 CHECK(atomic_load(&ReaderCalls)>=40000);MockDestroyMutex(&Pair.Lock);
 printf("{\"passed\":true,\"callback_checks\":%u,\"concurrent_publishes\":25000,\"concurrent_status_queries\":%u,\"actual_WDK_and_host_layout_compared_separately\":true,\"modeled_kernel_lock_IRQL_time_owner_power\":true,\"native_operations\":0}\n",Checks,atomic_load(&ReaderCalls));
 return 0;
}
