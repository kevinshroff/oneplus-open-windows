/* SPDX-License-Identifier: MIT */
#include "battery_miniclass.h"
static uint64_t NowUs(void){return KeQueryInterruptTime()/10;}
static int Valid(const OPEN_BATTERY_DEVICE *d)
{return KeGetCurrentIrql()==PASSIVE_LEVEL&&d&&d->Pair&&d->Gauge<2;}
static NTSTATUS Convert(int rc)
{
 switch(rc){case OB_OK:return STATUS_SUCCESS;case OB_NO_DEVICE:return STATUS_NO_SUCH_DEVICE;
 case OB_NOT_READY:return STATUS_DEVICE_NOT_READY;default:return STATUS_INVALID_PARAMETER;}
}
static int Reading(OPEN_BATTERY_DEVICE *d,ULONG tag,OB_READING *r)
{
 int rc;ExAcquireFastMutex(&d->Pair->Lock);rc=ObRead(&d->Pair->State,d->Gauge,tag,NowUs(),r);ExReleaseFastMutex(&d->Pair->Lock);return rc;
}
void OpenBatteryInitialize(OPEN_BATTERY_PAIR *p)
{if(p&&KeGetCurrentIrql()==PASSIVE_LEVEL){ExInitializeFastMutex(&p->Lock);ObInitialize(&p->State);}}
int OpenBatteryBeginOwner(OPEN_BATTERY_PAIR *p,uint64_t epoch,ULONG *notify)
{
 int rc;uint32_t n=0;if(notify)*notify=0;
 if(!p||!notify||KeGetCurrentIrql()!=PASSIVE_LEVEL)return OB_ARGUMENT;
 ExAcquireFastMutex(&p->Lock);rc=ObBeginOwner(&p->State,epoch,&n);ExReleaseFastMutex(&p->Lock);*notify=n;return rc;
}
int OpenBatteryPublish(OPEN_BATTERY_PAIR *p,const OB_BATCH *b,ULONG *notify)
{
 int rc;uint32_t n=0;if(notify)*notify=0;
 if(!p||!b||!notify||KeGetCurrentIrql()!=PASSIVE_LEVEL)return OB_ARGUMENT;
 ExAcquireFastMutex(&p->Lock);rc=ObPublish(&p->State,b,NowUs(),&n);ExReleaseFastMutex(&p->Lock);*notify=n;return rc;
}
int OpenBatteryTick(OPEN_BATTERY_PAIR *p,ULONG *notify)
{
 int rc;uint32_t n=0;if(notify)*notify=0;
 if(!p||!notify||KeGetCurrentIrql()!=PASSIVE_LEVEL)return OB_ARGUMENT;
 ExAcquireFastMutex(&p->Lock);rc=ObTick(&p->State,NowUs(),&n);ExReleaseFastMutex(&p->Lock);*notify=n;return rc;
}
int OpenBatteryInvalidate(OPEN_BATTERY_PAIR *p,ULONG *notify)
{
 uint32_t n=0;if(notify)*notify=0;
 if(!p||!notify||KeGetCurrentIrql()!=PASSIVE_LEVEL)return OB_ARGUMENT;
 ExAcquireFastMutex(&p->Lock);ObInvalidate(&p->State,&n);ExReleaseFastMutex(&p->Lock);*notify=n;return OB_OK;
}
static NTSTATUS QueryTag(PVOID x,PULONG tag)
{
 OPEN_BATTERY_DEVICE *d=x;uint32_t t=0;int rc;if(tag)*tag=BATTERY_TAG_INVALID;
 if(!Valid(d)||!tag)return STATUS_INVALID_PARAMETER;
 ExAcquireFastMutex(&d->Pair->Lock);rc=ObQueryTag(&d->Pair->State,d->Gauge,NowUs(),&t);ExReleaseFastMutex(&d->Pair->Lock);*tag=t;return Convert(rc);
}
static NTSTATUS QueryInformation(PVOID x,ULONG tag,BATTERY_QUERY_INFORMATION_LEVEL level,
 LONG atRate,PVOID buffer,ULONG length,PULONG returned)
{
 OPEN_BATTERY_DEVICE *d=x;OB_READING r;BATTERY_INFORMATION info={0};ULONG scalar=0,needed=0;const void *value=0;
 /* Equal ASCII names, including terminator; no runtime CRT string call. */
 static const WCHAR names[2][sizeof("OnePlus Open ZY0602 gauge 0")]={L"OnePlus Open ZY0602 gauge 0",L"OnePlus Open ZY0602 gauge 1"};
 if(returned)*returned=0;UNREFERENCED_PARAMETER(atRate);
 if(!Valid(d)||!returned)return STATUS_INVALID_PARAMETER;
 int rc=Reading(d,tag,&r);if(rc)return Convert(rc);
 switch(level){
 case BatteryInformation:
  /* mAh capacity and signed mA rate share a relative unit/hour system. Never
   * multiply capacity by instantaneous voltage and label it stored energy.
   * These are two gauge views, not a topology/69:31 aggregate assertion. */
  info.Capabilities=BATTERY_SYSTEM_BATTERY|BATTERY_CAPACITY_RELATIVE;
  info.Technology=1; /* Rechargeable phone battery; chemistry not identified. */
  info.Chemistry[0]='U';info.Chemistry[1]='N';info.Chemistry[2]='K';info.Chemistry[3]='N';
  info.DesignedCapacity=BATTERY_UNKNOWN_CAPACITY;info.FullChargedCapacity=r.FullMah;
  info.DefaultAlert1=info.DefaultAlert2=BATTERY_UNKNOWN_CAPACITY;
  value=&info;needed=sizeof(info);break;
 case BatteryTemperature:scalar=r.TemperatureTenthsKelvin;value=&scalar;needed=sizeof(scalar);break;
 case BatteryEstimatedTime:scalar=BATTERY_UNKNOWN_TIME;value=&scalar;needed=sizeof(scalar);break;
 case BatteryDeviceName:value=names[d->Gauge];needed=sizeof(names[0]);break;
 case BatteryGranularityInformation:case BatteryManufactureDate:case BatteryManufactureName:
 case BatteryUniqueID:case BatterySerialNumber:return STATUS_INVALID_DEVICE_REQUEST;
 default:return STATUS_INVALID_PARAMETER;
 }
 if(length<needed)return STATUS_BUFFER_TOO_SMALL;
 if(!buffer)return STATUS_INVALID_PARAMETER;
 RtlCopyMemory(buffer,value,needed);*returned=needed;return STATUS_SUCCESS;
}
static NTSTATUS QueryStatus(PVOID x,ULONG tag,PBATTERY_STATUS out)
{
 OPEN_BATTERY_DEVICE *d=x;OB_READING r;if(out)RtlZeroMemory(out,sizeof(*out));
 if(!Valid(d)||!out)return STATUS_INVALID_PARAMETER;
 int rc=Reading(d,tag,&r);if(rc)return Convert(rc);
 /* Windows has no unknown-online bit. Do not synthesize an offline/charging
  * answer from gauge current, flags, full SOC or a present USB data cable. */
 if(!r.PowerKnown)return STATUS_DEVICE_NOT_READY;
 out->PowerState=r.PowerState;out->Capacity=r.RemainingMah;out->Voltage=r.VoltageMv;
 out->Rate=r.RateKnown?r.RateMa:(LONG)BATTERY_UNKNOWN_RATE;return STATUS_SUCCESS;
}
static NTSTATUS SetInformation(PVOID x,ULONG tag,BATTERY_SET_INFORMATION_LEVEL level,PVOID buffer)
{
 OPEN_BATTERY_DEVICE *d=x;OB_READING r;UNREFERENCED_PARAMETER(level);UNREFERENCED_PARAMETER(buffer);
 if(!Valid(d))return STATUS_INVALID_PARAMETER;
 int rc=Reading(d,tag,&r);return rc?Convert(rc):STATUS_INVALID_DEVICE_REQUEST;
}
static NTSTATUS SetNotify(PVOID x,ULONG tag,PBATTERY_NOTIFY threshold)
{
 OPEN_BATTERY_DEVICE *d=x;uint32_t n=0;int rc;
 if(!Valid(d)||!threshold)return STATUS_INVALID_PARAMETER;
 ExAcquireFastMutex(&d->Pair->Lock);
 rc=ObSetNotify(&d->Pair->State,d->Gauge,tag,NowUs(),threshold->PowerState,threshold->LowCapacity,threshold->HighCapacity,&n);
 /* Preserve immediate notifications for the owner to drain outside this lock.
  * BatteryClassStatusNotify can re-enter a callback. Never call it here. */
 d->Pair->State.PendingNotify|=n;ExReleaseFastMutex(&d->Pair->Lock);
 return rc==OB_NOT_READY?STATUS_NOT_SUPPORTED:Convert(rc);
}
static NTSTATUS DisableNotify(PVOID x)
{
 OPEN_BATTERY_DEVICE *d=x;int rc;if(!Valid(d))return STATUS_INVALID_PARAMETER;
 ExAcquireFastMutex(&d->Pair->Lock);rc=ObDisableNotify(&d->Pair->State,d->Gauge);ExReleaseFastMutex(&d->Pair->Lock);return Convert(rc);
}
NTSTATUS OpenBatteryCallbacks(OPEN_BATTERY_DEVICE *d,BATTERY_MINIPORT_INFO *info)
{
 if(!Valid(d)||!info)return STATUS_INVALID_PARAMETER;
 RtlZeroMemory(info,sizeof(*info));info->MajorVersion=BATTERY_CLASS_MAJOR_VERSION;info->MinorVersion=BATTERY_CLASS_MINOR_VERSION;
 info->Context=d;info->QueryTag=QueryTag;info->QueryInformation=QueryInformation;info->QueryStatus=QueryStatus;
 info->SetInformation=SetInformation;info->SetStatusNotify=SetNotify;info->DisableStatusNotify=DisableNotify;
 /* Caller supplies Pdo and keeps DeviceName NULL before class registration. */
 return STATUS_SUCCESS;
}
