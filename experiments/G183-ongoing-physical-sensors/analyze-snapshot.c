#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
int main(int argc,char**argv){
 if(argc!=2)return 2;FILE*f=fopen(argv[1],"rb");OP183_SNAPSHOT*s=calloc(1,sizeof(*s));if(!f||!s)return 2;
 if(fread(s,1,sizeof(*s),f)!=sizeof(*s)||fgetc(f)!=EOF)return 3;fclose(f);OP183_STATUS_DATA*d=&s->Status;S183_READING r;
 if(d->Size!=sizeof(*s)||d->Version!=1||d->Magic!=OP183_MAGIC||d->KernelBuild!=26100||d->Cpus!=8||d->Irql||!d->FirmwareMatch||!d->Prepared||!d->D0Active||d->MapCount!=20||d->MapCalls-d->UnmapCalls!=20||d->Valid!=1||d->Fault||d->Uncertain||d->ValidationCode||d->ProducerQualified||d->Reserved)return 4;
 if(S183Validate(&s->Result,&r)||memcmp(&r,&s->Reading,sizeof(r))||s->Result.Epoch!=d->D0Epoch||s->Result.Sequence!=d->LastSequence||d->Now100ns<s->Result.End100ns||d->Now100ns-s->Result.End100ns>S183_TTL_100NS||d->Completed!=d->ValidCount||d->Completed!=d->LastSequence)return 5;
 printf("{\"passed\":true,\"instance\":%"PRIu64",\"epoch\":%"PRIu64",\"sequence\":%"PRIu64",\"completed\":%"PRIu64",\"ticks\":%"PRIu64",\"map_calls\":%"PRIu64",\"pair_ms\":%.4f,\"age_ms\":%.4f,\"voltage_mV\":[%u,%u],\"temperature_C\":[%.1f,%.1f],\"remaining_mAh\":[%u,%u],\"SOC\":[%u,%u],\"current_raw\":[%u,%u],\"charger_enable\":%u,\"charger_state\":%u}\n",d->Instance,d->D0Epoch,d->LastSequence,d->Completed,d->Ticks,d->MapCalls,(s->Result.End100ns-s->Result.Begin100ns)/10000.,(d->Now100ns-s->Result.End100ns)/10000.,r.VoltageMv[0],r.VoltageMv[1],((int32_t)r.TemperatureDeciK[0]-2731)/10.,((int32_t)r.TemperatureDeciK[1]-2731)/10.,r.RemainingMah[0],r.RemainingMah[1],r.Percent[0],r.Percent[1],r.CurrentRaw[0],r.CurrentRaw[1],r.Enable,r.ChargerStateLast);
 free(s);return 0;
}
