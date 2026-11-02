/* SPDX-License-Identifier: MIT */
#include "charger_codec.h"
static const CL_QUERY Queries[CL_QUERY_COUNT]={
 {0x30,8,24,24},{1,0,16,44},{0x30,6,24,24},{0,0,16,16},
 {0x30,7,24,24},{0x30,9,24,24},{0x30,12,24,24},{0x30,4,24,24},
 {0x32,0,24,24},{0x32,6,24,24},{0x31,8,24,24},
 {0x31,24,24,24},{0x31,24,24,24},{0x31,24,24,24}
};
static uint32_t U32(const uint8_t*b){return(uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
static void P32(uint8_t*b,uint32_t v){for(uint32_t i=0;i<4;i++)b[i]=(uint8_t)(v>>(i*8));}
const CL_QUERY*CLQuerySpec(uint32_t i){return i<CL_QUERY_COUNT?Queries+i:0;}
uint32_t CLBuildQuery(uint32_t index,uint8_t out[24])
{
 const CL_QUERY*q=CLQuerySpec(index);if(!q||!out)return 0;
 for(uint32_t i=0;i<24;i++)out[i]=0;
 P32(out,0x800a);P32(out+4,1);P32(out+8,q->Opcode);
 if(q->RequestBytes==24)P32(out+16,q->Property);
 if(index==CL_FV_QUERY)P32(out+20,4470); /* mV, not cached GET microvolts */
 if(index==CL_ENABLE_QUERY)P32(out+20,1); /* disable remains exactly zero */
 return q->RequestBytes;
}
int CLDecodeReply(uint32_t index,const uint8_t*b,uint32_t n,CL_BATTERY*out)
{
 const CL_QUERY*q=CLQuerySpec(index);
 if(!q||!b||!out||n!=q->ReplyBytes||U32(b)!=0x800a||U32(b+4)!=1||U32(b+8)!=q->Opcode)return 0;
 uint32_t bit=1u<<index;
 if(out->WireValidMask&bit)return 0; /* One outstanding request; no stale duplicates. */
 if(q->RequestBytes==24){
  if(U32(b+12)!=q->Property)return 0;
  uint32_t value=U32(b+16),result=U32(b+20);out->ServiceResult[index]=result;
  if(result){out->WireValidMask|=bit;out->ServiceRejectedMask|=bit;return 1;}
  /* SET31's word4 is not assigned freshly by the original server. Never
   * interpret that stale word as an echo, a voltage or physical readback. */
  if(index>=CL_FV_QUERY){out->WireValidMask|=bit;out->ControlAckMask|=bit;return 1;}
  switch(index){
  case 0:out->VoltageMax=value;break;case 2:out->OpenCircuitVoltage=value;break;case 4:out->VoltageNow=value;break;
  case 5:out->CurrentNow=value;break;case 6:out->TemperatureProperty=value;break;
  case 7:out->CapacityProperty=value;break;case 8:out->UsbOnline=value;break;
  case 9:out->UsbType=value;break;default:return 0;
  }
 }else if(index==1){
  out->BatteryState=U32(b+12);out->RemainingCapacity=U32(b+16);out->Rate=U32(b+20);
  out->Voltage=U32(b+24);out->PowerState=U32(b+28);out->ChargingSource=U32(b+32);
  out->TemperatureRaw=U32(b+36);out->CurrentRaw=U32(b+40);
 }else if(index==3)out->LegacyBatteryId=U32(b+12);
 else return 0;
 out->WireValidMask|=bit;out->ValueValidMask|=bit;return 1;
}
