/* SPDX-License-Identifier: MIT */
#include "g159_codec.h"
static const G159_QUERY Queries[G159_QUERY_COUNT]={
 {9,0,16,736},{1,0,16,44},{0x30,6,24,24},{0,0,16,16},
 {0x30,7,24,24},{0x30,9,24,24},{0x30,12,24,24},{0x30,4,24,24},
 {0x32,0,24,24},{0x32,6,24,24}
};
static uint32_t U32(const uint8_t*b){return(uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
static void P32(uint8_t*b,uint32_t v){for(uint32_t i=0;i<4;i++)b[i]=(uint8_t)(v>>(i*8));}
const G159_QUERY*G159QuerySpec(uint32_t i){return i<G159_QUERY_COUNT?Queries+i:0;}
uint32_t G159BuildQuery(uint32_t index,uint8_t out[24])
{
 const G159_QUERY*q=G159QuerySpec(index);if(!q||!out)return 0;
 for(uint32_t i=0;i<24;i++)out[i]=0;
 P32(out,0x800a);P32(out+4,1);P32(out+8,q->Opcode);
 if(q->RequestBytes==24)P32(out+16,q->Property);
 return q->RequestBytes;
}
int G159DecodeReply(uint32_t index,const uint8_t*b,uint32_t n,G159_BATTERY*out)
{
 const G159_QUERY*q=G159QuerySpec(index);
 if(!q||!b||!out||n!=q->ReplyBytes||U32(b)!=0x800a||U32(b+4)!=1||U32(b+8)!=q->Opcode)return 0;
 uint32_t bit=1u<<index;
 if(out->WireValidMask&bit)return 0; /* One outstanding request; no stale duplicates. */
 if(q->RequestBytes==24){
  if(U32(b+12)!=q->Property)return 0;
  uint32_t value=U32(b+16),result=U32(b+20);out->ServiceResult[index]=result;
  if(result){out->WireValidMask|=bit;out->ServiceRejectedMask|=bit;return 1;}
  switch(index){
  case 2:out->OpenCircuitVoltage=value;break;case 4:out->VoltageNow=value;break;
  case 5:out->CurrentNow=value;break;case 6:out->TemperatureProperty=value;break;
  case 7:out->CapacityProperty=value;break;case 8:out->UsbOnline=value;break;
  case 9:out->UsbType=value;break;default:return 0;
  }
 }else if(index==0){
  /*736-byte legacy info: final battery ID is distinct from power_unit at+12.*/
  if(U32(b+732)!=0)return 0;
  out->PowerUnit=U32(b+12);out->DesignCapacity=U32(b+16);out->LastFullCapacity=U32(b+20);
  out->DesignVoltage=U32(b+28);out->CycleCount=U32(b+40);out->BatteryId=U32(b+732);
  if(out->PowerUnit>1){out->WireValidMask|=bit;return 1;}
 }else if(index==1){
  out->BatteryState=U32(b+12);out->RemainingCapacity=U32(b+16);out->Rate=U32(b+20);
  out->Voltage=U32(b+24);out->PowerState=U32(b+28);out->ChargingSource=U32(b+32);
  out->TemperatureRaw=U32(b+36);out->CurrentRaw=U32(b+40);
 }else if(index==3)out->LegacyStatus=U32(b+12);
 else return 0;
 out->WireValidMask|=bit;out->ValueValidMask|=bit;return 1;
}
