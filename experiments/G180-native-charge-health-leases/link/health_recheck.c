/* SPDX-License-Identifier: MIT */
#include "health_recheck.h"
uint32_t CHRecheck(const CH_HEALTH*h,uint64_t nonce,uint64_t now,
 uint64_t oldNonce,uint64_t oldTime,uint32_t role)
{
 if(!h||!nonce||role<CH_BEFORE_FV||role>CH_RENEW)return CH_ARGUMENT;
 if(h->Nonce!=nonce||nonce==oldNonce)return CH_NONCE;
 if(!h->ConfigBegin100ns||h->ConfigEnd100ns<h->ConfigBegin100ns||
  h->GaugeEnd100ns<h->ConfigEnd100ns||h->GaugeEnd100ns>now||
  now-h->ConfigBegin100ns>CH_FRESH_100NS||
  h->GaugeEnd100ns-h->ConfigBegin100ns>CH_PAIR_100NS||h->GaugeEnd100ns<=oldTime)return CH_FRESHNESS;
 if(h->FastMa!=300||h->UsbType!=4||
  (h->FloatMv!=4470&&(role!=CH_BEFORE_FV||h->FloatMv!=4550)))return CH_PROFILE;
 for(unsigned i=0;i<2;i++){
  if(h->TemperatureDeciK[i]<2931||h->TemperatureDeciK[i]>3131)return CH_TEMPERATURE;
  if(h->VoltageMv[i]<3250||h->VoltageMv[i]>4300)return CH_VOLTAGE;
  if(h->CurrentRaw[i]>65535||h->Flags[i]>65535||!h->FullMah[i]||h->FullMah[i]>65535||
   h->RemainingMah[i]>h->FullMah[i]||h->ChargePercent[i]>100)return CH_GAUGE_DATA;
  int32_t current=h->CurrentRaw[i]<32768?(int32_t)h->CurrentRaw[i]:(int32_t)h->CurrentRaw[i]-65536;
  if(current< -500||current>500)return CH_CURRENT;
 }
 if(h->VoltageMv[0]+150<h->VoltageMv[1]||h->VoltageMv[1]+150<h->VoltageMv[0])return CH_VOLTAGE;
 if(role==CH_BEFORE_FV||role==CH_BEFORE_RESTART){
  if(h->Enable!=1||h->StateFirst!=7||h->StateLast!=7)return CH_STATE;
 }else if(h->Enable!=1||h->StateFirst<1||h->StateFirst>4||h->StateLast<1||
  h->StateLast>4||(h->Flags[0]&1)||(h->Flags[1]&1))return CH_STATE;
 return CH_OK;
}
