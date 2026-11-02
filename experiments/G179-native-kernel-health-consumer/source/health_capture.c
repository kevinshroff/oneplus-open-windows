/* SPDX-License-Identifier: MIT; fixed provider ABI, no bus or OS operations. */
#include "health_capture.h"
#include "health_layout.h"
#include <string.h>
static uint32_t U32(const uint8_t*p){return(uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t U64(const uint8_t*p){return U32(p)|(uint64_t)U32(p+4)<<32;}
static int GaugeReadAllowed(uint32_t at)
{
 static const uint32_t offsets[]={0,4,0x24,0x28,0x40,0x48,0x4c,0x64,0x68,0x6c,0x26c,0x270,0x278,0x610,0x640,0x800,0x804,0xe24,0xe28,0x258,0x7c,0x254,0x260,0x264,0x284,0x288,0x600,0x604,0x614,0x630,0x634,0x644,0x80c,0x810,0x814,0x908};
 for(unsigned i=0;i<2;i++){
  uint32_t base=i?0x98c000:0x880000;
  if(at==base+0x780)return 1;
  for(unsigned j=0;j<sizeof(offsets)/sizeof(offsets[0]);j++){
   if(i&&j==18)continue;uint32_t off=i&&j==17?0x50:offsets[j];if(at==base+off)return 1;
  }
 }
 return 0;
}
static int Status(const uint8_t*p,uint64_t magic,uint32_t maps)
{
 return U32(p)==80&&U32(p+4)==1&&U64(p+8)==magic&&U32(p+16)==26100&&
  U32(p+20)==8&&U32(p+24)==0&&U32(p+28)==576&&U32(p+32)==1&&
  U32(p+36)==0&&U32(p+40)==maps&&U32(p+44)==1&&U32(p+48)==1&&U32(p+52)==0&&
  U64(p+64)>0&&U64(p+64)<=UINT64_C(1000000000)&&U64(p+72)>0;
}
uint32_t CHValidate(const uint8_t*c,size_t cn,const uint8_t*g,size_t gn,
 uint64_t nonce,uint64_t now,uint64_t oldNonce,uint64_t oldTime,uint32_t role,CH_HEALTH*out)
{
 CH_HEALTH h;memset(&h,0,sizeof(h));if(out)memset(out,0,sizeof(*out));
 if(!c||!g||!out||cn!=CH_CONFIG_BYTES||gn!=CH_GAUGE_BYTES||!nonce||role>CH_RENEW)return CH_ARGUMENT;
 if(!Status(c,UINT64_C(0x314d50373631474f),5)||!Status(g,UINT64_C(0x315147303631474f),11))return CH_IDENTITY;
 if(U64(c+80)!=nonce||U64(g+80)!=nonce||nonce==oldNonce)return CH_NONCE;
 h.Nonce=nonce;h.ConfigBegin100ns=U64(c+104);h.ConfigEnd100ns=U64(c+112);h.GaugeEnd100ns=U64(g+56);
 if(h.ConfigEnd100ns<h.ConfigBegin100ns||h.GaugeEnd100ns<h.ConfigEnd100ns||
  h.GaugeEnd100ns>now||now-h.ConfigBegin100ns>CH_FRESH_100NS||
  h.GaugeEnd100ns-h.ConfigBegin100ns>CH_PAIR_100NS||h.GaugeEnd100ns<=oldTime)return CH_FRESHNESS;
 const uint8_t*r=c+120;
 if(U32(c+92)!=19||U32(c+96)||U32(c+100)||U32(r)!=976||U32(r+4)||
  U32(r+8)||U32(r+16)!=19||U32(r+20)!=19||U32(r+28)!=19||U32(r+32)||
  U32(r+36)!=1||U32(r+40)||U32(r+44)||U64(r+56)<U64(r+48)||U64(r+56)-U64(r+48)>1000000)return CH_CONFIG_RESULT;
 /* Independent fixed-address/completion/data binding, including padded bytes. */
 static const uint32_t q[19][3]={{0,0,8},{1,0,8},{2,0,8},{3,0,8},{4,0,8},
 {2,6,8},{2,14,2},{2,0x40,8},{2,0x50,8},{2,0x58,8},{2,0x60,1},
 {3,0x10,1},{4,0x0a,2},{4,0x10,1},{4,0x40,8},{4,0x50,8},{2,0xa0,1},{5,0x43,1},{2,6,8}};
 for(unsigned i=0;i<19;i++){
  const uint8_t*t=r+216+40*i;uint32_t n=q[i][2];
  if(U32(t)!=q[i][0]||U32(t+4)!=q[i][1]||U32(t+8)!=n||U32(t+12)!=63||
   (!(U32(t+20)&1)&&U32(t+16))||((U32(t+24)&15)!=1)||U32(t+36)||memcmp(r+64+8*i,t+28,n))return CH_CONFIG_TRACE;
  for(unsigned j=n;j<8;j++)if(r[64+8*i+j])return CH_CONFIG_TRACE;
 }
 const uint8_t*v=r+64;
 /* Native type/subtype/revision identities pinned by both finite providers. */
 if(memcmp(v,(const uint8_t[]){0x20,0,0,2,0x51,0x47,1,0},8)||
  v[8+4]!=2||v[8+5]!=0xa8||v[16+4]!=2||v[16+5]!=0xa9||
  v[24+4]!=2||v[24+5]!=0xab||v[32+4]!=2||v[32+5]!=0xac)return CH_IDENTITY;
 h.StateFirst=v[5*8]&7;h.StateLast=v[18*8]&7;h.Enable=v[7*8+6]&1;
 h.FloatMv=3600+(uint32_t)(v[9*8]&127)*10;h.FastMa=(uint32_t)v[8*8+4]*50;
 h.UsbType=v[12*8+1];
 if(v[17*8]!=0x40||v[16*8]||h.FastMa!=300||
  !(v[12*8]&1)||h.UsbType!=4||v[15*8+4]&1||
  (h.FloatMv!=4470&&(role!=CH_BEFORE_FV||h.FloatMv!=4550))||
  v[5*8+5]!=v[9*8]||v[18*8+5]!=v[9*8])return CH_PROFILE;
 r=g+120;
 if(U32(g+96)!=11||U32(g+100)||U32(g+104)!=46||U32(g+108)!=46||U32(g+112)||U32(g+116)||
  U32(r)!=279760||U32(r+4)||U32(r+8)||U32(r+12)!=46||U32(r+16)!=46||
  U32(r+20)!=0xfffff||U32(r+24)!=3||U32(r+28)!=3||U32(r+32)>16384||U32(r+36)||
  U32(r+48)||U32(r+52)||U32(r+56)||U32(r+60)||U64(r+72)<U64(r+64)||U64(r+72)-U64(r+64)>2000000)return CH_GAUGE_RESULT;
 uint32_t readCount=0,writeCount=0,rxCount=0,commandCount=0,fifoCount=0;
 for(uint32_t i=0;i<U32(r+32);i++){
  const uint8_t*e=r+G178_GAUGE_TRACE+16*i;
  uint32_t kind=U32(e),address=U32(e+4),value=U32(e+8),command=U32(e+12);
  if(command>46)return CH_GAUGE_TRACE;
  if(kind==1){
   if(!GaugeReadAllowed(address))return CH_GAUGE_TRACE;
   readCount++;
   if((address&4095)==0x780){
    if(rxCount>=20||address!=(rxCount<10?0x880780u:0x98c780u)||(value&65535)!=U32(r+80+4*rxCount))return CH_GAUGE_TRACE;
    rxCount++;
   }
  }else if(kind==2){
   uint32_t base=address>=0x880000&&address<0x881000?0x880000:address>=0x98c000&&address<0x98d000?0x98c000:0;
   if(!base)return CH_GAUGE_TRACE;
   switch(address-base){
   case 0x26c:if(value!=1&&value!=3)return CH_GAUGE_TRACE;break;
   case 0x270:if(value!=2)return CH_GAUGE_TRACE;break;
   case 0x80c:if(value>1)return CH_GAUGE_TRACE;break;
   case 0x600:{
    unsigned n=commandCount%23,k=n<9?n%3:1+((n-9)&1);
    const uint32_t commands[3]={0x0800aa00,0x0800aa04,0x1000aa00};
    if(commandCount>=46||base!=(commandCount<23?0x880000u:0x98c000u)||value!=commands[k])return CH_GAUGE_TRACE;
    commandCount++;break;}
   case 0x700:{
    if(!commandCount)return CH_GAUGE_TRACE;
    unsigned n=(commandCount-1)%23;const uint32_t regs[7]={6,8,10,16,18,20,44};
    uint32_t expected=n<9?(n%3==0?(n/3)<<8:0):regs[(n-9)/2];
    if(value!=expected)return CH_GAUGE_TRACE;fifoCount++;break;}
   case 0x618:if(!value||(value&~UINT32_C(0x7fc07e7f)))return CH_GAUGE_TRACE;break;
   default:return CH_GAUGE_TRACE;
   }
   writeCount++;
  }else return CH_GAUGE_TRACE;
 }
 if(rxCount!=20||commandCount!=46||fifoCount!=26||readCount!=U32(r+40)||writeCount!=U32(r+44)||writeCount!=U32(g+92))return CH_GAUGE_TRACE;
 /* Before/after preflight offsets are generated and checked against actual C. */
 if(U32(r+160+4)||U32(r+160+20)!=3||U32(r+160+24)!=3||U32(r+160+28)!=15||
  U32(r+G178_GAUGE_AFTER+4)||U32(r+G178_GAUGE_AFTER+20)!=3||
  U32(r+G178_GAUGE_AFTER+24)!=3||U32(r+G178_GAUGE_AFTER+28)!=15)return CH_GAUGE_RESULT;
 for(unsigned i=0;i<2;i++){
  const uint8_t*a=r+80+40*i;uint32_t words[10];
  for(unsigned j=0;j<10;j++){words[j]=U32(a+4*j);if(words[j]>65535)return CH_GAUGE_DATA;}
  if(words[0]!=0x6002||words[1]!=0x0602||words[2]!=0x0200||!words[7]||words[6]>words[7]||words[9]>100)return CH_GAUGE_DATA;
  h.TemperatureDeciK[i]=words[3];h.VoltageMv[i]=words[4];h.CurrentRaw[i]=words[8];h.Flags[i]=words[5];
  h.RemainingMah[i]=words[6];h.FullMah[i]=words[7];h.ChargePercent[i]=words[9];
  if(words[3]<2931||words[3]>3131)return CH_TEMPERATURE;
  if(words[4]<3250||words[4]>4300)return CH_VOLTAGE;
  int32_t current=words[8]<32768?(int32_t)words[8]:(int32_t)words[8]-65536;
  if(current< -500||current>500)return CH_CURRENT;
 }
 if(h.VoltageMv[0]+150<h.VoltageMv[1]||h.VoltageMv[1]+150<h.VoltageMv[0])return CH_VOLTAGE;
 if(role==CH_BEFORE_FV||role==CH_BEFORE_RESTART){if(!h.Enable||h.StateFirst!=7||h.StateLast!=7)return CH_STATE;}
 if(role==CH_RENEW){
  if(!h.Enable||h.StateFirst<1||h.StateFirst>4||h.StateLast<1||h.StateLast>4||
   h.Flags[0]&1||h.Flags[1]&1)return CH_STATE;
 }
 *out=h;return CH_OK;
}
