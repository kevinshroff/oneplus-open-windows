/* SPDX-License-Identifier: MIT */
#include "g91_adapter_policy.h"
#include "g91_power.h"
const G91_IO_RANGE G91IoRanges[10]={
 {0x17a20000,0x2000,1},{0x17100000,0x1000,0},{0xf10a000,0x1000,0},{0xf118000,0x2000,0},
 {0xc400000,0x1000,0},{0xc402000,0x1000,0},{0xc42d000,0x1000,0},{0xc440000,0x1000,1},{0xc441000,0x1000,1},{0xc445000,0x1000,1}
};
int G91IoReadAllowed(uint32_t at)
{
 static const uint32_t base[25]={0x17a20000,0x17a20004,0x17a2000c,0x17a20d00,0x17a20d04,0x17a20d28,0x17a20d24,0x17a20d2c,0x17a20d34,0x17a20d38,0x17a20d3c,0x17a20d40,0x17a20d44,0x17100104,0x17100204,0x17100304,0x17100c08,0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c};
 if(at&3)return 0;for(unsigned i=0;i<25;i++)if(at==base[i])return 1;
 if(at==0xc400000||at==0xc400004)return 1;
 const uint32_t apid[3]={117,145,695};for(unsigned i=0;i<3;i++){
  uint32_t b=0xc440000+apid[i]*0x20;
  if(at==0xc402000+apid[i]*4||at==0xc42d000+apid[i]*4||at==b||at==b+8||at==b+0x18||at==b+0x1c)return 1;
 }return 0;
}
int G91IoWriteAllowed(uint32_t at,uint32_t value)
{
 if(at&3)return 0;
 if(at==0xc440ea0||at==0xc441220||at==0xc4456e0)return value==0x08000007||value==0x08000080||value==0x08000407;
 return G91RscWriteAllowed(at,value);
}
