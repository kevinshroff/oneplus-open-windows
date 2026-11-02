#include "fault_iort.h"
static uint32_t u32(const unsigned char*p){return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static uint64_t u64(const unsigned char*p){return u32(p)|((uint64_t)u32(p+4)<<32);}
int OfIortContract(const void*data,size_t bytes){const unsigned char*b=data;if(!b||bytes<48||bytes>65536||u32(b)!=0x54524f49||u32(b+4)!=bytes)return -1;unsigned sum=0;for(size_t i=0;i<bytes;i++)sum+=b[i];if(sum&255)return -1;uint32_t count=u32(b+36),off=u32(b+40);if(!count||count>256||off<48||off>bytes)return -1;unsigned found=0;
 static const unsigned spi[25]={677,678,679,680,681,682,683,684,685,686,687,422,476,574,575,576,577,659,661,664,665,666,668,669,699};
 for(uint32_t i=0;i<count;i++){if(off>bytes-16)return -1;unsigned len=(unsigned)b[off+1]|((unsigned)b[off+2]<<8);if(len<16||len>bytes-off)return -1;if(b[off]==3){if(len<60)return -1;if(u64(b+off+16)==0x03da0000){found++;if(u64(b+off+24)!=0x40000||u32(b+off+32)!=3)return -1;uint32_t g=u32(b+off+40),n=u32(b+off+44),c=u32(b+off+48);if(g<60||g>len-16||n!=25||c<60||c>len||n>(len-c)/8)return -1;if(u32(b+off+g)!=705||u32(b+off+g+4)!=0)return -1;for(unsigned k=0;k<25;k++)if(u32(b+off+c+k*8)!=spi[k]+32||u32(b+off+c+k*8+4)!=0)return -1;}}off+=len;}
 return found==1?0:-1;
}
/* Exact G991 publication contract: same ABI124, real third CB0 IRQ count. */
int OfOgbtContract(const void*data,size_t bytes){const unsigned char*b=data;if(!b||bytes!=124||u32(b)!=0x5442474f||u32(b+4)!=124||b[8]!=1)return -1;unsigned sum=0;for(size_t i=0;i<bytes;i++)sum+=b[i];if(sum&255)return -1;return u32(b+36)==1&&u32(b+40)==3&&!u64(b+44)&&u32(b+52)==7&&u32(b+56)==7&&u32(b+60)==1&&!u32(b+64)&&u32(b+100)==5&&u32(b+104)==6&&u32(b+108)==3&&!u32(b+112)&&!u32(b+116)&&!u32(b+120)?0:-1;}
