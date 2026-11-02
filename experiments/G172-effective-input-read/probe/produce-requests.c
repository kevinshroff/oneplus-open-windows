#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef uint8_t UCHAR;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#include "g111_core.h"
#include "g172_protocol.h"
int main(int argc,char**argv){assert(argc==2);G172_REQUEST q={sizeof(q),G172_ABI,G172_MAGIC,0,0,0};char path[4096];for(int i=0;i<2;i++){q.Nonce=i?0x123456789abcdefULL:0;snprintf(path,sizeof(path),"%s/%s-request.bin",argv[1],i?"read":"status");FILE*f=fopen(path,"wbx");assert(f&&fwrite(&q,1,sizeof(q),f)==sizeof(q));fclose(f);}printf("{\"status\":%u,\"read\":%u,\"result\":%u}\n",G172_IOCTL_STATUS,G172_IOCTL_READ,G172_IOCTL_RESULT);}
