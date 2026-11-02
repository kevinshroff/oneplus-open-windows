/* Actual C schema for Go and native ARM64 compile-time assertions. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int32_t NTSTATUS;typedef void*WDFDEVICE;
#define C_ASSERT(x) _Static_assert(x,#x)
#define CTL_CODE(t,f,m,a) (((t)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22u
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#include "provider_io.h"
#include "g179_protocol.h"
#define O(t,n) printf("\"" #n "\":%zu,",offsetof(t,n))
#define Z(t,n) printf("\"" #n "\":%zu",offsetof(t,n))
int main(int argc,char**argv)
{
 if(argc==4){
  FILE*f=fopen(argv[1],"rb");CH_IO_RESULT io;assert(f&&fread(&io,1,sizeof(io),f)==sizeof(io)&&fgetc(f)==EOF&&!fclose(f));
  G179_CAPTURE c={0};c.Status.Size=sizeof(c.Status);c.Status.Version=1;c.Status.Magic=G179_MAGIC;c.Status.KernelBuild=26100;c.Status.Processors=8;c.Status.FirmwareBytes=576;c.Status.FirmwareMatch=1;c.Status.Attempts=1;c.Status.Ready=1;c.Status.InterruptTime=io.End100ns+10000;c.Status.Frequency=19200000;c.Status.Sequence=4;c.Status.SafeToUnload=1;c.Nonce=io.Health.Nonce;c.Result=io;
  f=fopen(argv[2],"wbx");assert(f&&fwrite(&c,1,sizeof(c),f)==sizeof(c)&&!fclose(f));G179_REQUEST q={32,1,G179_MAGIC,0x1234,0,0};f=fopen(argv[3],"wbx");assert(f&&fwrite(&q,1,sizeof(q),f)==sizeof(q)&&!fclose(f));
 }else assert(argc==1);
 printf("{\"status_size\":%zu,\"capture_size\":%zu,\"request_size\":%zu,\"io_size\":%zu,\"health_size\":%zu,\"magic\":\"%016llx\",\"codes\":{\"status\":%u,\"read\":%u,\"result\":%u},\"status\":{",sizeof(G179_STATUS),sizeof(G179_CAPTURE),sizeof(G179_REQUEST),sizeof(CH_IO_RESULT),sizeof(CH_HEALTH),(unsigned long long)G179_MAGIC,G179_IOCTL_STATUS,G179_IOCTL_READ,G179_IOCTL_RESULT);
 O(G179_STATUS,Size);O(G179_STATUS,Version);O(G179_STATUS,Magic);O(G179_STATUS,KernelBuild);O(G179_STATUS,Processors);O(G179_STATUS,Irql);O(G179_STATUS,FirmwareBytes);O(G179_STATUS,FirmwareMatch);O(G179_STATUS,FirmwareStatus);O(G179_STATUS,MapCalls);O(G179_STATUS,Attempts);O(G179_STATUS,Ready);O(G179_STATUS,Fault);O(G179_STATUS,InterruptTime);O(G179_STATUS,Frequency);O(G179_STATUS,Sequence);O(G179_STATUS,SafeToUnload);O(G179_STATUS,TransportUncertain);Z(G179_STATUS,Reserved);
 printf("},\"capture\":{");O(G179_CAPTURE,Status);O(G179_CAPTURE,Nonce);O(G179_CAPTURE,Admission);O(G179_CAPTURE,Reserved);Z(G179_CAPTURE,Result);
 printf("},\"io\":{");O(CH_IO_RESULT,Stage);O(CH_IO_RESULT,FailedStage);O(CH_IO_RESULT,ValidationAttempted);O(CH_IO_RESULT,Valid);O(CH_IO_RESULT,CreatedMask);O(CH_IO_RESULT,OpenedMask);O(CH_IO_RESULT,SentMask);O(CH_IO_RESULT,ReceivedMask);O(CH_IO_RESULT,ClosedMask);O(CH_IO_RESULT,DeletedMask);O(CH_IO_RESULT,ManagedBuffers);O(CH_IO_RESULT,HealthCode);O(CH_IO_RESULT,LastStatus);O(CH_IO_RESULT,SendStatus);O(CH_IO_RESULT,ReceivedBytes);O(CH_IO_RESULT,Reserved);O(CH_IO_RESULT,Begin100ns);O(CH_IO_RESULT,Validation100ns);O(CH_IO_RESULT,End100ns);Z(CH_IO_RESULT,Health);
 printf("},\"health\":{");O(CH_HEALTH,Nonce);O(CH_HEALTH,ConfigBegin100ns);O(CH_HEALTH,ConfigEnd100ns);O(CH_HEALTH,GaugeEnd100ns);O(CH_HEALTH,StateFirst);O(CH_HEALTH,StateLast);O(CH_HEALTH,Enable);O(CH_HEALTH,FloatMv);O(CH_HEALTH,FastMa);O(CH_HEALTH,UsbType);O(CH_HEALTH,VoltageMv);O(CH_HEALTH,TemperatureDeciK);O(CH_HEALTH,CurrentRaw);O(CH_HEALTH,Flags);O(CH_HEALTH,RemainingMah);O(CH_HEALTH,FullMah);Z(CH_HEALTH,ChargePercent);printf("}}\n");return 0;
}
