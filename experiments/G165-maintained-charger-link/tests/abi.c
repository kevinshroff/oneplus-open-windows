/* SPDX-License-Identifier: MIT; C owns layout and control-code definitions. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#define C_ASSERT(x) _Static_assert(x,#x)
#define CTL_CODE(t,f,m,a) (((t)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22u
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#include "link_core.h"
#include "slots.h"
#include "protocol.h"
#define O(t,n) printf("\"" #n "\":%zu,",offsetof(t,n))
#define Z(t,n) printf("\"" #n "\":%zu",offsetof(t,n))
int main(int argc,char**argv)
{
 if(argc==2){
  const char*names[]={"status","snapshot","start","sample","close"};
  for(unsigned i=0;i<5;i++){
   char path[4096];assert(snprintf(path,sizeof(path),"%s/%s-request.bin",argv[1],names[i])>0);
   CLN_REQUEST r={sizeof(r),CLN_ABI,CLN_MAGIC,i<2?0:0x1234,i<2?0:7,0,0};
   FILE*f=fopen(path,"wbx");assert(f&&fwrite(&r,1,sizeof(r),f)==sizeof(r));fclose(f);
  }
 }else assert(argc==1);
 printf("{\"size\":%zu,\"state_size\":%zu,\"request_size\":%zu,\"magic\":\"%016llx\",",sizeof(CLN_SNAPSHOT_DATA),sizeof(CL_STATE),sizeof(CLN_REQUEST),(unsigned long long)CLN_MAGIC);
 printf("\"codes\":{\"status\":%u,\"snapshot\":%u,\"start\":%u,\"sample\":%u,\"close\":%u},",CLN_STATUS,CLN_SNAPSHOT,CLN_START,CLN_SAMPLE,CLN_CLOSE);
 printf("\"snapshot\":{");
 O(CLN_SNAPSHOT_DATA,Size);O(CLN_SNAPSHOT_DATA,Version);O(CLN_SNAPSHOT_DATA,Magic);O(CLN_SNAPSHOT_DATA,Cookie);O(CLN_SNAPSHOT_DATA,LastCommandId);
 O(CLN_SNAPSHOT_DATA,NowUs);O(CLN_SNAPSHOT_DATA,TimerCalls);O(CLN_SNAPSHOT_DATA,MapCalls);O(CLN_SNAPSHOT_DATA,KernelBuild);O(CLN_SNAPSHOT_DATA,Processors);
 O(CLN_SNAPSHOT_DATA,Irql);O(CLN_SNAPSHOT_DATA,FirmwareBytes);O(CLN_SNAPSHOT_DATA,FirmwareMatch);O(CLN_SNAPSHOT_DATA,FirmwareStatus);O(CLN_SNAPSHOT_DATA,WinPE);
 O(CLN_SNAPSHOT_DATA,Attempted);O(CLN_SNAPSHOT_DATA,AdmissionCode);O(CLN_SNAPSHOT_DATA,MapsLive);O(CLN_SNAPSHOT_DATA,Running);O(CLN_SNAPSHOT_DATA,Stopped);
 O(CLN_SNAPSHOT_DATA,SafeToUnload);O(CLN_SNAPSHOT_DATA,NativeFault);O(CLN_SNAPSHOT_DATA,LastAction);O(CLN_SNAPSHOT_DATA,LastResult);O(CLN_SNAPSHOT_DATA,FdtDigest);
 O(CLN_SNAPSHOT_DATA,Slots);O(CLN_SNAPSHOT_DATA,InitialDescriptor);O(CLN_SNAPSHOT_DATA,FinalDescriptor);Z(CLN_SNAPSHOT_DATA,State);printf("},\"state\":{");
 O(CL_STATE,Phase);O(CL_STATE,Fault);O(CL_STATE,TransportUncertain);O(CL_STATE,RpcUncertain);O(CL_STATE,OwnTx);O(CL_STATE,OwnRx);O(CL_STATE,RemoteCid);
 O(CL_STATE,RemoteOpen);O(CL_STATE,CloseSent);O(CL_STATE,CloseAcked);O(CL_STATE,RemoteClosed);O(CL_STATE,BatchActive);O(CL_STATE,Query);O(CL_STATE,Pending);
 O(CL_STATE,NextLocalId);O(CL_STATE,CurrentOffers);O(CL_STATE,TraceCount);O(CL_STATE,LastDescriptor);O(CL_STATE,TraceNext);O(CL_STATE,TraceOverwritten);
 O(CL_STATE,TxFrames);O(CL_STATE,RxFrames);O(CL_STATE,TxWriteAttempts);O(CL_STATE,CounterWriteAttempts);O(CL_STATE,KickAttempts);O(CL_STATE,Steps);
 O(CL_STATE,BatchesStarted);O(CL_STATE,BatchesCompleted);O(CL_STATE,Events);O(CL_STATE,IgnoredOpens);O(CL_STATE,Other);O(CL_STATE,Working);O(CL_STATE,LastBatch);Z(CL_STATE,Trace);printf("},\"batch\":{");
 O(CL_BATCH,Generation);O(CL_BATCH,BeginUs);O(CL_BATCH,EndUs);O(CL_BATCH,Complete);O(CL_BATCH,Aborted);O(CL_BATCH,ReplyBytes);O(CL_BATCH,Battery);Z(CL_BATCH,Replies);printf("},\"battery\":{");
 O(CL_BATTERY,WireValidMask);O(CL_BATTERY,ValueValidMask);O(CL_BATTERY,ServiceRejectedMask);O(CL_BATTERY,VoltageMax);O(CL_BATTERY,Voltage);
 O(CL_BATTERY,TemperatureRaw);O(CL_BATTERY,CurrentRaw);O(CL_BATTERY,OpenCircuitVoltage);O(CL_BATTERY,VoltageNow);O(CL_BATTERY,CurrentNow);
 O(CL_BATTERY,TemperatureProperty);O(CL_BATTERY,CapacityProperty);O(CL_BATTERY,UsbOnline);O(CL_BATTERY,UsbType);O(CL_BATTERY,LegacyStatus);Z(CL_BATTERY,ServiceResult);printf("}}\n");return 0;
}
