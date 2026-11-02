/* Only exact inherited cover framebuffer pixels can be cleared. No panel,
 * DPU, DSI, clock, PMIC, interrupt or system-RAM configuration write exists. */
#include <ntifs.h>
#include <wdf.h>
#include <aux_klib.h>
#include "g188_binding.h"
#include "g188_protocol.h"
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD G188Unload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL G188Control;
EVT_WDF_DEVICE_FILE_CREATE G188FileCreate;
static volatile LONG G188Attempts,G188Ready,G188Fault,G188Maps,G188Blank;
static volatile LONG64 G188Sequence;
static G188_CAPTURE*G188Frozen;
#include "guard-and-status.inc"
typedef struct{PVOID Clock,Core,Pipe[4],Frame;}G188_MAPS;
static int NoManagedRam(void){
 PPHYSICAL_MEMORY_RANGE r=MmGetPhysicalMemoryRangesEx2(NULL,0);int valid=0;if(!r)return 0;
 for(ULONG i=0;i<512;i++){ULONGLONG a=(ULONGLONG)r[i].BaseAddress.QuadPart,n=(ULONGLONG)r[i].NumberOfBytes.QuadPart;if(!n){valid=1;break;}if(n>MAXULONGLONG-a)break;
  if(a<G188_FB_PAGE+G188_FB_MAP_BYTES&&G188_FB_PAGE<a+n)goto done;
  const ULONG pages[6]={0xaf08000,0xaf09000,0xae05000,0xae07000,0xae09000,0xae0b000};for(ULONG j=0;j<6;j++)if(a<(ULONGLONG)pages[j]+4096&&pages[j]<a+n)goto done;
 }done:ExFreePool(r);return valid;
}
static ULONG Word(PVOID p,ULONG off){KeMemoryBarrier();ULONG v=READ_REGISTER_ULONG((PULONG)((PUCHAR)p+off));KeMemoryBarrier();return v;}
static int Gates(G188_MAPS*m){unsigned a[3]={Word(m->Clock,0),Word(m->Clock,0xc),Word(m->Clock,0xa4)},b[2]={Word(m->Core,0),Word(m->Core,4)};return G188Gate(a,b);}
static int Pipeline(G188_MAPS*m){
 if(!Gates(m))return 0;for(ULONG i=0;i<4;i++)for(ULONG j=0;j<12;j++)if(!Gates(m)||Word(m->Pipe[i],G188Off[j])!=G188Expected[i][j])return 0;return Gates(m);
}
static PVOID Map(ULONGLONG at,SIZE_T bytes,ULONG flags){PHYSICAL_ADDRESS a;a.QuadPart=(LONGLONG)at;InterlockedIncrement(&G188Maps);return MmMapIoSpaceEx(a,bytes,flags);}
static void Operate(G188_CAPTURE*out,WDFREQUEST request,ULONGLONG nonce,int blank){
 G188_MAPS m;G188_HEADER*h=&out->Header;RtlZeroMemory(&m,sizeof(m));Status(&h->Status);h->Nonce=nonce;h->Begin=KeQueryInterruptTime();if(blank)h->BlankAttempted=1;
 if(!h->Status.FirmwareMatch||h->Status.KernelBuild!=26300||h->Status.Processors!=8||h->Status.Irql!=PASSIVE_LEVEL||!FullWindows()){h->Code=1001;goto done;}
 if(!NoManagedRam()){h->Code=1002;goto done;}
 m.Clock=Map(0xaf08000,4096,PAGE_READONLY|PAGE_NOCACHE);if(!m.Clock){h->Code=1005;goto done;}
 m.Core=Map(0xaf09000,4096,PAGE_READONLY|PAGE_NOCACHE);if(!m.Core){h->Code=1005;goto done;}if(!Gates(&m)){h->Code=2001;goto done;}
 for(ULONG i=0;i<4;i++){if(!Gates(&m)){h->Code=2002;goto done;}m.Pipe[i]=Map(G188PipePages[i],4096,PAGE_READONLY|PAGE_NOCACHE);if(!m.Pipe[i]){h->Code=1005;goto done;}}
 if(!Pipeline(&m)){h->Code=2003;goto done;}
 m.Frame=Map(G188_FB_PAGE,G188_FB_MAP_BYTES,(blank?PAGE_READWRITE:PAGE_READONLY)|PAGE_WRITECOMBINE);if(!m.Frame){h->Code=1005;goto done;}
 for(ULONG i=0;i<G188_WORDS;i++){
  if(!(i%G188_WIDTH)){if(WdfRequestIsCanceled(request)){h->Code=1004;goto done;}if(!Gates(&m)){h->Code=2004;goto done;}}
  PULONG pixel=(PULONG)((PUCHAR)m.Frame+G188_FB_OFFSET+i*4u);
  if(blank){WRITE_REGISTER_ULONG(pixel,0);h->WrittenWords++;}else{out->Pixels[i]=READ_REGISTER_ULONG(pixel);h->ReadWords++;}
 }
 KeMemoryBarrier();if(!Pipeline(&m)){h->Code=2005;goto done;}
 if(blank){for(ULONG i=0;i<G188_WORDS;i++){if(READ_REGISTER_ULONG((PULONG)((PUCHAR)m.Frame+G188_FB_OFFSET+i*4u))){h->Code=2006;goto done;}h->VerifiedZero++;}if(!Pipeline(&m)){h->Code=2007;goto done;}h->BlankVerified=1;}
 done:if(m.Frame)MmUnmapIoSpace(m.Frame,G188_FB_MAP_BYTES);for(ULONG i=4;i;i--)if(m.Pipe[i-1])MmUnmapIoSpace(m.Pipe[i-1],4096);if(m.Core)MmUnmapIoSpace(m.Core,4096);if(m.Clock)MmUnmapIoSpace(m.Clock,4096);
 h->End=KeQueryInterruptTime();if(h->Code)InterlockedExchange(&G188Fault,1);InterlockedExchange(&G188Ready,1);Status(&h->Status);
}
VOID G188Control(WDFQUEUE queue,WDFREQUEST request,size_t outputBytes,size_t inputBytes,ULONG code){
 G188_REQUEST*input,in;PVOID output;size_t needed;NTSTATUS status;ULONG_PTR info=0;UNREFERENCED_PARAMETER(queue);
 if(code!=G188_IOCTL_STATUS&&code!=G188_IOCTL_READ&&code!=G188_IOCTL_BLANK&&code!=G188_IOCTL_RESULT){status=STATUS_INVALID_DEVICE_REQUEST;goto done;}
 if(inputBytes!=sizeof(in)){status=STATUS_INVALID_PARAMETER;goto done;}status=WdfRequestRetrieveInputBuffer(request,sizeof(in),(PVOID*)&input,NULL);if(!NT_SUCCESS(status))goto done;in=*input;
 if(in.Size!=sizeof(in)||in.Version!=1||in.Magic!=G188_MAGIC||in.Count||in.Reserved||(code==G188_IOCTL_STATUS?in.Nonce!=0:in.Nonce==0)){status=STATUS_INVALID_PARAMETER;goto done;}
 needed=code==G188_IOCTL_STATUS?sizeof(G188_STATUS):code==G188_IOCTL_BLANK?sizeof(G188_HEADER):sizeof(G188_CAPTURE);if(outputBytes!=needed){status=STATUS_BUFFER_TOO_SMALL;goto done;}status=WdfRequestRetrieveOutputBuffer(request,needed,&output,NULL);if(!NT_SUCCESS(status))goto done;
 if(code==G188_IOCTL_STATUS)Status(output);
 else if(code==G188_IOCTL_RESULT){if(!G188Ready||G188Frozen->Header.Nonce!=in.Nonce){status=STATUS_NOT_FOUND;goto done;}RtlCopyMemory(output,G188Frozen,sizeof(*G188Frozen));}
 else if(code==G188_IOCTL_READ){if(InterlockedCompareExchange(&G188Attempts,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}RtlZeroMemory(G188Frozen,sizeof(*G188Frozen));Operate(G188Frozen,request,in.Nonce,0);RtlCopyMemory(output,G188Frozen,sizeof(*G188Frozen));}
 else{if(!G188Ready||G188Fault||G188Frozen->Header.Nonce!=in.Nonce||G188Frozen->Header.ReadWords!=G188_WORDS){status=STATUS_DEVICE_NOT_READY;goto done;}if(InterlockedCompareExchange(&G188Blank,1,0)){status=STATUS_QUOTA_EXCEEDED;goto done;}Operate(G188Frozen,request,in.Nonce,1);RtlCopyMemory(output,&G188Frozen->Header,sizeof(G188_HEADER));}
 status=STATUS_SUCCESS;info=needed;done:WdfRequestCompleteWithInformation(request,status,info);
}
#include "lifecycle.inc"
