#include "gpu_owner.h"
#include "OpenInputPins.h"
#define UINTN SIZE_T
#define STATIC static
#define CopyMem RtlCopyMemory
#define ZeroMem RtlZeroMemory
#include "OpenSha256.h"
#undef UINTN
#undef STATIC
#undef CopyMem
#undef ZeroMem
static PCWSTR Names[6]={L"\\SystemRoot\\System32\\drivers\\OpenGpuInputs\\fdt.bin",L"\\SystemRoot\\System32\\drivers\\OpenGpuInputs\\smem-first.bin",L"\\SystemRoot\\System32\\drivers\\OpenGpuInputs\\smem-second.bin",L"\\SystemRoot\\System32\\drivers\\OpenGpuInputs\\cmddb.bin",L"\\SystemRoot\\System32\\drivers\\OpenGpuInputs\\gmu.bin",L"\\SystemRoot\\System32\\drivers\\OpenGpuInputs\\rsc.bin"};
VOID OgoFreeInputs(OGO_CONTEXT*p){for(ULONG i=0;i<6;i++)if(p->Input[i]){ExFreePoolWithTag(p->Input[i],OGO_TAG);p->Input[i]=NULL;}RtlZeroMemory(&p->Inputs,sizeof(p->Inputs));}
NTSTATUS OgoLoadInputs(OGO_CONTEXT*p){
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return STATUS_INVALID_DEVICE_STATE;
 for(ULONG i=0;i<6;i++)if(p->Input[i])return STATUS_INVALID_DEVICE_STATE;
 NTSTATUS st=STATUS_SUCCESS;
 for(ULONG i=0;i<6;i++){
  UNICODE_STRING name;OBJECT_ATTRIBUTES oa;IO_STATUS_BLOCK iosb;HANDLE file=NULL;FILE_STANDARD_INFORMATION info;UCHAR sha[32];
  RtlInitUnicodeString(&name,Names[i]);InitializeObjectAttributes(&oa,&name,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
  st=ZwCreateFile(&file,FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE,&oa,&iosb,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN,FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,NULL,0);
  if(st!=STATUS_SUCCESS)break;
  st=ZwQueryInformationFile(file,&iosb,&info,sizeof(info),FileStandardInformation);
  if(st==STATUS_SUCCESS&&(info.Directory||info.EndOfFile.QuadPart!=InputBytes[i]))st=STATUS_INVALID_IMAGE_HASH;
  if(st==STATUS_SUCCESS){p->Input[i]=ExAllocatePool2(POOL_FLAG_NON_PAGED,InputBytes[i],OGO_TAG);if(!p->Input[i])st=STATUS_INSUFFICIENT_RESOURCES;}
  if(st==STATUS_SUCCESS){LARGE_INTEGER zero={0};st=ZwReadFile(file,NULL,NULL,NULL,&iosb,p->Input[i],InputBytes[i],&zero,NULL);if(st==STATUS_SUCCESS&&iosb.Information!=InputBytes[i])st=STATUS_END_OF_FILE;}
  ZwClose(file);if(st!=STATUS_SUCCESS)break;
  OpenShaAll(p->Input[i],InputBytes[i],sha);if(RtlCompareMemory(sha,InputSha[i],32)!=32){st=STATUS_INVALID_IMAGE_HASH;break;}
 }
 if(st!=STATUS_SUCCESS){OgoFreeInputs(p);return p->InputStatus=st;}
 p->Inputs=(g196_inputs){{p->Input[0],InputBytes[0]},{p->Input[1],InputBytes[1]},{p->Input[2],InputBytes[2]},{p->Input[3],InputBytes[3]},{p->Input[4],InputBytes[4]}};
 return p->InputStatus=STATUS_SUCCESS;
}
