/* SPDX-License-Identifier: MIT -- fixed physical-G17 diagnostic client, no CRT. */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include "g74_client_policy.h"
#include "g74_binding.h"
static union{G74_STATUS Status;G74_SNAPSHOT Snapshot;G74_PMIC Pmic;G74_RUN Run;}Report;
static uint32_t Expected[50];static WCHAR RootDevice[128];static ULONG RootLength,FileOpens,Ioctls;
static void Zero(void*p,ULONG n){volatile UCHAR*b=p;for(ULONG i=0;i<n;i++)b[i]=0;}
static int Equal(const void*a,const void*b,ULONG n){const UCHAR*x=a,*y=b;for(ULONG i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;}
static char*Text(char*p,const char*s){while(*s)*p++=*s++;return p;}
static char*Number(char*p,ULONGLONG n){char b[24];ULONG i=0;do{b[i++]=(char)('0'+n%10);n/=10;}while(n);while(i)*p++=b[--i];return p;}
static void Output(const char*p,ULONG bytes){DWORD done;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),p,bytes,&done,NULL);}
static void Fail(const char*stage,ULONG error)
{
 char b[512],*p=b;p=Text(p,"{\"ok\":false,\"stage\":\"");p=Text(p,stage);p=Text(p,"\",\"error\":");p=Number(p,error);p=Text(p,",\"file_opens\":");p=Number(p,FileOpens);p=Text(p,",\"ioctls\":");p=Number(p,Ioctls);p=Text(p,"}\n");Output(b,(ULONG)(p-b));ExitProcess(1);
}
static void Guard(void)
{
 SYSTEM_INFO si;OSVERSIONINFOW v;UCHAR table[sizeof(G74ExpectedDsdt)];WCHAR root[64],fs[16];DWORD n;
 typedef LONG(WINAPI*VERSION)(OSVERSIONINFOW*);VERSION version;
 GetNativeSystemInfo(&si);if(si.wProcessorArchitecture!=PROCESSOR_ARCHITECTURE_ARM64||si.dwNumberOfProcessors!=8)Fail("architecture",0);
 version=(VERSION)(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlGetVersion");if(!version)Fail("version-api",GetLastError());Zero(&v,sizeof(v));v.dwOSVersionInfoSize=sizeof(v);if(version(&v)<0||v.dwBuildNumber!=26100)Fail("build",v.dwBuildNumber);
 n=GetSystemFirmwareTable(0x41435049u,0x54445344u,NULL,0);if(n!=sizeof(table))Fail("DSDT-length",n);if(GetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table))!=sizeof(table)||!Equal(table,G74ExpectedDsdt,sizeof(table)))Fail("DSDT-bytes",0);
 n=GetWindowsDirectoryW(root,64);if(n!=10||!Equal(root,L"X:\\Windows",22))Fail("windows-root",n);
 n=QueryDosDeviceW(L"X:",RootDevice,128);const WCHAR prefix[]=L"\\Device\\HarddiskVolume";RootLength=0;
 while(RootLength<128&&RootDevice[RootLength])RootLength++;
 ULONG start=(ULONG)(sizeof(prefix)/sizeof(WCHAR))-1;
 if(n<start+2||RootLength<=start||RootLength>=128||!Equal(RootDevice,prefix,start*2))Fail("physical-root",n);
 for(ULONG i=start;i<RootLength;i++)if(RootDevice[i]<L'0'||RootDevice[i]>L'9')Fail("physical-volume",i);
 Zero(fs,sizeof(fs));if(!GetVolumeInformationW(L"X:\\",NULL,0,NULL,NULL,NULL,fs,16)||!Equal(fs,L"NTFS",10))Fail("NTFS-root",GetLastError());
}
static void CheckFile(HANDLE h,const WCHAR*systemPath,int directory)
{
 BY_HANDLE_FILE_INFORMATION info;WCHAR actual[256],expected[256];DWORD n;ULONG i=0;
 if(!GetFileInformationByHandle(h,&info)||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||!!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory)Fail("result-handle-type",GetLastError());
 for(ULONG j=0;j<RootLength;j++)expected[i++]=RootDevice[j];for(ULONG j=2;systemPath[j];j++){if(i>=255)Fail("final-path-capacity",i);expected[i++]=systemPath[j];}expected[i]=0;
 n=GetFinalPathNameByHandleW(h,actual,256,VOLUME_NAME_NT);if(n!=i||!Equal(actual,expected,(i+1)*2))Fail("result-final-physical-path",n);
}
static void Control(HANDLE h,ULONG code,uint64_t nonce,void*out,ULONG size)
{
 G74_REQUEST in={24,1,G74_MAGIC,nonce};DWORD bytes=0;Ioctls++;
 if(!DeviceIoControl(h,code,&in,24,out,size,&bytes,NULL)||bytes!=size)Fail("device-control",GetLastError());
}
void G74Main(void)
{
 uint32_t mode;uint64_t nonceValue;char nonce[33],b[512],*p=b;WCHAR path[160];const WCHAR prefix[]=L"X:\\OpenG17\\payloads\\G74-";HANDLE device,directory,file;DWORD wrote;ULONG size,code,at=0;int qualified;
 _Static_assert(sizeof(WCHAR)==2,"UTF16 ABI");
 if(!G74ClientParse((const uint16_t*)GetCommandLineW(),&mode,nonce,&nonceValue))Fail("arguments",0);Guard();for(ULONG i=0;i<50;i++)Expected[i]=G74ExpectedValues[i];
 FileOpens++;device=CreateFileW(L"\\\\.\\OpenG74",GENERIC_READ|(mode==G74_CLIENT_RUN?GENERIC_WRITE:0),0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(mode==G74_CLIENT_ABSENT){
  if(device!=INVALID_HANDLE_VALUE){CloseHandle(device);Fail("device-present",0);}DWORD error=GetLastError();if(error!=ERROR_FILE_NOT_FOUND&&error!=ERROR_PATH_NOT_FOUND)Fail("device-absence",error);
  const char done[]="{\"ok\":true,\"device_absent\":true,\"ioctls\":0}\n";Output(done,sizeof(done)-1);ExitProcess(0);
 }
 if(device==INVALID_HANDLE_VALUE)Fail("open-device",GetLastError());
 if(mode==G74_CLIENT_RUN){Control(device,G74_IOCTL_STATUS,0,&Report.Status,sizeof(Report.Status));if(!G74ClientReady(&Report.Status))Fail("run-preflight",Report.Status.ObserverCaptures);}
 FileOpens++;directory=CreateFileW(L"X:\\OpenG17\\payloads",FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);if(directory==INVALID_HANDLE_VALUE)Fail("open-project-directory",GetLastError());CheckFile(directory,L"X:\\OpenG17\\payloads",1);
 while(prefix[at]){path[at]=prefix[at];at++;}const char*name=G74ClientMode(mode);while(*name)path[at++]=(WCHAR)*name++;path[at++]=L'-';for(ULONG i=0;i<32;i++)path[at++]=(WCHAR)nonce[i];path[at++]=L'.';path[at++]=L'b';path[at++]=L'i';path[at++]=L'n';path[at]=0;
 FileOpens++;file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,NULL);if(file==INVALID_HANDLE_VALUE)Fail("create-new-result",GetLastError());CheckFile(file,path,0);
 if(mode==G74_CLIENT_STATUS){code=G74_IOCTL_STATUS;size=sizeof(G74_STATUS);}else if(mode==G74_CLIENT_SNAPSHOT){code=G74_IOCTL_SNAPSHOT;size=sizeof(G74_SNAPSHOT);}else if(mode==G74_CLIENT_PMIC){code=G74_IOCTL_PMIC;size=sizeof(G74_PMIC);}else{code=mode==G74_CLIENT_RUN?G74_IOCTL_RUN:G74_IOCTL_RESULT;size=sizeof(G74_RUN);}
 Control(device,code,(mode==G74_CLIENT_RUN||mode==G74_CLIENT_RESULT)?nonceValue:0,&Report,size);
 if(!WriteFile(file,&Report,size,&wrote,NULL)||wrote!=size||!FlushFileBuffers(file))Fail("save-raw-result",GetLastError());CloseHandle(file);CloseHandle(directory);CloseHandle(device);
 qualified=mode==G74_CLIENT_STATUS?G74ClientStatus(&Report.Status):mode==G74_CLIENT_SNAPSHOT?G74ClientSnapshot(&Report.Snapshot,Expected):mode==G74_CLIENT_PMIC?G74ClientPmic(&Report.Pmic):G74ClientRun(&Report.Run,Expected,nonceValue);
 p=Text(p,"{\"ok\":");p=Text(p,qualified?"true":"false");p=Text(p,",\"captured\":true,\"mode\":\"");p=Text(p,G74ClientMode(mode));p=Text(p,"\",\"token\":\"");p=Text(p,nonce);p=Text(p,"\",\"bytes\":");p=Number(p,size);p=Text(p,",\"file_opens\":");p=Number(p,FileOpens);p=Text(p,",\"ioctls\":");p=Number(p,Ioctls);
 if(mode==G74_CLIENT_RUN||mode==G74_CLIENT_RESULT){p=Text(p,",\"code\":");p=Number(p,Report.Run.Off.Code);p=Text(p,",\"restore_error\":");p=Number(p,Report.Run.Off.RestoreError);p=Text(p,",\"restored\":");p=Number(p,Report.Run.Off.Restored);}
 p=Text(p,"}\n");Output(b,(ULONG)(p-b));ExitProcess(qualified?0:1);
}
