/* SPDX-License-Identifier: MIT -- no CRT, no arbitrary paths or MMIO. */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cfgmgr32.h>
#include "g70_client_policy.h"
#include "g70_binding.h"
static const GUID Interface={0x2f1df03e,0xa4ab,0x4e14,{0xa5,0x87,0x32,0xaf,0x76,0xb2,0x39,0x70}};
static const GUID *volatile InterfacePointer=&Interface;
static ULONG InterfacesQueried,FileOpens,Ioctls;
static void Zero(void*p,ULONG n){volatile UCHAR*b=p;for(ULONG i=0;i<n;i++)b[i]=0;}
static int Equal(const void*a,const void*b,ULONG n){const UCHAR*x=a,*y=b;for(ULONG i=0;i<n;i++)if(x[i]!=y[i])return 0;return 1;}
static char*Text(char*p,const char*s){while(*s)*p++=*s++;return p;}
static char*Number(char*p,ULONGLONG n){char b[24];ULONG i=0;do{b[i++]=(char)('0'+n%10);n/=10;}while(n);while(i)*p++=b[--i];return p;}
static void Output(const char*s,ULONG bytes){DWORD done=0;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,bytes,&done,NULL);}
static void Fail(const char*stage,ULONG error)
{
 char b[512],*p=b;p=Text(p,"{\"ok\":false,\"stage\":\"");p=Text(p,stage);p=Text(p,"\",\"error\":");p=Number(p,error);p=Text(p,",\"interfaces_queried\":");p=Number(p,InterfacesQueried);p=Text(p,",\"file_opens\":");p=Number(p,FileOpens);p=Text(p,",\"ioctls\":");p=Number(p,Ioctls);p=Text(p,"}\n");Output(b,(ULONG)(p-b));ExitProcess(1);
}
static void Guard(void)
{
 SYSTEM_INFO si;OSVERSIONINFOW version;UCHAR table[sizeof(G70ExpectedDsdt)];WCHAR root[64],device[256];DWORD n;
 typedef LONG(WINAPI*VERSION)(OSVERSIONINFOW*);VERSION getVersion;
 GetNativeSystemInfo(&si);if(si.wProcessorArchitecture!=PROCESSOR_ARCHITECTURE_ARM64||si.dwNumberOfProcessors!=8)Fail("architecture",0);
 getVersion=(VERSION)(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlGetVersion");if(!getVersion)Fail("version-api",GetLastError());Zero(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(getVersion(&version)<0||version.dwBuildNumber!=26100)Fail("build",version.dwBuildNumber);
 n=GetSystemFirmwareTable(0x41435049u,0x54445344u,NULL,0);if(n!=sizeof(table))Fail("DSDT-length",n);if(GetSystemFirmwareTable(0x41435049u,0x54445344u,table,sizeof(table))!=sizeof(table)||!Equal(table,G70ExpectedDsdt,sizeof(table)))Fail("DSDT-bytes",0);
 n=GetWindowsDirectoryW(root,64);if(n!=10||!Equal(root,L"X:\\Windows",22))Fail("windows-root",n);
 n=QueryDosDeviceW(L"X:",device,256);if(n<18||!Equal(device,L"\\Device\\Ramdisk{",32))Fail("RAM-root",n);
}
static HANDLE OpenInterface(ULONG cycle)
{
 ULONG n=0;WCHAR paths[512];CONFIGRET cr;ULONG i;HANDLE handle;HMODULE configmgr;
 typedef CONFIGRET(WINAPI*SIZE)(PULONG,LPGUID,DEVINSTID_W,ULONG);
 typedef CONFIGRET(WINAPI*LIST)(LPGUID,DEVINSTID_W,PZZWSTR,ULONG,ULONG);
 SIZE size;LIST list;
 configmgr=LoadLibraryExW(L"cfgmgr32.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32);if(!configmgr)Fail("configmgr-module",GetLastError());
 size=(SIZE)(void*)GetProcAddress(configmgr,"CM_Get_Device_Interface_List_SizeW");list=(LIST)(void*)GetProcAddress(configmgr,"CM_Get_Device_Interface_ListW");if(!size||!list)Fail("configmgr-procedures",GetLastError());
 InterfacesQueried++;cr=size(&n,(LPGUID)InterfacePointer,L"ACPI\\OPEN0070\\0",CM_GET_DEVICE_INTERFACE_LIST_PRESENT);if(cr||n<3||n>512)Fail("interface-size",cr);
 for(i=0;i<512;i++)paths[i]=0;
 InterfacesQueried++;cr=list((LPGUID)InterfacePointer,L"ACPI\\OPEN0070\\0",paths,n,CM_GET_DEVICE_INTERFACE_LIST_PRESENT);if(cr)Fail("interface-list",cr);
 for(i=0;i<n&&paths[i];i++){}if(i+2!=n||paths[i+1]||i<21||!Equal(paths,L"\\\\?\\ACPI#OPEN0070#0#",40))Fail("single-owned-interface",n);
 FileOpens++;handle=CreateFileW(paths,GENERIC_READ|(cycle?GENERIC_WRITE:0),0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(handle==INVALID_HANDLE_VALUE)Fail("open-interface",GetLastError());return handle;
}
static void Control(HANDLE handle,ULONG code,ULONGLONG nonce,G70_REPORT*out)
{
 G70_REQUEST in={sizeof(in),1,G70_MAGIC,nonce};DWORD bytes=0;Ioctls++;
 if(!DeviceIoControl(handle,code,&in,sizeof(in),out,sizeof(*out),&bytes,NULL)||bytes!=sizeof(*out))Fail("device-control",GetLastError());
}
static void CheckRAMHandle(HANDLE handle,int directory)
{
 BY_HANDLE_FILE_INFORMATION info;WCHAR path[256];DWORD n;
 if(!GetFileInformationByHandle(handle,&info)||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||!!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory)Fail("result-handle-type",GetLastError());
 n=GetFinalPathNameByHandleW(handle,path,256,VOLUME_NAME_NT);if(n<18||n>=256||!Equal(path,L"\\Device\\Ramdisk{",32))Fail("result-final-RAM-path",n);
}
void G70Main(void)
{
 uint32_t cycle=0;uint64_t nonceValue=0;char nonce[33],output[512],*p=output;WCHAR path[128];const WCHAR prefix[]=L"X:\\OpenG17\\payloads\\G70-consumer-";ULONG at=0,i;HANDLE device,file,directory;G70_REPORT report;DWORD wrote;int qualified=0;
 _Static_assert(sizeof(WCHAR)==2,"UTF16 Windows ABI");
 if(!G70ClientParse((const uint16_t*)GetCommandLineW(),&cycle,nonce,&nonceValue))Fail("arguments",0);
 Guard();device=OpenInterface(cycle);Control(device,G70_IOCTL_QUERY,0,&report);
 if(!G70ClientReportShape(&report,sizeof(G70ExpectedDsdt))||(cycle&&!G70ClientReadyForCycle(&report,sizeof(G70ExpectedDsdt))))Fail("owned-fresh-report",0);
 FileOpens++;directory=CreateFileW(L"X:\\OpenG17\\payloads",FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);if(directory==INVALID_HANDLE_VALUE)Fail("open-RAM-result-directory",GetLastError());CheckRAMHandle(directory,1);
 while(prefix[at]){path[at]=prefix[at];at++;}for(i=0;i<32;i++)path[at++]=(WCHAR)nonce[i];path[at++]=L'.';path[at++]=L'b';path[at++]=L'i';path[at++]=L'n';path[at]=0;
 FileOpens++;file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,NULL);if(file==INVALID_HANDLE_VALUE)Fail("create-new-result",GetLastError());CheckRAMHandle(file,0);
 if(cycle){Control(device,G70_IOCTL_CYCLE,nonceValue,&report);qualified=G70ClientCycleComplete(&report,sizeof(G70ExpectedDsdt),nonceValue);}
 if(!WriteFile(file,&report,sizeof(report),&wrote,NULL)||wrote!=sizeof(report)||!FlushFileBuffers(file))Fail("save-raw-result",GetLastError());CloseHandle(file);CloseHandle(directory);CloseHandle(device);
 p=Text(p,"{\"ok\":");p=Text(p,cycle&&!qualified?"false":"true");p=Text(p,",\"captured\":true,\"mode\":\"");p=Text(p,cycle?"cycle":"query");p=Text(p,"\",\"nonce\":\"");p=Text(p,nonce);p=Text(p,"\",\"bytes\":2056,\"code\":");p=Number(p,report.Clock.Code);p=Text(p,",\"restore_error\":");p=Number(p,report.Clock.RestoreError);p=Text(p,",\"restored\":");p=Number(p,report.Clock.Restored);p=Text(p,",\"probe_code\":");p=Number(p,report.Probe.Code);p=Text(p,",\"engine_reads\":");p=Number(p,report.Probe.ReadCount);p=Text(p,"}\n");Output(output,(ULONG)(p-output));ExitProcess(cycle&&!qualified?1:0);
}
