"""Execute the actual kernel admission registry guard with UTF-16 service models."""
from pathlib import Path
import argparse,re,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();O=a.output.resolve();assert not O.exists();O.mkdir();W=Path(__file__).resolve().parent;s=(W/'g98_driver.c').read_text();m=re.search(r'^static int FullWindows\(',s,re.M);at=s.index('{',m.end())+1;d=1
while d:d+=(s[at]=='{')-(s[at]=='}');at+=1
function=s[m.start():at]
body=r'''#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
typedef uint8_t UCHAR;typedef uint32_t ULONG;typedef int32_t NTSTATUS;typedef __WCHAR_TYPE__ WCHAR;typedef void*HANDLE;typedef struct{const WCHAR*Buffer;}UNICODE_STRING;typedef struct{const UNICODE_STRING*Name;ULONG Flags;}OBJECT_ATTRIBUTES;typedef struct{ULONG TitleIndex,Type,DataLength;UCHAR Data[1];}KEY_VALUE_PARTIAL_INFORMATION;
#define PASSIVE_LEVEL 0
#define OBJ_KERNEL_HANDLE 0x200
#define OBJ_CASE_INSENSITIVE 0x40
#define KEY_QUERY_VALUE 1
#define KeyValuePartialInformation 2
#define REG_SZ 1
#define NT_SUCCESS(x) ((x)>=0)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xc0000034)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xc000003a)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define RtlCompareMemory(a,b,n) (memcmp(a,b,n)?0:(n))
#define InitializeObjectAttributes(a,n,f,r,s) ((a)->Name=(n),(a)->Flags=(f))
static unsigned Scenario,Opens,Closes;
static unsigned KeGetCurrentIrql(void){return Scenario==13?2:0;}
static void RtlInitUnicodeString(UNICODE_STRING*s,const WCHAR*text){s->Buffer=text;}
static NTSTATUS ZwOpenKey(HANDLE*out,ULONG access,OBJECT_ATTRIBUTES*a){assert(access==1&&a->Flags==0x240);Opens++;if(Opens==1){if(Scenario==1){*out=(void*)1;return 0;}if(Scenario==2)return(NTSTATUS)0xc0000022;return Scenario==3?STATUS_OBJECT_PATH_NOT_FOUND:STATUS_OBJECT_NAME_NOT_FOUND;}if(Scenario==4)return STATUS_OBJECT_NAME_NOT_FOUND;*out=(void*)2;return 0;}
static NTSTATUS ZwClose(HANDLE h){assert(h==(void*)1||h==(void*)2);Closes++;return 0;}
static NTSTATUS ZwQueryValueKey(HANDLE h,UNICODE_STRING*n,unsigned kind,void*out,ULONG size,ULONG*returned){assert(h==(void*)2&&n->Buffer&&kind==2&&size==128);if(Scenario==5)return(NTSTATUS)0xc0000023;KEY_VALUE_PARTIAL_INFORMATION*v=out;const WCHAR text[]=L"C:\\Windows";memset(out,0,size);v->Type=Scenario==6?4:1;v->DataLength=Scenario==7||Scenario==12?20:Scenario==10?24:22;memcpy(v->Data,text,sizeof(text));if(Scenario==8)v->Data[0]='X';if(Scenario==11)v->Data[20]='!';*returned=Scenario==9?12:Scenario==14?129:12+v->DataLength;return 0;}
'''+function+r'''
int main(void){unsigned cases=0;for(Scenario=0;Scenario<15;Scenario++){Opens=Closes=0;int expected=Scenario==0||Scenario==3||Scenario==7||Scenario==12;assert(FullWindows()==expected);assert(Closes==(Scenario==13||Scenario==2||Scenario==4?0:1));cases++;}printf("{\"passed\":true,\"cases\":%u,\"actual_kernel_registry_guard\":true,\"UTF16_layout\":true,\"registry_services_modeled\":true,\"native_operations\":0}\n",cases);return 0;}
'''
f=O/'model.c';f.write_text(body);exe=O/'model';q=subprocess.run(['clang','-std=c11','-fshort-wchar','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(f),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r['function_sha256']=hashlib.sha256(function.encode()).hexdigest();(O/'tests.json').write_text(json.dumps(r,indent=2));print(json.dumps(r))
