"""Run the actual WinPE registry guard under explicit malformed OS models."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
w=Path(__file__).resolve().parent;o=a.output.resolve();assert not o.exists();o.mkdir(parents=True)
s=(w/'guard-and-status.inc').read_text();start=s.index('static int WinPE(void)');end=s.index('\nstatic void Status',start)
prefix=r'''
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
typedef wchar_t WCHAR;typedef uint8_t UCHAR;typedef uint32_t ULONG;typedef int32_t NTSTATUS;typedef void* HANDLE;
typedef struct{const WCHAR*Buffer;}UNICODE_STRING;
typedef struct{UNICODE_STRING*Name;}OBJECT_ATTRIBUTES;
typedef struct{ULONG TitleIndex,Type,DataLength;UCHAR Data[1];}KEY_VALUE_PARTIAL_INFORMATION;
#define PASSIVE_LEVEL 0
#define OBJ_KERNEL_HANDLE 1
#define OBJ_CASE_INSENSITIVE 2
#define KEY_QUERY_VALUE 1
#define KeyValuePartialInformation 2
#define REG_SZ 1
#define NT_SUCCESS(s) ((s)>=0)
#define FIELD_OFFSET(t,m) offsetof(t,m)
static ULONG Irql,Opens,Closes,Queries,Type,Length,ReturnedBytes,MutateRoot;
static NTSTATUS MiniStatus,RootStatus,QueryStatus;
static const WCHAR Root[]=L"X:\\Windows";
static ULONG KeGetCurrentIrql(void){return Irql;}
static void RtlInitUnicodeString(UNICODE_STRING*s,const WCHAR*p){s->Buffer=p;}
static void InitializeObjectAttributes(OBJECT_ATTRIBUTES*a,UNICODE_STRING*n,ULONG flags,void*x,void*y){assert(flags==3&&!x&&!y);a->Name=n;}
static NTSTATUS ZwOpenKey(HANDLE*k,ULONG flags,OBJECT_ATTRIBUTES*a){assert(flags==1&&a->Name->Buffer);Opens++;NTSTATUS r=Opens==1?MiniStatus:RootStatus;if(NT_SUCCESS(r))*k=(void*)(uintptr_t)Opens;return r;}
static NTSTATUS ZwClose(HANDLE h){assert((uintptr_t)h==1||(uintptr_t)h==2);Closes++;return 0;}
static NTSTATUS ZwQueryValueKey(HANDLE h,UNICODE_STRING*n,ULONG kind,void*out,ULONG capacity,ULONG*got){assert((uintptr_t)h==2&&n->Buffer&&kind==2&&capacity==128);Queries++;KEY_VALUE_PARTIAL_INFORMATION*v=out;v->Type=Type;v->DataLength=Length;memcpy(v->Data,Root,sizeof(Root));if(MutateRoot)v->Data[0]='C';*got=ReturnedBytes;return QueryStatus;}
static size_t RtlCompareMemory(const void*a,const void*b,size_t n){const UCHAR*x=a,*y=b;size_t i=0;for(;i<n&&x[i]==y[i];i++){}return i;}
static void Reset(void){Irql=Opens=Closes=Queries=MutateRoot=0;MiniStatus=RootStatus=QueryStatus=0;Type=1;Length=sizeof(Root);ReturnedBytes=(ULONG)(offsetof(KEY_VALUE_PARTIAL_INFORMATION,Data)+Length);}
'''
main=r'''
int main(void){unsigned cases=0;_Static_assert(sizeof(WCHAR)==2,"Windows UTF16");
 Reset();assert(WinPE()&&Opens==2&&Closes==2&&Queries==1);cases++;
 Reset();Length-=2;ReturnedBytes-=2;assert(WinPE()&&Closes==2);cases++;
 for(unsigned i=0;i<10;i++){Reset();
  if(i==0)Irql=1;if(i==1)MiniStatus=-1;if(i==2)RootStatus=-1;if(i==3)QueryStatus=-1;
  if(i==4)Type=4;if(i==5)Length=0;if(i==6)Length=sizeof(Root)-1;
  if(i==7)ReturnedBytes=129;if(i==8)ReturnedBytes=11;if(i==9)MutateRoot=1;
  assert(!WinPE());assert(Closes==(i==0||i==1?0u:i==2?1u:2u));cases++;
 }
 Reset();ReturnedBytes--;assert(!WinPE()&&Closes==2);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_WinPE_function\":true,\"registry_and_IRQL_modeled\":true,\"all_opened_keys_closed\":true,\"native_operations\":0}\n",cases);return 0;}
'''
f=o/'model.c';f.write_text(prefix+s[start:end]+main)
q=subprocess.run(['clang','-std=c11','-O1','-fshort-wchar','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(f),'-o',str(o/'test')],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(o/'test')],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr)
r=json.loads(q.stdout);r['guard_sha256']=hashlib.sha256((w/'guard-and-status.inc').read_bytes()).hexdigest();(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
