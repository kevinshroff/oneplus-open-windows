/* Execute the actual registry wrapper; NT registry/IRQL are explicit models. */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef uint32_t ULONG;typedef uint8_t UCHAR;typedef int32_t NTSTATUS;
typedef struct{const wchar_t*Buffer;}UNICODE_STRING;
typedef struct{UNICODE_STRING*Name;}OBJECT_ATTRIBUTES;typedef uintptr_t HANDLE;
typedef struct{ULONG TitleIndex,Type,DataLength;UCHAR Data[1];}KEY_VALUE_PARTIAL_INFORMATION;
#define PASSIVE_LEVEL 0
#define OBJ_KERNEL_HANDLE 1
#define OBJ_CASE_INSENSITIVE 2
#define KEY_QUERY_VALUE 1
#define KeyValuePartialInformation 1
#define NT_SUCCESS(s) ((s)>=0)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)-1)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)-2)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define InitializeObjectAttributes(a,n,f,r,s) do{assert((f)==3&&!(r)&&!(s));(a)->Name=n;}while(0)
static unsigned Irql,Opened,Closed,Queried;
static NTSTATUS Mini,Software,Query;
static uint32_t Returned,Type,Length;
static uint16_t Root[11];
static unsigned KeGetCurrentIrql(void){return Irql;}
static void RtlInitUnicodeString(UNICODE_STRING*s,const wchar_t*p){s->Buffer=p;}
static NTSTATUS ZwOpenKey(HANDLE*h,ULONG access,OBJECT_ATTRIBUTES*a){assert(access==1);int mini=wcsstr(a->Name->Buffer,L"MiniNT")!=NULL;NTSTATUS s=mini?Mini:Software;if(s>=0){*h=mini?1:2;Opened++;}return s;}
static void ZwClose(HANDLE h){assert(h==1||h==2);Closed++;}
static NTSTATUS ZwQueryValueKey(HANDLE h,UNICODE_STRING*n,unsigned cls,void*b,ULONG cap,ULONG*bytes){assert(h==2&&!wcscmp(n->Buffer,L"SystemRoot")&&cls==1&&cap==128);Queried++;KEY_VALUE_PARTIAL_INFORMATION*v=b;v->Type=Type;v->DataLength=Length;memcpy(v->Data,Root,sizeof(Root));*bytes=Returned;return Query;}
#include "../source/identity.inc"
static void Reset(int normal){Irql=Opened=Closed=Queried=0;Mini=normal?STATUS_OBJECT_NAME_NOT_FOUND:0;Software=Query=0;Returned=34;Type=1;Length=22;const uint16_t root[]={'X',':','\\','W','i','n','d','o','w','s',0};memcpy(Root,root,sizeof(Root));if(normal)Root[0]='C';}
int main(void){unsigned cases=0;
 for(int normal=0;normal<2;normal++)for(unsigned n=0;n<27;n++){
  Reset(normal);uint32_t build=normal?26300:26100;int expected=normal?2:1;
  switch(n){
   case 0:break;case 1:Length=20;Returned=32;break;
   case 2:Root[0]+='a'-'A';Root[3]='w';break;
   case 3:Mini=STATUS_OBJECT_PATH_NOT_FOUND;if(!normal)expected=0;break;
   case 4:Mini=-3;expected=0;break;case 5:Software=-3;expected=0;break;
   case 6:Query=-3;expected=0;break;case 7:Returned=11;expected=0;break;
   case 8:Returned=129;expected=0;break;case 9:Returned=33;expected=0;break;
   case 10:Length=24;expected=0;break;case 11:Length=21;expected=0;break;
   case 12:Length=0;expected=0;break;case 13:Type=2;expected=0;break;
   case 14:Root[10]='!';expected=0;break;case 15:Root[5]=0;expected=0;break;
   case 16:Root[0]='D';expected=0;break;case 17:Root[0]=normal?'X':'C';expected=0;break;
   case 18:build=normal?26100:26300;expected=0;break;
   case 19:build++;expected=0;break;case 20:Irql=1;expected=0;break;
   case 21:Mini=normal?0:STATUS_OBJECT_NAME_NOT_FOUND;expected=0;break;
   case 22:Length=UINT32_MAX;expected=0;break;
   case 23:Root[2]='/';expected=0;break;case 24:Root[9]='x';expected=0;break;
   case 25:Type=0;expected=0;break;case 26:Returned=0;expected=0;break;
  }
  assert(TargetOsMode(build)==expected);assert(Opened==Closed);if(Irql)assert(!Opened&&!Queried);cases++;
 }
 assert(!Op184OsMode(26300,0,1,NULL,22));assert(!Op184OsMode(26300,-1,1,Root,22));
 printf("{\"passed\":true,\"actual_registry_wrapper_cases\":%u,\"null_or_error_cases\":2,\"native_operations\":0}\n",cases);
}
