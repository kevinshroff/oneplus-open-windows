#include "os_identity.h"
static int TargetOsMode(uint32_t build)
{
 UNICODE_STRING name;OBJECT_ATTRIBUTES attributes;HANDLE key;NTSTATUS status;ULONG bytes=0;
 union {KEY_VALUE_PARTIAL_INFORMATION Info;UCHAR Storage[128];}value={0};int mini;
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return 0;
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\MiniNT");
 InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);
 if(NT_SUCCESS(status)){mini=1;ZwClose(key);}
 else if(status==STATUS_OBJECT_NAME_NOT_FOUND||status==STATUS_OBJECT_PATH_NOT_FOUND)mini=0;
 else return 0;
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
 InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);if(!NT_SUCCESS(status))return 0;
 RtlInitUnicodeString(&name,L"SystemRoot");
 status=ZwQueryValueKey(key,&name,KeyValuePartialInformation,&value,sizeof(value),&bytes);ZwClose(key);
 const ULONG offset=FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data);
 if(!NT_SUCCESS(status)||bytes<offset||bytes>sizeof(value)||value.Info.DataLength>bytes-offset)return 0;
 return (int)Op184OsMode(build,mini,value.Info.Type,(const uint16_t*)value.Info.Data,value.Info.DataLength);
}
