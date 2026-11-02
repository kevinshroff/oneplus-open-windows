static int WinPE(void)
{
 UNICODE_STRING name;OBJECT_ATTRIBUTES attributes;HANDLE key;NTSTATUS status;ULONG bytes=0;
 union {KEY_VALUE_PARTIAL_INFORMATION Info;UCHAR Storage[128];}value={0};
 static const WCHAR expected[]=L"X:\\Windows";
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL)return 0;
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\MiniNT");InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);if(!NT_SUCCESS(status))return 0;ZwClose(key);
 RtlInitUnicodeString(&name,L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");InitializeObjectAttributes(&attributes,&name,OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,NULL,NULL);
 status=ZwOpenKey(&key,KEY_QUERY_VALUE,&attributes);if(!NT_SUCCESS(status))return 0;
 RtlInitUnicodeString(&name,L"SystemRoot");status=ZwQueryValueKey(key,&name,KeyValuePartialInformation,&value,sizeof(value),&bytes);ZwClose(key);
 return NT_SUCCESS(status)&&bytes>=FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data)&&bytes<=sizeof(value)&&value.Info.Type==REG_SZ&&(value.Info.DataLength==sizeof(expected)||value.Info.DataLength==sizeof(expected)-sizeof(WCHAR))&&bytes>=FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION,Data)+value.Info.DataLength&&RtlCompareMemory(value.Info.Data,expected,value.Info.DataLength)==value.Info.DataLength;
}
