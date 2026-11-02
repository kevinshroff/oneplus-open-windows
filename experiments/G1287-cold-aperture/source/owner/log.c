/* SPDX-License-Identifier: MIT
 * Original synchronous probe logger. No thread can outlive the driver image.
 */
#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdarg.h>
static HANDLE g_File;
static KMUTEX g_LogLock;
VOID LogOpen(VOID)
{
    UNICODE_STRING name;OBJECT_ATTRIBUTES oa;IO_STATUS_BLOCK iosb;
    KeInitializeMutex(&g_LogLock,0);
    RtlInitUnicodeString(&name,L"\\??\\C:\\OpenGpuStart.log");
    InitializeObjectAttributes(&oa,&name,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
    if(!NT_SUCCESS(ZwCreateFile(&g_File,FILE_APPEND_DATA|SYNCHRONIZE,&oa,&iosb,NULL,
       FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_OPEN_IF,
       FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE|FILE_WRITE_THROUGH,NULL,0)))
        g_File=NULL;
}
VOID LogClose(VOID)
{
    KeWaitForSingleObject(&g_LogLock,Executive,KernelMode,FALSE,NULL);
    if(g_File) {ZwClose(g_File);g_File=NULL;}
    KeReleaseMutex(&g_LogLock,FALSE);
}
VOID LogPrint(PCSTR Fmt,...)
{
    va_list args;CHAR text[512];SIZE_T length=0;IO_STATUS_BLOCK iosb;NTSTATUS st;
    va_start(args,Fmt);
    if(KeGetCurrentIrql()!=PASSIVE_LEVEL) {
        vDbgPrintExWithPrefix("OpenGpuStart: ",DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,Fmt,args);
        va_end(args);return;
    }
    st=RtlStringCbVPrintfA(text,sizeof(text),Fmt,args);va_end(args);
    if(!NT_SUCCESS(st)&&st!=STATUS_BUFFER_OVERFLOW) return;
    DbgPrintEx(DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,"OpenGpuStart: %s",text);
    if(!NT_SUCCESS(RtlStringCbLengthA(text,sizeof(text),&length))) return;
    KeWaitForSingleObject(&g_LogLock,Executive,KernelMode,FALSE,NULL);
    if(g_File) (void)ZwWriteFile(g_File,NULL,NULL,NULL,&iosb,text,(ULONG)length,NULL,NULL);
    KeReleaseMutex(&g_LogLock,FALSE);
}
VOID LogHex(PCSTR Prefix,const UCHAR *Buf,ULONG Len)
{
    UNREFERENCED_PARAMETER(Buf);LogPrint("%s bytes %u (hex dump disabled in capability probe)\n",Prefix,Len);
}
