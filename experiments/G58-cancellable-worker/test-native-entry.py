"""Compile the full native adapter against aborting test-only kernel services."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
shim=(W/'driver-model-prefix.h').read_text()+r'''
typedef int64_t LONGLONG;typedef uint32_t*PULONG;typedef int BOOLEAN;typedef struct{int64_t QuadPart;}LARGE_INTEGER;typedef LARGE_INTEGER PHYSICAL_ADDRESS;
#define RTL_NUMBER_OF(a) (sizeof(a)/sizeof((a)[0]))
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_NOCACHE 0x200
#define STATUS_DEVICE_REMOVED ((NTSTATUS)0xc00002b6)
#define KeMemoryBarrier() __atomic_thread_fence(__ATOMIC_SEQ_CST)
ULONG KeQueryActiveProcessorCountEx(ULONG);ULONG KeGetCurrentIrql(void);NTSTATUS RtlGetVersion(RTL_OSVERSIONINFOW*);NTSTATUS AuxKlibGetSystemFirmwareTable(ULONG,ULONG,void*,ULONG,ULONG*);ULONGLONG KeQueryInterruptTime(void);LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER*);PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS,SIZE_T,ULONG);VOID MmUnmapIoSpace(PVOID,SIZE_T);ULONG TestRead(PULONG);VOID TestWrite(PULONG,ULONG);VOID KeStallExecutionProcessor(ULONG);NTSTATUS KeDelayExecutionThread(int,int,LARGE_INTEGER*);
#define READ_REGISTER_ULONG(p) TestRead(p)
#define WRITE_REGISTER_ULONG(p,v) TestWrite(p,v)
'''
(a.output/'ntddk.h').write_text(shim)
for name in ['wdf.h','aux_klib.h']:(a.output/name).write_text('/* Test-only framework header: no services used. */\n')
cores=['g58_observer.c','g58_rsc.c','g58_power.c','g58_spi.c','g58_engine.c','g58_touch.c','g58_contract.c','g58_plan.c','g58_report.c','g58_poll.c','geni_fifo.c','g58_input.c','g58hid_lifecycle.c'];names=cores+['g58_hardware.c','g58_hwapi.h','g58_protocol.h','native-entry-model.c','driver-model-prefix.h'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();before={n:sha(W/n)for n in names};exe=a.output/'test'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-const-variable','-fsanitize=address,undefined','-I',str(a.output),'-I',str(W),'-I',str(W/'private/inputs'if(W/'private/inputs').is_dir()else W/'inputs'),str(W/'native-entry-model.c'),*[str(W/n)for n in cores],'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);assert all(sha(W/n)==h for n,h in before.items());v.update(ASan_UBSan=True,source_sha256=before,native_operations=0,limits=['All kernel services and firmware identity responses are test models.','The mapping failure and refusal cases deliberately abort any actual modeled register read/write.']);(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
