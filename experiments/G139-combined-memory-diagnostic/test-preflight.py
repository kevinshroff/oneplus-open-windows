"""Compile the actual adapter against UEFI headers and execute service-model cases."""
from pathlib import Path
import hashlib,json,struct,subprocess,uuid,zlib

w=Path(__file__).resolve().parent
root=Path('/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms')
capture=w.parent/'charging-G118/private/firmware-input'
lib=w/'private/candidate-source/Platforms/AndromedaPkg/Library/DeviceBootManagerLib'
fixture=w/'private/test-input'
fixture.mkdir(exist_ok=True)
sha=lambda b:hashlib.sha256(b).hexdigest()
m=json.loads((capture/'capture.json').read_text())
# A valid synthetic parent GPT is the explicit service-model boundary. The
# selected child identity, file hashes and relevant metadata stay from G118.
array=bytearray(4096)
array[:16]=uuid.UUID(m['target']['TypeGUID']).bytes_le
array[16:32]=uuid.UUID(m['target']['PartitionGUID']).bytes_le
struct.pack_into('<QQQ',array,32,4614,81413,0)
array[56:70]='modem_a'.encode('utf-16le')
header=bytearray(4096)
header[:8]=b'EFI PART'
struct.pack_into('<IIIIQQQQ',header,8,0x10000,92,0,0,1,m['target']['DiskBytes']//4096-1,6,m['target']['DiskBytes']//4096-6)
header[56:72]=uuid.UUID(m['target']['DiskGUID']).bytes_le
struct.pack_into('<QIII',header,72,2,1,128,zlib.crc32(array[:128]))
struct.pack_into('<I',header,16,zlib.crc32(header[:92]))
(fixture/'test-gpt-header.bin').write_bytes(header)
(fixture/'test-gpt-array.bin').write_bytes(array)
binding=(lib/'OpenAdspInputs.h').read_text()
def hex_c(h):return '{'+','.join('0x'+h[i:i+2]for i in range(0,len(h),2))+'}'
for name,original,data in [('mSourceHeaderHash',m['GPT_header_sha256'],header),('mSourceArrayHash',m['GPT_array_sha256'],array[:128])]:
    old=f'STATIC CONST UINT8 {name}[32] = '+hex_c(original)+';'
    assert binding.count(old)==1
    binding=binding.replace(old,f'STATIC CONST UINT8 {name}[32] = '+hex_c(sha(data))+';')
(fixture/'TestAdspInputs.h').write_text(binding)
incs=[root/x for x in ['MU_BASECORE/MdePkg/Include','MU_BASECORE/MdePkg/Include/X64','MU_BASECORE/MdeModulePkg/Include','Platforms/AndromedaPkg/Include','MU_BASECORE/ArmPkg/Include']]
incs += [lib,root/'Platforms/AndromedaPkg/Library/DeviceBootManagerLib',fixture]
exe=w/'private/preflight-tests'
cmd=['cc','-std=c11','-D_POSIX_C_SOURCE=200112L','-DNO_MSABI_VA_FUNCS','-fshort-wchar','-g','-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer','-Werror=implicit-function-declaration','-Werror=incompatible-pointer-types','-Werror=int-conversion']+['-I'+str(p)for p in incs]+[str(w/'test-preflight.c'),str(root/'Platforms/AndromedaPkg/Library/DeviceBootManagerLib/ReadOnlyBlockIo.c'),'-o',str(exe)]
r=subprocess.run(['colima','ssh','--']+cmd,capture_output=True,text=True)
(w/'private/test-compile.log').write_text(r.stdout+r.stderr)
if r.returncode: print(r.stderr[-9000:]);raise SystemExit(r.returncode)
cases=['success','parent-hash','duplicate-label','source-size','parent-path','source-read-error','metadata-hash','install-error','partial-install','no-filesystem','open-volume','open-error','get-info','file-size','file-directory','read-error','short-read','extra-eof','file-hash','file-close','root-close','write-attempt','read-budget','disconnect-error','uninstall-error','compiled-map','compiled-cache','gcd-type','gcd-gap','efi-type','probe-publication-error','DSP-result-error','DSP-fatal-restore','inventory-publication-error']
results=[]
for case in cases:
    # Intentional retained contexts model a failed firmware disconnect. Leak
    # checking is disabled; bounds/use-after-free/undefined-behavior checks remain.
    cmd=['colima','ssh','--','env','ASAN_OPTIONS=detect_leaks=0',str(exe),str(capture),str(fixture),case]
    r=subprocess.run(cmd,capture_output=True,text=True)
    if r.returncode:
        (w/'private/test-failure.json').write_text(json.dumps({'case':case,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr},indent=2)+'\n')
        print(case,r.stdout[-1000:],r.stderr[-9000:]);raise SystemExit(1)
    results.append(json.loads(r.stdout))
out={'passed':True,'cases':len(results),'source_sha256':sha((lib/'OpenAdspPreflight.c').read_bytes()),
     'native_ReadOnlyBlockIo_sha256':'ca1543c88759e23b42b40fa5578e674351a8f015a38d3a901b968fe5dbc90adc',
     'sanitizers':['address','undefined behavior'],'input_firmware_files':64,
     'models':['UEFI boot/DXE services, handles, protocol binding and ACPI publication','synthetic parent GPT with explicit test hashes','filesystem APIs return actual captured files, not an executed FAT implementation','block reads preserve relevant captured metadata; uncaptured alignment bytes are model padding'],
     'limits':['Host X64 C tests against firmware headers; not ARM64 native execution.','FAT dispatch, storage DMA, native ACPI retention, hardware memory ownership and the physical boot remain unqualified.','Known live contexts are intentionally retained after disconnect/uninstall failure.'],
     'PIL_inventory_lifetime':'One modeled publication after outside-window collection and before facade/probe/PAS; its failure does not grant in-window access or alter G136 admission.',
     'metadata_call_lifetime':'One call before facade disconnect/uninstall; Ready only with all memory/file/write guards; helper modeled, not executed.',
     'native_operations':0,'results':results}
(w/'private/preflight-test-results.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({k:v for k,v in out.items()if k not in ['results','models','limits']}))
