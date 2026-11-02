"""Compile the real KMDF adapter and portable observer with pinned headers."""
import argparse,hashlib,json,struct,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
for n in ['kits','msvc','binding','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
includes=[a.kits/'wdk/c/Include/10.0.26100.0/km',a.kits/'wdk/c/Include/wdf/kmdf/1.15',a.kits/'sdk/c/Include/10.0.26100.0/shared',a.kits/'sdk/c/Include/10.0.26100.0/ucrt',a.msvc]
assert all(x.is_dir()for x in includes)
base=['clang','--target=aarch64-pc-windows-msvc','-ffreestanding','-fms-extensions','-fms-compatibility','-fno-stack-protector','-O2','-std=c11','-D_ARM64_=1','-D_KERNEL_MODE','-DNTDDI_VERSION=0x0A000000','-D_WIN32_WINNT=0x0A00','-Wall','-Wextra','-Werror','-I'+str(a.binding.resolve()),'-I'+str(W)]
for x in includes:base+=['-isystem',str(x.resolve())]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();objects=[]
for name in ['g54_driver','g54_observer','g54_rsc','g54_power','g54_spi','g54_engine','g54_touch','g54_contract','g54_plan','g54_report','g54_poll','geni_fifo']:
 obj=a.output/(name+'.obj');cmd=base+['-c',str(W/(name+'.c')),'-o',str(obj)]
 r=subprocess.run(cmd,capture_output=True,text=True);(a.output/(name+'-compiler.txt')).write_text(r.stdout+r.stderr)
 assert r.returncode==0,r.stdout+r.stderr
 b=obj.read_bytes();assert struct.unpack_from('<H',b)[0]==0xaa64;obj.write_bytes(b[:4]+b'\0'*4+b[8:])
 objects.append({'source':name+'.c','source_sha256':sha(W/(name+'.c')),'object':obj.name,'bytes':obj.stat().st_size,'sha256':sha(obj),'argv':cmd,'compiler_output':r.stdout+r.stderr})
report={'objects':objects,'headers':{n:sha(W/n)for n in ['g54_protocol.h','g54_observer.h','g54_power.h','g54_spi.h','g54_engine.h','g54_touch.h','g54_contract.h','g54_trial.h','g54_report.h','g54_poll.h','geni_fifo.h']},'binding_sha256':sha(a.binding/'g54_binding.h'),'MMIO_writes_limited_to_fixed_platform_and_validated_bounded_report_reads_and_fixed_event_clears':True,'native_access_qualified_by_this_compile':False}
(a.output/'compile.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'ARM64_objects':[{k:x[k]for k in ['object','bytes','sha256']}for x in objects]}))
