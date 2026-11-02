"""Offline source tests and actual WDK ABI comparison. Never installs a driver."""
from pathlib import Path
import argparse, hashlib, json, struct, subprocess

p=argparse.ArgumentParser()
p.add_argument('--output',type=Path,required=True)
p.add_argument('--wdk-root',type=Path,required=True,help='Directory containing wdk/ and sdk/ extracted 26100 headers')
p.add_argument('--msvc-include',type=Path,required=True)
p.add_argument('--thread-sanitizer',action='store_true')
a=p.parse_args();root=Path(__file__).resolve().parent;out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def run(label,argv):
 r=subprocess.run([str(x) for x in argv],capture_output=True,text=True)
 (out/(label+'.log')).write_text(r.stdout+r.stderr)
 commands.append({'label':label,'argv':[str(x) for x in argv],'exit_code':r.returncode})
 assert r.returncode==0,(label,r.stdout,r.stderr)
 return r.stdout
def coff_words(path):
 b=path.read_bytes();machine,nsections,_,ptr,nsyms,optional,_=struct.unpack_from('<HHIIIHH',b)
 assert machine==0xaa64
 strings=b[ptr+18*nsyms:];i=0
 while i<nsyms:
  off=ptr+18*i;name=b[off:off+8];value,section,_,_,aux=struct.unpack_from('<IhHBB',b,off+8)
  if name[:4]==b'\0'*4:
   start=struct.unpack_from('<I',name,4)[0];name=strings[start:].split(b'\0',1)[0]
  else:name=name.split(b'\0',1)[0]
  if name==b'G162AbiWords':
   assert 1<=section<=nsections
   sec=20+optional+(section-1)*40
   count,offset=struct.unpack_from('<II',b,sec+16);assert value+27*4<=count
   return list(struct.unpack_from('<27I',b,offset+value))
  i+=1+aux
 raise AssertionError('Actual compiler ABI symbol missing')
commands=[];result={'passed':False,'native_operations':0,'hardware_and_PnP_lifetime_modeled':False}
try:
 fixture=root/'tests/g160-native-words.bin'
 assert sha(fixture)=='41d72098cbac9b78f13e9155fa0749a21c33143bc6b9e750f1b87a310a12d0e9'
 common=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(root/'source')]
 old=root/'tests/old-G152'
 for name,pinned in {'battery_cache.c':'bb7f50abfed914acc570cedf3c002d27d79e062163acf8811495778b212456dd','battery_cache.h':'c958352d9b767b169aa61585d932230ddbc1c26231ba5947555364474cf07918'}.items():assert sha(old/name)==pinned
 run('G152-regression-compile',[*common[:-1],'-I'+str(old),old/'battery_cache.c',root/'test-G152-regression.c','-o',out/'regression'])
 result['G152_regression']=json.loads(run('G152-regression-run',[out/'regression']))
 run('cache-compile',[*common,root/'source/battery_cache.c',root/'test-cache.c','-o',out/'cache'])
 result['cache']=json.loads(run('cache-run',[out/'cache',fixture]))
 callbacks=[root/'source/battery_cache.c',root/'source/battery_miniclass.c',root/'tests/mock/kernel.c',root/'tests/test-callbacks.c']
 cp=[*common,'-fshort-wchar','-pthread','-I'+str(root/'tests/mock')]
 run('callbacks-compile',[*cp,*callbacks,'-o',out/'callbacks'])
 result['callbacks']=json.loads(run('callbacks-run',[out/'callbacks']))
 if a.thread_sanitizer:
  ts=[x.replace('address,undefined','thread') for x in cp]
  run('race-compile',[*ts,*callbacks,'-o',out/'race'])
  result['race']=json.loads(run('race-run',[out/'race']))
 run('host-ABI-compile',[*cp,'-DG162_HOST_ABI',root/'tests/abi.c','-o',out/'host-abi'])
 host=[int(x) for x in run('host-ABI-run',[out/'host-abi']).split()]
 sdk=a.wdk_root.resolve();msvc=a.msvc_include.resolve()
 wp=['clang','--target=aarch64-pc-windows-msvc','-ffreestanding','-fms-extensions','-fms-compatibility','-fno-stack-protector','-O2','-std=c11','-D_ARM64_=1','-D_KERNEL_MODE','-DNTDDI_VERSION=0x0A000008','-D_WIN32_WINNT=0x0A00','-Wall','-Wextra','-Werror','-I'+str(root/'source')]
 for d in [sdk/'wdk/c/Include/10.0.26100.0/km',sdk/'wdk/c/Include/wdf/kmdf/1.15',sdk/'sdk/c/Include/10.0.26100.0/shared',sdk/'sdk/c/Include/10.0.26100.0/ucrt',msvc]:
  assert d.is_dir(),d;wp+=['-isystem',str(d)]
 objects=[]
 for source in [root/'source/battery_cache.c',root/'source/battery_miniclass.c',root/'tests/abi.c']:
  obj=out/(source.stem+'.obj');run(source.stem+'-ARM64-compile',[*wp,'-c',source,'-o',obj])
  raw=obj.read_bytes();assert raw[:2]==b'\x64\xaa';obj.write_bytes(raw[:4]+b'\0'*4+raw[8:])
  objects.append({'source':source.name,'sha256':sha(obj),'bytes':obj.stat().st_size})
 actual=coff_words(out/'abi.obj');assert host==actual,(host,actual)
 names=['WCHAR','BATTERY_STATUS','Rate_offset','BATTERY_INFORMATION','FullChargedCapacity_offset','DefaultAlert1_offset','BATTERY_NOTIFY','BATTERY_MINIPORT_INFO','Context_offset','QueryTag_offset','QueryStatus_offset','SetStatusNotify_offset','DisableStatusNotify_offset','Pdo_offset','DeviceName_offset','FAST_MUTEX','OPEN_BATTERY_PAIR','State_offset','OPEN_BATTERY_DEVICE','Gauge_offset','OB_CACHE','BatteryTemperature','BatteryEstimatedTime','BatteryDeviceName','BatteryGranularityInformation','BATTERY_CAPACITY_RELATIVE','BATTERY_UNKNOWN_RATE']
 result.update(passed=True,abi=dict(zip(names,actual)),host_and_actual_WDK_ABI_agree=True,ARM64_objects=objects,fixture_sha256=sha(fixture),source_sha256={str(f.relative_to(root)):sha(f) for f in [*sorted((root/'source').glob('*')),*sorted((root/'tests').rglob('*')),root/'test-cache.c',root/'test-G152-regression.c',Path(__file__).resolve()] if f.is_file()})
finally:
 result['commands']=commands;(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:result[k] for k in ['passed','cache','callbacks','host_and_actual_WDK_ABI_agree','native_operations']},indent=2))
