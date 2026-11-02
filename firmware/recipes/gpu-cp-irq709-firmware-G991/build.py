from pathlib import Path
import hashlib,json,shutil,subprocess,os,struct
H=Path(__file__).resolve().parent;R=H.parents[1];B=R/'work/firmware-build-G203';W=H/'firmware';S=R/'work/gpu-cold-start-reconcile-G736/src/firmware';sha=lambda b:hashlib.sha256(b).hexdigest()
assert not W.exists(),'Fresh build directory required'
W.mkdir();shutil.copytree(S/'Conf',W/'Conf');shutil.copytree(S/'OpenOwnerPkg',W/'OpenOwnerPkg')
old=(S/'Mmu1.asl').read_text();assert old.count('{ 705 }')==old.count('{ 711 }')==1 and '709' not in old
new=old.replace('Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive, ,, CB02) { 711 }','Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive, ,, CB02) { 711 }\n                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive, ,, CB00) { 709 }');assert new!=old
(W/'Mmu1.asl').write_text(new)
p=subprocess.run(['/opt/homebrew/bin/iasl','-p',str(W/'Mmu1'),str(W/'Mmu1.asl')],capture_output=True,text=True);(H/'iasl.log').write_text(p.stdout+p.stderr);assert p.returncode==0
aml=bytearray((W/'Mmu1.aml').read_bytes());base=(S/'Mmu1.aml').read_bytes();assert sum(base)&255==0
# Retain baseline table identity/compiler metadata; update only length/checksum/body.
header=bytearray(base[:36]);header[4:8]=struct.pack('<I',len(aml));header[9]=0;aml[:36]=header;aml[9]=(-sum(aml))&255;assert sum(aml)&255==0
(W/'Mmu1.aml').write_bytes(aml);(W/'OpenOwnerPkg/Mmu1.h').write_text('STATIC CONST UINT8 mMmu1[] = {\n'+''.join(' '+','.join(f'0x{x:02x}' for x in aml[i:i+16])+',\n' for i in range(0,len(aml),16))+'};\n')
pub=W/'OpenOwnerPkg/Publish.c';text=pub.read_text();assert text.count('r.MmuIrq=2;')==1;pub.write_text(text.replace('r.MmuIrq=2;','r.MmuIrq=3;'))
assert sha((S/'IortLevel.bin').read_bytes())=='e9ef2f2f89f10aa09fab8e253157e0395b85ecb169eb41ba04e895d9b2f4f3b7'
for f in (S/'OpenOwnerPkg').iterdir():
 if f.name not in ['Mmu1.h','Publish.c']:assert (W/'OpenOwnerPkg'/f.name).read_bytes()==f.read_bytes()
meta=json.loads((R/'work/firmware-observe-G206/evidence/build-environment.json').read_text());env={**os.environ,**meta['environment']};env['WORKSPACE']=str(W);env['CONF_PATH']=str(W/'Conf');env['PACKAGES_PATH']=':'.join(map(str,[W,B/'source',B/'source/MU_BASECORE',B/'source/Platforms']));env['PATH']=':'.join(map(str,[B/'venv/bin',B/'toolchain/bin',B/'source/MU_BASECORE/BaseTools/BinWrappers/PosixLike',B/'source/MU_BASECORE/BaseTools/Source/C/bin']))+':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin'
cmd=[str(B/'source/MU_BASECORE/BaseTools/BinWrappers/PosixLike/build'),'-p','OpenOwnerPkg/Owner.dsc','-a','AARCH64','-b','DEBUG','-t','CLANGPDB','-n','4']
with (H/'dxe-build.log').open('w') as out:p=subprocess.run(cmd,cwd=W,env=env,stdout=out,stderr=out)
report={'exit_code':p.returncode,'command':cmd,'offline_only':True,'staged_or_booted':False,'MmuIrq':3,'baseline_MMIO_and_IRQ705_711_preserved':True,'added_IRQ709':'Exclusive ActiveHigh Level','GPU0_unchanged':True,'IortLevel_unchanged':True,'AML':{'sha256':sha(aml),'bytes':len(aml)}}
(H/'DXE-BUILD.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));raise SystemExit(p.returncode)
