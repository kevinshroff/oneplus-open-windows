"""Prepare, compile and validate an offline reservation/selection source candidate.

The baseline source and all 49 descriptor bytes are tied to the installed G80
PrePi. Header constants are reconstructed from that table and validated by an
ARM64 compilation of the whole unchanged array. This is not a full UEFI build.
"""
from pathlib import Path
import argparse,json,hashlib,struct,re,subprocess,difflib,configparser
p=argparse.ArgumentParser(description=__doc__)
for n in ['source-root','prepi','output']:p.add_argument('--'+n,type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
C='Platforms/KailuaPkg/Device/oneplus-open/Library/PlatformMemoryMapLib/PlatformMemoryMapLib.c';PLAT='Platforms/KailuaPkg/Device/oneplus-open/Binaries/RawFiles/uefiplat.cfg';PIL='Platforms/KailuaPkg/Device/oneplus-open/Binaries/RawFiles/uefipil.cfg';raws={n:(a.source_root/n).read_bytes()for n in [C,PLAT,PIL]};sha=lambda b:hashlib.sha256(b).hexdigest();expected={C:'c7ec67769fbcd64cdd709f87128217cbd10c596b8f9aec25268ee40d78a26e2d',PLAT:'b142d920fca30826392838ecc1eba7bbbee4c8250854efd914527ee1afe32d3d',PIL:'13f509813bcaa5f862d0cdaa55e784c557bd0d9c9a93255185f2786a94b4c387'};assert all(sha(raws[n])==h for n,h in expected.items());prepi=a.prepi.read_bytes();assert sha(prepi)=='9207af80d4f4584d186c9f2f474669ff65b893c5d644f9dce7cbbdb4272a7a02'

def rows(source):
 s=re.sub(r'/\*.*?\*/','',source,flags=re.S);s=re.sub(r'//[^\n]*','',s);table=s[s.index('gDeviceMemoryDescriptorEx[]'):s.index('};',s.index('gDeviceMemoryDescriptorEx[]'))];out=[]
 for m in re.finditer(r'\{\s*"([^"]+)"\s*,([^}]+)\}',table):
  vals=[v.strip()for v in m[2].split(',')];assert len(vals)==7;out.append({'name':m[1],'tokens':vals})
 assert out[-1]['name']=='Terminator'and len(out)==49;return out
oldrows=rows(raws[C].decode());start=prepi.index(b'NOMAP\0');oldtable=prepi[start:start+49*72];constants={};old=[]
for i,row in enumerate(oldrows):
 data=oldtable[i*72:(i+1)*72];name=data[:32].split(b'\0',1)[0].decode();assert name==row['name'];vals=struct.unpack_from('<QQ6I',data,32);assert vals[-1]==0
 for token,value in zip(row['tokens'],vals[:-1]):
  if re.fullmatch(r'0x[0-9A-Fa-f]+|[0-9]+',token):assert int(token,0)==value,(row,token,value)
  else:assert re.fullmatch(r'[A-Za-z_]\w*',token);assert constants.setdefault(token,value)==value,(token,value)
 old.append({'name':name,'address':vals[0],'bytes':vals[1],'HobOption':vals[2],'ResourceType':vals[3],'ResourceAttribute':vals[4],'MemoryType':vals[5],'ArmAttributes':vals[6]})
new=raws.copy()
for n in [C,PLAT]:
 s=new[n].decode();lines=[];changes=0
 for line in s.splitlines(keepends=True):
  if '"PIL Reserved"'in line:assert line.count('0x18280000')==1;line=line.replace('0x18280000','0x18A80000');changes+=1
  elif '"Display Demura"'in line:assert '0xA2A80000'in line and'0x02B00000'in line;line=line.replace('0xA2A80000','0xA3280000').replace('0x02B00000','0x02300000');changes+=1
  lines.append(line)
 assert changes==2;new[n]=''.join(lines).encode()
s=new[PIL]
for name in ['FULL_ADSP','FULL_ADSP_DTB']:
 m=re.search(rb'(?ms)^\['+name.encode()+rb'\]\n(.*?)(?=^\[|\Z)',s);assert m;section=m[0];updated=re.sub(rb'(?m)^PartiGuid = .*\n',b'PartiLabel = modem_a\n',section);assert updated!=section;s=s[:m.start()]+updated+s[m.end():]
new[PIL]=s
# The installed and candidate AUTO lists must both remain empty.
for b in [raws[PIL],new[PIL]]:
 cfg=configparser.ConfigParser(allow_no_value=True,interpolation=None);cfg.read_string(b.decode());assert not dict(cfg['AUTO']);assert int(cfg['FULL_ADSP']['ResvMemorySize'],0)==0x4880000
 if b==new[PIL]:
  for section in ['FULL_ADSP','FULL_ADSP_DTB']:assert cfg[section]['PartiLabel']=='modem_a'and 'PartiGuid'not in cfg[section]
newrows=rows(new[C].decode());nums=[]
for row in newrows:
 vals=[int(t,0)if re.fullmatch(r'0x[0-9A-Fa-f]+|[0-9]+',t)else constants[t]for t in row['tokens']];nums.append(vals)
reserved=next(row for row in nums if row[:2]==[0x8a800000,0x18a80000]);tail=next(row for row in nums if row[:2]==[0xa3280000,0x2300000]);assert reserved[0]+reserved[1]==tail[0]and tail[0]+tail[1]==0xa5580000;assert reserved[0]<=0x9e980000 and 0x9ea00000+0x4880000==reserved[0]+reserved[1]
for i,(before,after)in enumerate(zip(oldrows,newrows)):
 assert before['name']==after['name'];assert before['tokens'][2:]==after['tokens'][2:];assert before==after or i in [8,9]
# Compile both complete source arrays using an explicit ABI shim. Infer no
# numerical macro blindly: all baseline table bytes must reproduce first.
shim='''typedef struct {char Name[32];unsigned long long Address,Length;unsigned HobOption,ResourceType,ResourceAttribute,MemoryType,ArmAttributes;} ARM_MEMORY_REGION_DESCRIPTOR_EX;
_Static_assert(sizeof(ARM_MEMORY_REGION_DESCRIPTOR_EX)==72,"descriptor ABI");
_Static_assert(__builtin_offsetof(ARM_MEMORY_REGION_DESCRIPTOR_EX,ResourceAttribute)==56,"resource attribute offset");
_Static_assert(__builtin_offsetof(ARM_MEMORY_REGION_DESCRIPTOR_EX,MemoryType)==60,"memory type offset");
_Static_assert(__builtin_offsetof(ARM_MEMORY_REGION_DESCRIPTOR_EX,ArmAttributes)==64,"ARM attribute offset");
'''+''.join('#define '+k+' '+hex(v)+'u\n'for k,v in sorted(constants.items()))

def sections(blob):
 h=struct.unpack_from('<16sHHIQQQIHHHHHH',blob);assert h[0][:6]==b'\x7fELF\x02\x01'and h[2]==183 and h[11]==64;off,count,strings=h[6],h[12],h[13];headers=[struct.unpack_from('<IIQQQQIIQQ',blob,off+i*64)for i in range(count)];st=headers[strings];names=blob[st[4]:st[4]+st[5]];out={}
 for x in headers:
  name=names[x[0]:].split(b'\0',1)[0].decode();assert x[4]+x[5]<=len(blob)or x[1]==8
  if x[1]!=8:out[name]=blob[x[4]:x[4]+x[5]]
 return out
compiled={};reports={}
for label,src in [('baseline',raws[C]),('candidate',new[C])]:
 folder=a.output/label;folder.mkdir();f=folder/'map.c';f.write_text(shim+re.sub(r'(?m)^#include.*\n','',src.decode()));obj=folder/'map.o';cmd=['clang','--target=aarch64-none-elf','-std=c11','-ffreestanding','-O2','-Wall','-Wextra','-Werror','-c',str(f),'-o',str(obj)];r=subprocess.run(cmd,capture_output=True,text=True);assert r.returncode==0,r.stderr;ss=sections(obj.read_bytes());compiled[label]=ss;reports[label]={'object_sha256':sha(obj.read_bytes()),'data_sha256':sha(ss['.data']),'command':cmd}
assert compiled['baseline']['.data']==oldtable,'whole installed table reproduction failed';assert compiled['baseline']['.text']==compiled['candidate']['.text'];ct=compiled['candidate']['.data'];assert len(ct)==len(oldtable);changed=[i for i,(x,y)in enumerate(zip(oldtable,ct))if x!=y];allowed=set(range(8*72+40,8*72+48))|set(range(9*72+32,9*72+48));assert changed and all(i in allowed for i in changed)
# Verify each row and preserve all names, types, HOB/cache attributes and pads.
for i,vals in enumerate(nums):assert ct[i*72+32:(i+1)*72]==struct.pack('<QQ6I',*vals,0)
# Materialize a source-only candidate and reviewable unified diff. Never patch
# the installed TE, firmware image or source working tree.
patch=''
for name in [C,PLAT,PIL]:
 target=a.output/'candidate-source'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(new[name]);patch+=''.join(difflib.unified_diff(raws[name].decode().splitlines(True),new[name].decode().splitlines(True),fromfile='a/'+name,tofile='b/'+name,n=0))
(a.output/'candidate.patch').write_text(patch)
report={'passed':True,'native_operations':0,'full_UEFI_build':False,'source_before_sha256':expected,'source_after_sha256':{n:sha(b)for n,b in new.items()},'installed_PrePi_sha256':sha(prepi),'table':{'offset':start,'rows':49,'descriptor_bytes':72,'all_baseline_ARM64_table_bytes_match':True,'compiled_function_code_unchanged':True,'changed_table_offsets':changed,'only_three_address_length_fields_change':True,'all_other_records_names_types_HOB_memory_cache_attributes_padding_unchanged':True},'compiler':reports,'derived_macro_values_validated_by_whole_table_reproduction':constants,'layout':{'PIL':[hex(reserved[0]),hex(reserved[0]+reserved[1])],'retained_legacy_Demura_tail':[hex(tail[0]),hex(tail[0]+tail[1])],'ADSP_bytes':0x4880000,'ADSP_in_PIL':True,'reserved_union_start_end_unchanged':['0x8a800000','0xa5580000'],'new_conventional_RAM_bytes':0,'reclassified_8MiB_cache_policy':{'range':['0xa2a80000','0xa3280000'],'before':'legacy Demura write-through attribute5','after':'PIL uncached attribute0','record_attribute_fields_unchanged':True}},'selection':{'FULL_ADSP':'PartiLabel=modem_a; no PartiGuid','FULL_ADSP_DTB':'PartiLabel=modem_a; no PartiGuid','AUTO':'remains empty'},'limits':['Offline source candidate, not a full UEFI build or a deployed reservation fix.','The legacy Demura tail remains reserved, with reduced unused capacity; it is not qualified as a future operational Demura allocation.','G116 observed disabled fetch only in the current boot. Native preflight must recheck ownership and exact metadata before a controlled startup.','Native UEFI filesystem/partition inventory, FAT geometry, SCM authentication, thermal policy and Windows DSP handoff remain unqualified.']};(a.output/'validation.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k in ['passed','native_operations','full_UEFI_build','table','layout','selection']}))
