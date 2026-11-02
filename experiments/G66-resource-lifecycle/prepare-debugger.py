"""Bind callback observation to byte-identical map and REA instruction evidence."""
from pathlib import Path
import hashlib,json,struct

W=Path(__file__).resolve().parent;P=W/'private';B=W.parent/'resources-G63'
m=json.loads((W/'native-symbol-map.json').read_text());assert m['phase']=='byte_identical_unsigned_recorder_linked_with_exact_symbol_map'
e=json.loads((P/'REA-callback-instructions.json').read_text())
binary=(B/'private/G63-signed.sys').read_bytes();assert hashlib.sha256(binary).hexdigest()==m['signed_sha256']=='52515537783623532bf0fe202f7992a3e2d09242939a86b4233fdca214b83574'
pe=struct.unpack_from('<I',binary,0x3c)[0];sections=struct.unpack_from('<H',binary,pe+6)[0];table=pe+24+struct.unpack_from('<H',binary,pe+20)[0]
def at(rva,n):
 for i in range(sections):
  o=table+i*40;size,va,raw,off=struct.unpack_from('<IIII',binary,o+8)
  if va<=rva and rva+n<=va+raw:
   assert struct.unpack_from('<I',binary,o+36)[0]&0x20000000
   return binary[off+rva-va:off+rva-va+n]
 raise AssertionError('Executable RVA bounds')
rows=[('PREPARE_STATE',0x1404,'x20','ldp x20, x19'),('PREPARE_SUCCESS',0x140c,None,'ldp x22, x21'),('RELEASE_STATE',0x1490,'x19','ldp x30, x19'),('D0ENTRY_STATE',0x1510,'x19','ldp x30, x19'),('D0EXIT_STATE',0x1588,'x19','ldp x30, x19')]
ins={line.split(':',1)[0]:line for c in e['callbacks']for line in c['instructions']['normalized_result']['instructions']}
probes=[];commands=[];guards=[]
for name,rva,reg,instruction in rows:
 line=ins[hex(0x140000000+rva)];assert instruction in line
 word=struct.unpack('<I',at(rva,4))[0];guards.append('(dwo(OpenG63+'+hex(rva)+')=='+hex(word)+')')
 body='.echo G66_'+name+'; '
 if name!='PREPARE_STATE':body+='r x0; '
 if reg:body+='r '+reg+'; dd @'+reg+'+0x60 L6; '
 body+='gc'
 commands.append('bu OpenG63+'+hex(rva)+' "'+body+'"')
 probes.append({'label':name,'RVA':hex(rva),'context_register':reg,'counter_offset':0x60 if reg else None,'counter_words':6 if reg else 0,'instruction_word':hex(word),'REA_instruction':line})
run=r'C:\Users\PUBLIC_USER\Downloads\Open-G17\logs\G66-lifecycle-01'
startup='\r\n'.join(['.echo G66_ATTACH_BEGIN','.reload','lmv m OpenG63','bl','.writemem "'+run+r'\native-code.bin" OpenG63+0x1000 OpenG63+0x158f','.if ('+' && '.join(guards)+') { '+ '; '.join(commands)+'; .echo G66_ARMED; .bpcmds; bl } .else { .echo G66_REFUSED_CODE_MISMATCH }','.echo G66_ATTACH_END','g',''])
assert max(map(len,startup.splitlines()))<3000
(P/'G66-first-attach.txt').write_bytes(startup.encode('ascii'))
span=at(0x1000,0x590);(P/'expected-native-code.bin').write_bytes(span)
plan={'phase':'static_callback_probe_plan_derived_not_native_lifecycle_evidence','driver_sha256':m['signed_sha256'],'image_base':m['image_base'],'native_code_RVA':'0x1000','native_code_bytes':len(span),'native_code_sha256':hashlib.sha256(span).hexdigest(),'probes':probes,'counter_order':['prepare','release','D0entry','D0exit','InD0','CaptureComplete'],'REA_evidence_ids':[c['instructions']['evidence_id']for c in e['callbacks']],'host_run':run,'native_lifecycle_observed':False,'hardware_access':False}
(W/'callback-plan.json').write_text(json.dumps(plan,indent=2)+'\n');print(json.dumps({k:plan[k]for k in ['phase','native_code_bytes','native_code_sha256']}))
