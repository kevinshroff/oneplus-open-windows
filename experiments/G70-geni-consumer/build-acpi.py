"""Combine source-bound GCC and GENI resources under one inert ACPI owner."""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--original',type=Path,required=True);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
sha=lambda b:hashlib.sha256(b).hexdigest();b=a.original.read_bytes();assert len(b)==576 and sha(b)=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01' and sum(b)%256==0
clock=json.loads((a.inputs/'clock-owner-G67/source-map.json').read_text());geni=json.loads((a.inputs/'resources-G63/source-map.json').read_text());assert clock['fixed_trial_pages']==[0x118000,0x123000,0x152000] and clock['page_bytes']==4096;assert geni['pilot_memory_base']==0xa90000 and geni['pilot_memory_bytes']==0x4000 and geni['pilot_ACPI_interrupt']==389 and geni['pilot_CCA']==1
asl=r'''DefinitionBlock ("", "SSDT", 2, "OPEN  ", "GENIG70 ", 1)
{
 Name (G70C, 0x47373043)
 Scope (\_SB) {
  Device (GEN0) {
   Name (_HID, "OPEN0070")
   Name (_UID, Zero)
   Name (_CCA, One)
   Name (_DDN, "OnePlus Open primary GENI bounded consumer")
   Method (_STA, 0, NotSerialized) { Return (0x0F) }
   Name (RBUF, ResourceTemplate () {
    Memory32Fixed (ReadWrite, 0x00118000, 0x00001000)
    Memory32Fixed (ReadWrite, 0x00123000, 0x00001000)
    Memory32Fixed (ReadWrite, 0x00152000, 0x00001000)
    Memory32Fixed (ReadWrite, 0x00A90000, 0x00004000)
    Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {389}
   })
   Method (_CRS, 0, NotSerialized) { Return (RBUF) }
  }
 }
}
'''
dsl=a.output/'consumer.dsl';dsl.write_text(asl);q=subprocess.run(['iasl','-tc',str(dsl)],capture_output=True,text=True);(a.output/'compiler.txt').write_text(q.stdout+q.stderr);assert not q.returncode,(q.stdout,q.stderr)
ssdt=dsl.with_suffix('.aml').read_bytes();assert sum(ssdt)%256==0 and ssdt[:4]==b'SSDT'
table=bytearray(b+ssdt[36:]);struct.pack_into('<I',table,4,len(table));struct.pack_into('<I',table,24,struct.unpack_from('<I',b,24)[0]+70);table[9]=0;table[9]=(-sum(table))&255;assert table[36:576]==b[36:] and sum(table)%256==0
crs=b''.join(bytes.fromhex('86090001')+struct.pack('<II',page,n) for page,n in [(0x118000,4096),(0x123000,4096),(0x152000,4096),(0xa90000,16384)])+bytes.fromhex('8906000101')+struct.pack('<I',389)+b'\x79\x00';assert len(crs)==59 and ssdt.count(crs)==1
(a.output/'acpitabl.dat').write_bytes(table);(a.output/'expected-crs.bin').write_bytes(crs)
header='/* Generated exact G70 DSDT. */\nstatic const unsigned char G70ExpectedDsdt[]={\n'+''.join(' '+','.join('0x%02x'%v for v in table[i:i+16])+',\n' for i in range(0,len(table),16))+'};\n';(a.output/'g70_binding.h').write_text(header)
commands='evaluate \\G70C; evaluate \\_SB.GEN0._HID; evaluate \\_SB.GEN0._STA; evaluate \\_SB.GEN0._CCA; evaluate \\_SB.GEN0._CRS';q=subprocess.run(['acpiexec','-b',commands,str(a.output/'acpitabl.dat')],capture_output=True,text=True);evaluation=q.stdout+q.stderr;(a.output/'evaluation.txt').write_text(evaluation);assert not q.returncode and 'ACPI Error' not in evaluation
for name,want in [('G70C',0x47373043),('_SB.GEN0._STA',15),('_SB.GEN0._CCA',1)]:
 section=evaluation.split('Evaluating \\'+name+'\n',1)[1].split('Evaluating ',1)[0];values=re.findall(r'\[Integer\] = ([0-9A-Fa-f]+)',section);assert len(values)==1 and int(values[0],16)==want
assert '[String] Length 08 = "OPEN0070"' in evaluation
section=evaluation.split('Evaluating \\_SB.GEN0._CRS\n',1)[1];parts=[]
for line in section.splitlines():
 m=re.match(r'\s*([0-9A-Fa-f]{4}): (.*?)\s*//',line)
 if m:assert int(m[1],16)==len(parts);parts.extend(bytes.fromhex(m[2]))
assert bytes(parts)==crs and 'No outstanding allocations' in evaluation
out={'phase':'combined_resource_owner_compiled_and_evaluated_not_deployed','source_DSDT_sha256':sha(b),'trial_DSDT_sha256':sha(table),'trial_bytes':len(table),'original_AML_body_preserved':True,'changed_original_header_offsets':[i for i in range(len(b)) if table[i]!=b[i]],'HID':'OPEN0070','GCC_pages':clock['fixed_trial_pages'],'GENI_memory':[0xa90000,16384],'raw_GSI':389,'CCA':1,'expected_CRS_sha256':sha(crs),'expected_CRS_bytes':59,'binding_header_sha256':sha(header.encode()),'source_maps_sha256':{n:sha((a.inputs/n/'source-map.json').read_bytes()) for n in ['clock-owner-G67','resources-G63']},'native_operations':0};(a.output/'build.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
