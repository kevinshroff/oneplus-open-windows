"""Append one inert resource-only ACPI device to the exact original G17 DSDT."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,re
p=argparse.ArgumentParser();p.add_argument('--original',type=Path,required=True);p.add_argument('--source-map',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);sha=lambda b:hashlib.sha256(b).hexdigest();b=a.original.read_bytes();assert len(b)==576 and b[:4]==b'DSDT'and sum(b)%256==0 and sha(b)=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01';source=json.loads(a.source_map.read_text());assert source['pilot_memory_base']==0xa90000 and source['pilot_memory_bytes']==0x4000 and source['pilot_ACPI_interrupt']==389 and source['pilot_CCA']==1
asl='''DefinitionBlock ("", "SSDT", 2, "OPEN  ", "GENIG63 ", 1)
{
    Name (G63C, 0x47363343)
    Scope (\\_SB)
    {
        Device (GEN0)
        {
            Name (_HID, "OPEN0063")
            Name (_UID, Zero)
            Name (_CCA, One)
            Name (_DDN, "OnePlus Open primary GENI resource pilot")
            Method (_STA, 0, NotSerialized) { Return (0x0F) }
            Name (RBUF, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite, 0x00A90000, 0x00004000)
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {389}
            })
            Method (_CRS, 0, NotSerialized) { Return (RBUF) }
        }
    }
}
''';dsl=a.output/'pilot.dsl';dsl.write_text(asl)
q=subprocess.run(['iasl','-tc',str(dsl)],capture_output=True,text=True);(a.output/'compiler.txt').write_text(q.stdout+q.stderr);assert not q.returncode,(q.stdout,q.stderr)
ssdt=dsl.with_suffix('.aml').read_bytes();assert ssdt[:4]==b'SSDT'and sum(ssdt)%256==0
out=bytearray(b);out.extend(ssdt[36:]);struct.pack_into('<I',out,4,len(out));struct.pack_into('<I',out,24,struct.unpack_from('<I',b,24)[0]+63);out[9]=0;out[9]=(-sum(out))&255;assert out[36:576]==b[36:]and sum(out)%256==0
(a.output/'acpitabl.dat').write_bytes(out);crs=bytes.fromhex('86090001')+struct.pack('<II',0xa90000,0x4000)+bytes.fromhex('8906000101')+struct.pack('<I',389)+bytes([0x79,0]);assert ssdt.count(crs)==1 and len(crs)==23;(a.output/'expected-crs.bin').write_bytes(crs)
# Exact bytes bind the future source driver to this table. No alternate table,
# normal G17 or side-effecting AML is accepted by the kernel adapter.
header='/* Generated exact G63 trial DSDT; do not edit. */\nstatic const unsigned char G63ExpectedDsdt[] = {\n'+''.join('  '+','.join('0x%02x'%v for v in out[i:i+16])+',\n'for i in range(0,len(out),16))+'};\n';(a.output/'g63_binding.h').write_text(header)
commands='evaluate \\G63C; evaluate \\_SB.GEN0._HID; evaluate \\_SB.GEN0._STA; evaluate \\_SB.GEN0._CCA; evaluate \\_SB.GEN0._CRS'
q=subprocess.run(['acpiexec','-b',commands,str(a.output/'acpitabl.dat')],capture_output=True,text=True);(a.output/'evaluation.txt').write_text(q.stdout+q.stderr);assert not q.returncode and'ACPI Error'not in q.stdout+q.stderr,(q.stdout,q.stderr)
evaluation=q.stdout+q.stderr
for name,want in [('G63C',0x47363343),('_SB.GEN0._STA',15),('_SB.GEN0._CCA',1)]:
 section=evaluation.split('Evaluating \\'+name+'\n',1)[1].split('Evaluating ',1)[0];found=re.findall(r'\[Integer\] = ([0-9A-Fa-f]+)',section);assert len(found)==1 and int(found[0],16)==want,(name,found)
section=evaluation.split('Evaluating \\_SB.GEN0._HID\n',1)[1].split('Evaluating ',1)[0];assert '[String] Length 08 = "OPEN0063"'in section
section=evaluation.split('Evaluating \\_SB.GEN0._CRS\n',1)[1];parts=[]
for line in section.splitlines():
 m=re.match(r'\s*([0-9A-Fa-f]{4}): (.*?)\s*//',line)
 if m:assert int(m[1],16)==len(parts);parts.extend(bytes.fromhex(m[2]))
assert bytes(parts)==crs and 'No outstanding allocations'in evaluation
r={'phase':'offline_resource_table_compiled_and_evaluated_not_deployed','source_DSDT_sha256':sha(b),'trial_DSDT_sha256':sha(out),'trial_bytes':len(out),'all_original_AML_body_bytes_preserved':True,'allowed_header_changed_offsets':[4,5,6,7,9,24,25,26,27],'actual_existing_header_changed_offsets':[i for i in range(len(b))if out[i]!=b[i]],'evaluated_marker_STA_CCA_HID_and_resource_bytes_match':True,'added_hardware_id':'OPEN0063','added_memory':[0xa90000,0x4000],'added_ACPI_interrupt':389,'added_CCA':1,'binding_header_sha256':sha(header.encode()),'expected_resource_bytes':len(crs),'expected_resource_sha256':sha(crs),'source_map_sha256':sha(a.source_map.read_bytes()),'native_operations':0};(a.output/'build.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
