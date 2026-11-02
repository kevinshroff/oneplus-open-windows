"""Independent byte-level audit of the actual native WDF capture, never a fixture."""
from pathlib import Path
import hashlib,json,struct
W=Path(__file__).resolve().parent;P=W/'private';s=json.loads((W/'native-resource-recorder.json').read_text());boot=json.loads((W/'boot-resource.json').read_text())
assert s['phase']=='native_KMDF_raw_and_translated_resource_capture_retained'and s['session']==boot['session']
b=(P/'G63-native-assigned.bin').read_bytes();assert len(b)==608
u=lambda off:struct.unpack_from('<I',b,off)[0]
assert u(0)==608 and u(4)==1 and b[8:16]==b'OPG63RS1'
assert [u(o)for o in range(16,40,4)]==[26100,8,0,730,1,0]
assert u(40)==u(44)+1 and u(40)>0 and u(48)==u(52)+1 and u(48)>0 and u(56)==1
assert[u(o)for o in range(60,96,4)]==[1,2,2,20,8,2,2,0,0]
rows={}
for name,off in [('raw',96),('translated',352)]:
    memory=b[off:off+32];irq=b[off+32:off+64]
    assert memory[:4]==bytes([3,1,0,0])and irq[:4]==bytes([2,1,0,0])
    start,length=struct.unpack_from('<QI',memory,4);assert(start,length)==(0xa90000,0x4000)
    level,group,vector,affinity=struct.unpack_from('<HHIQ',irq,4)
    if name=='raw':assert vector==389
    assert memory[20:]==irq[20:]==bytes(12)and b[off+64:off+256]==bytes(192)
    rows[name]={'memory_start':start,'memory_length':length,'interrupt_level':level,'interrupt_group':group,'interrupt_vector':vector,'interrupt_affinity':affinity,'memory_descriptor_hex':memory[:20].hex(),'interrupt_descriptor_hex':irq[:20].hex()}
sha=hashlib.sha256(b).hexdigest();assert sha==s['raw_resource_sha256']==s['capture_result']['result']['sha256']
for name,row in rows.items():
    reported=s['capture_result']['result']['report'][name]
    assert reported[0]['start']==row['memory_start']and reported[0]['length']==row['memory_length']
    assert reported[1]['level']==row['interrupt_level']and reported[1]['group']==row['interrupt_group']and reported[1]['vector']==row['interrupt_vector']and reported[1]['affinity']==row['interrupt_affinity']
r={'passed':True,'evidence_kind':'actual native ARM64 IOCTL response, not a model fixture','bytes':608,'sha256':sha,'session':boot['session'],
   'exact_G63_RAM_DSDT_proved':True,'native_PrepareHardware_resources_and_active_D0_proved':True,'native_descriptor_bytes':20,
   'prepare_calls':u(40),'release_calls':u(44),'D0_entries':u(48),'D0_exits':u(52),'resources':rows,
   'native_resource_handoff_qualified':True,'hardware_mapping_or_register_operation_performed':False,
   'interrupt_delivery_qualified':False,'DMA_coherency_qualified':False,'functional_SPI_controller_qualified':False,
   'limits':['The interrupt numbers/affinity are actual descriptors, not evidence of an ISR or interrupt delivery.','This recorder does not map MMIO, issue SPI commands, create DMA transactions, or alter clocks, power or GPIO.','The table describes one candidate GENI device; other peripheral resource dependencies remain unresolved.']}
(W/'native-resource-audit.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
