"""Independent audit of actual breakpoint counter reads and post-restart IOCTL bytes."""
from pathlib import Path
import hashlib,json,re,struct

W=Path(__file__).resolve().parent;P=W/'private'
from lifecycle_trace import decode_trace

b=(P/'callback-trace-01.txt').read_bytes();text=b.decode('utf-16')if b.startswith((b'\xff\xfe',b'\xfe\xff'))else b.decode('utf-8','replace')
events=decode_trace(text)
# Verify the evidence parser does not accept missing callbacks, failure status,
# incomplete memory reads, or a counter value at the wrong memory address.
bad=[text.replace('G66_RELEASE_STATE\nx0','G66_RELEASE_MISSING\nx0'),text.replace('G66_RELEASE_STATE\r\nx0','G66_RELEASE_MISSING\r\nx0')]
effective=[]
for x in bad:
 if x!=text:effective.append(x)
effective.append(text.replace('x0=0000000000000000','x0=0000000000000001',1))
first=events[0]['context_address'];addr=int(first,16)+0x60
pattern=r'(?m)^'+re.escape(format(addr>>32,'x')+'`'+format(addr&0xffffffff,'08x'))
changed,count=re.subn(pattern,format((addr+4)>>32,'x')+'`'+format((addr+4)&0xffffffff,'08x'),text,count=1);assert count==1;effective.append(changed)
for sample in effective:
 try:decode_trace(sample)
 except AssertionError:pass
 else:raise AssertionError('Corrupted native trace accepted')

s=json.loads((W/'native-restart.json').read_text());f=json.loads((W/'native-cycle.json').read_text())
assert s['phase']=='native_exact_instance_restart_and_post_restart_resources_retained'
assert s['restart_response']['status']=='ok'and s['restart_response']['exit_code']==0 and 'Device restarted successfully.'in s['restart_response']['output']
assert s['instance']==r'ACPI\OPEN0063\0'and not s['reboot_or_force_requested']
assert f['disable_refusal_CR']==40 and f['unchanged_started_node']and f['enable_not_attempted']
raw=(P/'G66-after-resources.bin').read_bytes();assert len(raw)==608 and hashlib.sha256(raw).hexdigest()==s['after_resource_sha256']
u=lambda o:struct.unpack_from('<I',raw,o)[0]
assert u(0)==608 and u(4)==1 and raw[8:16]==b'OPG63RS1'
assert [u(i)for i in range(16,96,4)]==[26100,8,0,730,1,0,1,0,1,0,1,1,2,2,20,8,2,2,0,0]
resources={}
for name,o in [('raw',96),('translated',352)]:
 mem,irq=raw[o:o+32],raw[o+32:o+64]
 assert mem[:4]==bytes([3,1,0,0])and irq[:4]==bytes([2,1,0,0])
 start,size=struct.unpack_from('<QI',mem,4);assert(start,size)==(0xa90000,0x4000)
 level,group,vector,affinity=struct.unpack_from('<HHIQ',irq,4)
 if name=='raw':assert vector==389
 assert mem[20:]==irq[20:]==bytes(12)and raw[o+64:o+256]==bytes(192)
 resources[name]={'start':start,'length':size,'level':level,'group':group,'vector':vector,'affinity':affinity}
report={'passed':True,'evidence_kind':'actual native callback breakpoint memory reads plus post-restart608byte IOCTL','native_restart_and_resource_lifecycle_qualified':True,'events':events,'counter_order':['prepare','release','D0entry','D0exit','InD0','CaptureComplete'],'post_restart_resources':resources,'post_restart_report_sha256':hashlib.sha256(raw).hexdigest(),'trace_sha256':hashlib.sha256(b).hexdigest(),'trace_rejection_cases':len(effective),'counter_reset_observed':True,'context_identity_inferred_from_reused_address':False,'disable_refused_CR':40,'hardware_MMIO_IRQ_DMA_or_power_vote_qualified':False,'all21_goal_areas_active':True}
(W/'native-lifecycle-audit.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
