"""Overlay only the qualified new Android image; preserve every trailing byte."""
from pathlib import Path
import base64,hashlib,json,struct
W=Path(__file__).resolve().parent;R=W.parents[2];P=W/'private';sha=lambda b:hashlib.sha256(b).hexdigest()
build=json.loads((W/'build/receipt.json').read_text());assert build['mode']==9 and build['acpi_marker']=='GPTG18T1' and build['verified_build_images']==121
assert build['firmware_scope']['RAM_driver_byte_identical'] and build['firmware_scope']['marker_compiled_in_BdsDxe']
original=(W.parent/'private/boot_a-before.img').read_bytes();assert len(original)==201326592 and sha(original)=='f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'
baseline=(R/'work/boot-G16/build-apply/boot_a.img').read_bytes();assert original[:len(baseline)]==baseline
image=(W/'build/boot_a.img').read_bytes();assert len(image)==build['image_bytes'] and sha(image)==build['image_sha256']
for a in [original,image]:
 assert a[:8]==b'ANDROID!' and struct.unpack_from('<I',a,12)[0]==0 and struct.unpack_from('<I',a,20)[0]==1580 and struct.unpack_from('<I',a,40)[0]==3
 assert a[24:40]==bytes(16) and 0<struct.unpack_from('<I',a,8)[0]<16*1024*1024-4096
# BootShim instructions are invariant. Image-generation source and exact byte
# differences are retained separately; do not pad or zero old Android data.
x=original[:16<<20];y=bytearray(x);y[:len(image)]=image;y=bytes(y)
assert y[len(image):]==x[len(image):] and original[16<<20:]!=bytes(len(original)-(16<<20))
changes=[{'offset':o,'before':base64.b64encode(x[o:o+4096]).decode(),'after':base64.b64encode(y[o:o+4096]).decode()} for o in range(0,len(x),4096) if x[o:o+4096]!=y[o:o+4096]]
assert 0<len(changes)<=1024
plan={'version':2,'target':'boot_a','prefix_bytes':len(x),'before_sha256':sha(x),'after_sha256':sha(y),'changes':changes}
inverse={**plan,'before_sha256':sha(y),'after_sha256':sha(x),'changes':[{'offset':c['offset'],'before':c['after'],'after':c['before']} for c in changes]}
restored=bytearray(y)
for c in inverse['changes']:restored[c['offset']:c['offset']+4096]=base64.b64decode(c['after'])
assert bytes(restored)==x
for name,obj in [('boot-trial-plan.json',plan),('boot-trial-undo.json',inverse)]:
 p=P/name;assert not p.exists();p.write_text(json.dumps(obj,indent=2)+'\n')
r={'target':'boot_a','prefix_bytes':len(x),'image_bytes':len(image),'image_sha256':sha(image),'before_prefix_sha256':sha(x),'after_prefix_sha256':sha(y),'before_full_partition_sha256':sha(original),'after_full_partition_sha256':sha(y+original[len(y):]),'changed_sectors':len(changes),'changed_bytes':sum(a!=b for a,b in zip(x,y)),'unchanged_bytes_outside_image_verified':True,'independent_inverse_restores_exact_before':True,'activation_plan_sha256':sha((P/'boot-trial-plan.json').read_bytes()),'inverse_plan_sha256':sha((P/'boot-trial-undo.json').read_bytes()),'image_Android_header_kernel_bytes':build['kernel_bytes'],'activation':'not applied'}
(W/'boot-plan-receipt.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
