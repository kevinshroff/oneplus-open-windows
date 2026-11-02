from pathlib import Path
import sys,subprocess,hashlib,json,shutil
ROOT=Path('/path/to/user/Documents/Codex/2026-10-20/sta');W=ROOT/'work/boot-repair-G80';P=W/'private'
sys.path.insert(0,str(ROOT/'work/debug-G08'));from fat32_read import Fat32
old=ROOT/'work/recovery-G79/private/phone-r5/userdata-first256MiB.img'
assets=P/'boot-files';assets.mkdir(exist_ok=True)
files=Fat32(old).contents()
for name,data in files.items():
 p=assets/name;assert '..' not in p.relative_to(assets).parts;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
pe=ROOT/'work/recovery-G79/private/zcode-handoff/G18-maintenance.wim'
assert pe.stat().st_size==644359620 and hashlib.sha256(pe.read_bytes()).hexdigest()=='a702247a17605e5a66c809bbe4abf6b2c336548cf50dd8936e545fb66bcd1f9f'
(assets/'OpenG18').mkdir(exist_ok=True);shutil.copyfile(pe,assets/'OpenG18/G18-maintenance.wim');shutil.copyfile(P/'pe-audit/boot.sdi',assets/'OpenG18/boot.sdi')
img=P/'boot-fat-4kn-1GiB.img'
if img.exists():raise RuntimeError('Preserve existing boot image')
with img.open('xb') as f:f.truncate(1<<30)
subprocess.run(['colima','ssh','--','mkfs.fat','-F','32','-S','4096','-s','1','-n','OPENESP','-h',str(0x4582ec),str(img)],check=True)
for path in sorted(assets.iterdir()):
 subprocess.run(['colima','ssh','--','mcopy','-s','-p','-i',str(img),str(path),'::/'],check=True)
print('Base 4Kn FAT built; BCD replacement and complete content audit follow',flush=True)
