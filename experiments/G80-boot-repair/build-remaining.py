from pathlib import Path
import subprocess,sys
W=Path(__file__).resolve().parents[1]
G='/home/PROJECT_USER.guest/woa-open/mu_aloha_platforms'
old=13
variants=[('undo',14),('normal',9)]
if '--resume-undo' in sys.argv:
 subprocess.run([sys.executable,str(W/'scripts/verify-firmware.py'),'undo'],check=True)
 old=14;variants=[('normal',9)]
for variant,mode in variants:
 code="from pathlib import Path;p=Path(%r);s=p.read_text();assert s.count(%r)==1;p.write_text(s.replace(%r,%r))"%(G+'/Platforms/KailuaPkg/Device/oneplus-open/PcdsFixedAtBuild.dsc.inc','PcdOpenBringupMode|'+str(old),'PcdOpenBringupMode|'+str(old),'PcdOpenBringupMode|'+str(mode))
 subprocess.run(['colima','ssh','--','python3','-c',code],check=True)
 print('Building',variant,'mode',mode,flush=True)
 cmd='source ~/woa-open/venv/bin/activate; source ~/woa-open/build-env.sh; cd '+G+'; python3 build_uefi.py -d oneplus-open -t DEBUG > /tmp/open-G80-'+variant+'-build.log 2>&1'
 subprocess.run(['colima','ssh','--','bash','-lc',cmd],check=True)
 subprocess.run([sys.executable,str(W/'scripts/verify-firmware.py'),variant],check=True)
 old=mode
print('All G80 firmware variants built and captured',flush=True)
