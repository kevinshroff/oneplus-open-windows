from pathlib import Path
import subprocess,json,hashlib
w=Path(__file__).resolve().parent;s=w/'reference/runtime';rows=[]
def run(name,files,include):
 args=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all']+['-I'+str(p) for p in include]+list(map(str,files))+['-o',str(w/'build'/name)]
 p=subprocess.run(args,capture_output=True,text=True);assert p.returncode==0,p.stderr;p=subprocess.run([str(w/'build'/name)],capture_output=True,text=True);assert p.returncode==0,p.stdout+p.stderr;print(p.stdout,end='');rows.append({'test':name,'argv':args,'output':p.stdout})
run('test_cp_native_transport',[w/'tests/test_cp_native_transport.c',s/'g433_cp.c',s/'vendor/AdrenoPM4.c'],[s])
run('test_power_native_transport',[w/'tests/test_power_native_transport.c',s/'g440_gpu_power.c',s/'g190_backend.c',s/'vendor/AdrenoFirmware.c',s/'vendor/AdrenoHfiEncode.c'],[s])
run('test_format_policy',[w/'tests/test_format_policy.c',w/'source/fault_policy.c'],[w/'source'])
run('test_gpu_user',[w/'tests/test_gpu_user.c',w/'source/gpu_user_bank.c',w/'source/fault_policy.c',w/'source/open_smmu_handoff.c'],[w/'source'])
(w/'evidence/CORE-ACTORS.json').write_text(json.dumps({'ASan_UBSan':True,'tests':rows,'native_evidence':False,'source_sha256':{str(p.relative_to(w)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [s/'g433_cp.c',s/'g440_gpu_power.c',w/'source/gpu_user_bank.c',w/'source/fault_policy.c']}},indent=2)+'\n')
