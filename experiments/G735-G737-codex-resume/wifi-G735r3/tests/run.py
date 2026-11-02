#!/usr/bin/env python3
from pathlib import Path
import subprocess,json
root=Path(__file__).resolve().parents[1]
src=root/'firmware/G289Pkg/Wlan'
binary=root/'tests/test_identity'
cmd=['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g','-I'+str(src),str(root/'tests/test_identity.c'),str(src/'g735_smmu_identity.c'),'-o',str(binary)]
subprocess.run(cmd,check=True)
p=subprocess.run([str(binary)],check=True,capture_output=True,text=True)
# Driver's actual integration must propagate failure into STEP's goto Done
# before the root-publication call; also require diagnostic install success.
driver=(src/'G289Driver.c').read_text()
assert 'STEP(43,PrepareSmmuIdentity());' in driver
assert driver.index('STEP(43,PrepareSmmuIdentity());')<driver.index('STEP(44,G401PublishRoot(')
assert 'if(EFI_ERROR(e)){mR->Status=e;goto Done;}' in driver
body=driver[driver.index('static EFI_STATUS PrepareSmmuIdentity'):driver.index('static void PublishTransport')]
assert 'return E;' in body and 'EFI_ERROR(P)&&!EFI_ERROR(E)' in body
assert 'Fallback' not in body and 'Cfg|1' not in body
assert 'G735VerifyPreparedSid(&SidIo,&mSid,&mIdentity)' in body
assert '0x1c0203c' not in body
write_body=driver[driver.index('static int SmmuWrite'):driver.index('static EFI_STATUS PublishIdentity')]
assert 'SmmuNoRootNamespace()' in write_body and 'G735VerifyPreparedSid(&SidIo,&mSid,&mIdentity)' in write_body
assert 'Offsets[]={0,0x10,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c}' in write_body
assert 'Sdt->GetAcpiTable' in driver and 'CompareMem(B+P,"P401",4)' in driver
sid_binary=root/'tests/test_sid_integration'
sid_cmd=cmd[:cmd.index(str(root/'tests/test_identity.c'))]+[str(root/'tests/test_sid_integration.c'),str(src/'g403_sid.c'),str(src/'g735_sid_guard.c'),str(src/'g735_smmu_identity.c'),'-o',str(sid_binary)]
subprocess.run(sid_cmd,check=True)
sid_result=subprocess.run([str(sid_binary)],check=True,capture_output=True,text=True)
out={'schema':'g735-host-tests/1','command':cmd,'output':p.stdout.strip(),'sid_integration_command':sid_cmd,'sid_integration_output':sid_result.stdout.strip(),'integration_gate_source_checked':True,'hardware_tested':False}
(root/'evidence').mkdir(exist_ok=True)
(root/'evidence/host-tests.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))

subprocess.run(['python3',str(root/'tests/test_report.py')],check=True)
