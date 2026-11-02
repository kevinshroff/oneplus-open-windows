"""Offline source renderer only; never stages, compiles or touches a device."""
from pathlib import Path
import argparse,hashlib,json,re,secrets,shutil
HERE=Path(__file__).resolve().parent
FILES=('SingleInfSelector.cs','ScanAndCache.cs','Policy.ps1','Initialize-Once.ps1','Launch-FutureTask.ps1','Native-Compile-Only.ps1')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def need(ok,why):
 if not ok:raise ValueError(why)
def validate_actual(j):
 need(j.get('schema')=='G1333-actual-fresh-admission/1' and type(j.get('BootId')) is int and j['BootId']>167,'Actual future Boot>167 required')
 need(re.fullmatch('[0-9a-f]{32}',str(j.get('phone_session',''))),'Actual new root-observed session required')
 need(re.fullmatch(r'PCI\\VEN_17CB&DEV_1107[^\r\n]+',str(j.get('instance_id','')),re.I),'Exact actual PCI instance required')
 need(j.get('native_qcwlan_Start4_Stopped') is True and j.get('native_GPU_owner_broker_Start4_Stopped') is True and j.get('actual_old_and_new_qcwlan_module_absent') is True and j.get('actual_no_old_SYS_breakpoints_or_observer') is True,'Actual fresh fences/module/debugger facts required')
 need(re.fullmatch('[0-9a-f]{64}',str(j.get('actual_native_admission_sha256',''))) and re.fullmatch('[0-9a-f]{64}',str(j.get('actual_module_evidence_sha256',''))),'Actual admission/module evidence hashes required')
 need(j.get('package_directory') and len(j['package_directory'])<220 and '"' not in j['package_directory'] and "'" not in j['package_directory'],'Root-selected actual phone source-package path required')
 return j

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--actual',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();j=validate_actual(json.loads(a.actual.read_text()));need(not a.out.exists(),'New exclusive output required')
 pins=json.loads((HERE/'SOURCE-PINS.json').read_text());need(all(sha(HERE/n)==h for n,h in pins['sources'].items()),'Frozen source changed')
 a.out.mkdir(parents=True)
 for n in FILES:shutil.copyfile(HERE/n,a.out/n)
 shutil.copyfile(HERE/'SOURCE-PINS.json',a.out/'SOURCE-PINS.json')
 review={'schema':'G1333-matched4478-once-review/1','BootId':j['BootId'],'phone_session':j['phone_session'],'instance_id':j['instance_id'],'root_nonce':secrets.token_hex(16),'package_directory':j['package_directory'],'package_sha256':pins['matched_package_files'],'installed_member_sha256':pins['generic_runtime_files'],'source_sha256':{n:sha(HERE/n) for n in FILES},'source_pins_sha256':sha(HERE/'SOURCE-PINS.json'),'accepted_matched_package_selection_init_scan':False,'accepted_future_Start4_fence':False,'accepted_copy_install_new_signed_package':False,'root_qualifies_actual_no_old_or_new_WLAN_loaded':False,'root_qualifies_no_old_breakpoints_or_observer':False,'actual_admission_input_sha256':sha(a.actual),'actual_native_admission_sha256':j['actual_native_admission_sha256'],'actual_module_evidence_sha256':j['actual_module_evidence_sha256'],'native_compile_result_sha256':None}
 (a.out/'review.candidate.json').write_text(json.dumps(review,indent=2)+'\n');(a.out/'INERT.json').write_text(json.dumps({'BootId':j['BootId'],'root_permissions_all_false':True,'staged_or_executed':False,'compiled':False,'old_RVAs_or_observer_used':False},indent=2)+'\n')
if __name__=='__main__':main()
