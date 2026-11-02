"""Export the verified expiry result and observed resource gap,not raw captures."""
from pathlib import Path
import hashlib,json,shutil
w=Path(__file__).resolve().parent;p=w/'private';repo=Path('/path/to/user/Documents/GitHub/oneplusopen-win11');out=repo/'experiments/G181-native-health-expiry';e=repo/'evidence/G181';out.mkdir(exist_ok=False);e.mkdir(exist_ok=False);sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();a=json.loads((p/'native-analysis.json').read_text());assert a['passed']
for f in w.iterdir():
 if f.is_file()and f.suffix in ['.py','.ps1','.c','.txt']:
  s=f.read_text();(out/f.name).write_text('\n'.join(line.rstrip()for line in s.splitlines())+'\n')
for n in ['native-analysis.json','resource-analysis.json','package.json']:shutil.copyfile(p/n,e/n)
jobinfo={}
for n in ['host-stage-intent.json','old-owner-close-intent.json','fresh-boot-intent.json','native-stage-intent.json','expiry-intent.json','complete-late-observation-intent.json','resource-inventory-intent.json']:
 d=json.loads((p/n).read_text());jobinfo[n]={k:d.get(k)for k in ['created','completed','complete','phase','session']};jobinfo[n]['jobs']=d.get('jobs',[{'job':d['job']}]if'job'in d else[])
(e/'native-job-summary.json').write_text(json.dumps({'intents':jobinfo,'late_request_sent_once':True,'expected_negative_result':'controller status=error,exit1,request_submitted=true; observed then followed with read-only state checks.','no_control_replay':True,'same_G180_signed_driver_sha256':'1ba087facfecd7693691b2ff1110d83aa27038cb0675e2ef1fd989b42c62fcf6','partition_flashes':0,'same_boot_PAS_retries':0,'all_six_goal_areas_incomplete':True},indent=2)+'\n')
lead='''OnePlus Open native Windows: current status,26 October2026 / G181 native

G181 verifies the exactG180 driver's default90s charging expiry with zero
health renewals. Native off->on TX gap5.008620s,on->finaloff90.006253s; all4fixed
SETs service0. A physical-only observation near45s finds enable1/FULLON and
raw signed currents232/130mA without changing the lease deadline,health checks,
command ID or GLINK counts. After expiry,enable0/DISABLED,currents11/0mA.
Four physical pairs independently decode and pass actual-C validation; both
providers retire and are separately absent each time.76SPMI READs/80gauge queries.

One late typed renewal with the valid current cookie/nextID4 is refused before
producer I/O. ID stays3,health checks/accepted stay2,renewals0,all producer
metadata and GLINK counters unchanged. The controller reports the expected
exit1 as statuserror; the wrapper initially asserted statusok,then the original
saved result was observed and read-only state verification completed. The
control was never resent. No native timeout or thermal-fault injection occurs.

G180's ordinary clean close/drain/unmap/unload is now natively verified with
its work-item support. Ninth unattended healthy-WinPE->fastboot->unchangedG155
->WinPE cycle completes; eighthG155 boot/sessiond375b631668c42207af7fd35425915fe.
Fresh DSP report passes and ordinary ESP loader restores. No partition flash,
GPT/BCD change or same-boot PAS retry. Current exactG180 owner is retainedREADY,
fault0,2maps,TX20/RX28,2completedbatches,lastcmd3,next4 after fresh cookie snapshot;
FV/restart consumed. Keep it until a whole next package is ready. G181's consumed
close-current.py targets the previousG180 instance,lastcmd32; do not replay it.
Current debuggerPID11836,OpenG80,logG181-20261026-040102/kd.txt,triggerless task.

A read-only live PnP inventory finds164connected nodes and just2ACPI devices:
UFS(QCOM24A5) and SSDE. UFS owns the sole reported memory range1D84000..1D9FFFF.
No gauge-controller,SPMI or GLINK PnP node appears. The576-byte DSDT exactly
matches the native driver binding and saved/source AML. Existing PnP metadata
does not prove the absence of firmware/non-PnP direct mappings,or the normal-
Windows resource state. These observations support adding a firmware-described
resource owner rather than marking the finite probes as a production lease.

Next qualify actual PnP resource/power lifetime and implement an ongoing native
paired producer,then battery-class/normal-Windows integration. G182 source work
has begun; it is not installed. Continuous standalone charging and all6full
project goal areas remain incomplete. Touch packets/mapping,300%,Never,test
certificate and default WinPE recovery are preserved. See experiments/G181-native-
health-expiry and evidence/G181. Native fault/timeout paths remain modeled;
healthy software recovery does not prove universal hard-hang recovery.

'''
(out/'README.txt').write_text(lead+'''\nReproduction scripts retain original private workspace/session/consumed-intent\nguards. They are evidence,not commands to replay blindly. Analysis uses the\nexactG180 C layout/validator and auditedG160/G167 decoders; native binaries are\nunchanged. Resource inventory command enumerates only; it never scans,restarts,\ninstalls or accesses registers. Raw firmware,physical captures and keys remain\nprivate. No driver source change or new native-driver signing is part ofG181.\n''')
for n in ['README.txt','PROGRESS.txt']:
 f=repo/n;s=f.read_text();assert s.startswith('OnePlus Open native Windows: current status,26 October2026 / G180 native');f.write_text(lead+s)
(e/'source-pins.json').write_text(json.dumps({f.name:sha(f)for f in sorted(out.iterdir())if f.is_file()},indent=2)+'\n');print({'export':str(out),'native_expiry_passed':True,'resource_inventory_observed':True})
