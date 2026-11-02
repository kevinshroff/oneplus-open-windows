"""Export verified policy components only; incomplete native adapter stays gated."""
from pathlib import Path
import hashlib,json,shutil
w=Path(__file__).resolve().parent;p=w/'private';repo=Path('/path/to/user/Documents/GitHub/oneplusopen-win11');ex=repo/'experiments/G178-charge-health-lease-core';ev=repo/'evidence/G178';ex.mkdir(exist_ok=False);ev.mkdir(exist_ok=False)
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();load=lambda n:json.loads((p/n).read_text());emit=lambda n,v:(ev/n).write_text(json.dumps(v,indent=2)+'\n')
files=[*list((w/'link').glob('*.c')),*list((w/'link').glob('*.h'))]
files+=[w/'tests'/n for n in ['test-link.c','peer.h','run.py','test-health.c','run-health.py','test-monitor.c','run-monitor.py','provider-layout.c']]
files+=[w/n for n in ['compile-components.py','prepare-health-layout.py','export-components.py']]
for f in files:
 d=ex/f.relative_to(w);d.parent.mkdir(exist_ok=True);shutil.copyfile(f,d)
for src,dst,key in [('core-ASan-final/tests.json','control-core-tests.json','source_sha256'),('health-ASan-final/tests.json','health-validator-tests.json','sources'),('monitor-ASan-final/tests.json','integrated-monitor-tests.json','source_sha256'),('components-ARM64-final/compile.json','components-ARM64-compile.json','source_sha256')]:
 v=load(src)
 for n,h in v[key].items():assert sha(w/n)==h and sha(ex/n)==h,n
 emit(dst,v)
emit('provider-layout-proof.json',load('health-layout/proof.json'))
assert load('core-ASan-final/tests.json')['cases']==715 and load('health-ASan-final/tests.json')['cases']==153 and load('monitor-ASan-final/tests.json')['cases']==12
assert '#error G178 native health-provider adapter'in(w/'native/driver.c').read_text()
emit('native-integration-obligations.json',{'status':'Not implemented or native qualified yet; draft driver build deliberately errors.','required_before_deployment':['Obtain immutable captures through fixed live kernel RESULT interfaces2255304/2255368; no user-provided physical values.','Use WDF-managed buffers with retained lifetime through timeout/cancel and close/delete of remote targets; test every acquisition/failure cleanup.','Evaluate actual interrupt time after reading both results; a slow read cannot renew an already expired interval.','Generate new C/Go request/snapshot ABI and ARM64 assertions; keep command IDs/idempotence,nonce binding and no raw property/value/duration API.','Wire fixed pre-FV/pre-restart roles and monitor renewals into the actual driver; preserve separate policy faults and GLINK uncertainty.','Native read-only consumer qualification can run with G177 retained and without starting another GLINK owner.','Only after every next/recovery asset is staged and verified,close/drain/unload G177 and use the qualified software-fastboot path for a fresh advertisement.','Qualify bounded15min charging,90s freshness-driven extensions and thermal/voltage/failure stops natively before normal Windows integration.','Proper PnP/resource/power ownership,physical producer lifecycle and G162 battery frontend remain required; no OwnerQualified/RateKnown shortcuts.'],'current_native_owner':'G177 remains retained READY,fault0,2maps,TX50/RX48,lastcmd4,next5 after fresh cookie snapshot; all control attempts consumed.','all_six_full_goal_areas_complete':False})
emit('WDF-contracts.json',{'sources':[{'url':'https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfiotarget/nf-wdfiotarget-wdfiotargetsendioctlsynchronously','used_for':'Planned fixed RESULT requests and WDF-managed buffer/reference lifetime; PASSIVE_LEVEL.'},{'url':'https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfiotarget/nf-wdfiotarget-wdfiotargetclose','used_for':'Planned close/cancellation/deletion ordering; pending child requests need explicit lifetime handling.'},{'url':'https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfrequest/ns-wdfrequest-_wdf_request_send_options','used_for':'Timeout cancellation contract for planned native requests.'}],'implementation_status':'Planning constraints only; actual native transport and its lifetime tests are still required.'})
(ex/'README.txt').write_text('''G178: verified charging-health and bounded-lifetime components, offline

Builds the monitoring/control policy needed before sustained charging. The
phone still runs the qualified G177 owner; this milestone sends no charger,
GLINK,bus,reset or flash request. One read-only owner snapshot confirms its
READY/fault0/2maps,lastcmd4 state. Native15min charging is not tested here.

health_capture.c validates completed immutableG167/G160 result records. It binds
the two nonces,checks exact source ABIs/identities/completion/cleanup,data/RX
traces and freshness in compatible interrupt-time units. Maximum pair span2s,
maximum age5s. It enforces the experimental mode40/CDP,300mA,FV4470 profile,
with4550 also allowed before the fixed FV action. Bounds are20..40C,3250..4300mV,
at most150mV cell difference and signed raw gauge current within+/-500mA. These
are experiment safeguards,not new OEM ratings or a pack-current calibration.
Pre-control states must be disabled/enabled1. Renewal requires an active charging
state and cleared discharge flags. It never manufactures PowerKnown/RateKnown,
a Windows capacity aggregate or a qualified hardware resource lease.

The control core retains the fixed off/5s/on sequence and normal kernel-driven
off. Without renewal the on interval is90s. An internally validated fresh health
sample may extend by at most90s,always capped at15min from enable acknowledgement.
An expired interval cannot be revived; duplicate times do not extend; early stop
and close win. Excess renewals force off. The monitor latches sensor/policy faults
and requests early off without hiding GLINK uncertainty or retrying a command.
A later good sample cannot clear a fault or re-enable the consumed sequence.

Verification uses the actual C components and explicit peer/time/fault models:
715 control-core cases,153 physical-record validator cases over the six saved
nativeG177 pairs,and12 integrated monitor/control cases. Cases include replay,
corruption,temperature/voltage/current limits,missed updates,stop/close,absolute
time cap and a lost off reply. All pass ASan/UBSan. Clock changes and mutated
sensor data are models,not new physical observations. These tests establish
software behavior,not native WDF/provider lifetime or sustained charging.

The actual ARM64 WDK compiles all4 components plus a17-assert provider ABI audit.
Offsets/lengths/control codes are checked against the exact existingG160/G167
source headers. Exports are rebuilt and pinned separately. Model inputs and
original source/header pins are retained as hashes; raw captures remain private.

Native integration is required next. The driver must read the two fixed live
kernel RESULT interfaces,not accept user-supplied sensor values. Managed request
buffers must survive timeout/cancel and remote-target deletion. Time must be
checked after provider I/O. New actual-driver tests,ABI/client generation,
signing and full package readiness precede any new charging run. The incomplete
native/client draft remains in the private workspace with a deliberate#error
build gate; it is not exported or deployable. G177 is retained until that entire
next package is ready. See evidence/G178/native-integration-obligations.json.

Reproduce: tests/run.py --output NEW_DIR. For run-health.py/run-monitor.py also
pass --captures WORKSPACE/work/charging-G177/private. compile-components.py takes
--output,--toolchain-receipt for the existingG135 compile receipt,--g160-source
and --g167-source for the exact provider source directories. prepare-health-layout.py
supports the same provider arguments plus --output. The generated header is
included and independently checked by the actual WDK provider-layout.c audit.

All six full goal areas remain incomplete. Sustained/normal-Windows charging,
startup/USB transitions,proper hardware/PnP/power/gauge ownership and battery
class registration are still required. Touch,300%,Never,test certificate and
default recovery WinPE stay preserved.
''')
emit('source-pins.json',{str(f.relative_to(ex)):sha(f)for f in sorted(ex.rglob('*'))if f.is_file()})
emit('verification.json',{'classification':'progress','control_cases':715,'health_cases':153,'integrated_cases':12,'ASan_UBSan':True,'ARM64_components_compiled':4,'ARM64_provider_ABI_assertions':17,'new_native_charger_or_bus_requests':0,'new_native_sustained_run':False,'native_adapter_ready':False,'draft_native_build_deliberately_blocked':True,'all_six_goal_areas_complete':False})
print({'exported':str(ex),'cases':[715,153,12],'native_sustained_tested':False})
