"""Finalize the successful bounded native result and exact reproducible sources."""
from pathlib import Path
import hashlib,json,shutil,struct
w=Path(__file__).resolve().parent;p=w/'private';repo=Path('/path/to/user/Documents/GitHub/oneplusopen-win11');ex=repo/'experiments/G177-AP-charge-restart';ev=repo/'evidence/G177'
load=lambda n:json.loads((p/n).read_text());sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();emit=lambda n,v:(ev/n).write_text(json.dumps(v,indent=2)+'\n')
analysis=load('cycle-analysis.json');assert analysis['successful']and len(analysis['snapshots'])==5 and len(analysis['observations'])==4
wire=load('restart-wire-proof.json');assert wire['passed']and wire['off_to_on_us']==5010416 and wire['on_to_off_us']==90007970 and wire['control_ack_mask']==14336
assert wire['initial_off_frames']==wire['enable_frames']==wire['final_off_frames']==1
assert not any(wire[k]for k in ['initial_off_result','enable_result','final_off_result'])
rows=[];timing=[]
windows=[(wire['initial_off_us'],wire['enable_us']),(wire['enable_us'],wire['final_off_us']),(wire['enable_us'],wire['final_off_us']),(wire['final_off_us'],2**64-1)]
for i,o in enumerate(analysis['observations']):
 c=o['captures']['G167'];g=o['captures']['G160'];assert c['independent_decode_equal']and g['independent_decode_equal']
 cb=Path(c['path']).read_bytes();gb=Path(g['path']).read_bytes();assert len(cb)==1096 and len(gb)==279880
 assert sha(Path(c['path']))==c['sha256']and sha(Path(g['path']))==g['sha256']
 begin,end=struct.unpack_from('<Q',cb,104)[0]/10,struct.unpack_from('<Q',cb,112)[0]/10;gdone=struct.unpack_from('<Q',gb,56)[0]/10;lo,hi=windows[i]
 assert lo<begin<=end<gdone<hi
 enable=cb[184+7*8+6]&1;assert enable==o['physical_enable_bit']==[0,1,1,0][i]
 t=c['result']['telemetry'];gauges=g['result']['gauges']
 assert t['float_voltage_mV']==4470 and t['fast_current_mA']==300 and t['register_4f43_raw']=='0x40'and t['APSD_type']=='CDP'
 assert t['state_first']==t['state_last']==['DISABLED','FULLON','FULLON','DISABLED'][i]
 assert all(a['identity_recognized']and 3250<=a['voltage_mV']<=4300 and 20<=a['temperature_celsius']<=40 for a in gauges)
 if i in [1,2]:assert all(not a['discharge_flag']and a['average_current_signed_mA']>100 for a in gauges)
 rows.append({'phase':o['label'],'physical_enable_bit':enable,'state':t['state_last'],'config':t,'gauges':gauges,'capture_sha256':{'G167':c['sha256'],'G160':g['sha256']},'finite_observers_retired_and_separately_absent':True})
 timing.append({'phase':o['label'],'config_interrupt_begin_us':begin,'config_interrupt_end_us':end,'gauge_final_status_interrupt_us':gdone,'inside_correct_wire_interval':True,'proof':'G167/G160 execute sequentially in the source-pinned helper; G167 wrapper bounds and the G160 final status point use interrupt time. Result QPC timestamps are not compared with this epoch.'})
assert rows[2]['gauges'][0]['remaining_capacity_mAh']>rows[0]['gauges'][0]['remaining_capacity_mAh']
assert rows[3]['gauges'][1]['remaining_capacity_mAh']>rows[0]['gauges'][1]['remaining_capacity_mAh']
final=load('owner-idle-native.json')['snapshot'];s=final['state'];assert final['Running']==1 and final['MapsLive']==2 and final['last_command_id']==4 and s['Phase']==3 and s['BatchesCompleted']==3 and s['TxFrames']==50 and s['RxFrames']==48
assert not any(s[k]for k in ['Fault','Pending','BatchActive','TransportUncertain','RpcUncertain'])
assert s['BoardFvAcked']==s['PulseAttempted']==s['RestartOffAcked']==s['PulseEnableAcked']==s['PulseDisableAcked']==1
restore=load('final-loader-inspection-receipt.json');v=json.loads(restore['output']);assert v['phase']=='G154_inspect'and v['windows_loader_sha256']=='fae47d78487e781aa06466775cb461adeb7ff7f887fe2c15295bb2eb4f4954e1'and v['ordinary_file_writes']==v['raw_disk_writes']==v['reboots']==0
old=load('old-owner-close-intent.json');assert old['complete']and old['native_closed_and_unloaded']
boot=load('fresh-boot-intent.json');assert boot['phase']=='temporary_boot_command_accepted';report=load('fresh-DSP-report-native.json')['report'];assert report['phase']==[3,3]and report['fault']==0 and report['main_public_success']
proof=load('export-rebuild-proof.json');assert proof['ARM64_C_objects_byte_identical']and proof['Go_tools_byte_identical']and proof['signed_CMS_verified']
for name,out in [('FV-wire-proof.json','FV-wire-proof.json'),('restart-wire-proof.json','restart-wire-proof.json'),('export-rebuild-proof.json','export-rebuild-proof.json')]:emit(out,load(name))
emit('interrupt-time-proof.json',{'passed':True,'intervals':timing,'native_recaptures':0})
emit('physical-results.json',{'campaign':'G177','session':analysis['session'],'observations':rows,'charging_observed_in_bounded_WinPE_test':True,'fully_qualified_ongoing_charging':False,'note':'Gauge discharge flags clear while enabled and remain clear at the short post-off point; no instantaneous flag return is claimed. Current falls to15/0mA and hardware state isDISABLED after final off. The OnePlus API sign-inverted column is retained alongside raw signed gauge words; no aggregate pack-current calibration is claimed.'})
for phase in ['before-fv','after-fv']:emit(phase+'-hardware-summary.json',load(phase+'-hardware-summary.json'))
native={'campaign':'G177','classification':'progress','session':analysis['session'],'scope':'One fixed bounded low-current WinPE test; real charging observed.','native_FV_SETs':1,'native_boolean_SETs':3,'boolean_values':[0,1,0],'service_results':[0,0,0,0],'native_GET_queries':10,'wire':wire,'physical_enable_bits':[0,1,1,0],'physical_states':['DISABLED','FULLON','FULLON','DISABLED'],'average_current_signed_mA':[[a['average_current_signed_mA']for a in r['gauges']]for r in rows],'cell_voltages_mV':[[a['voltage_mV']for a in r['gauges']]for r in rows],'remaining_capacity_mAh':[[a['remaining_capacity_mAh']for a in r['gauges']]for r in rows],'charging_observed_in_bounded_WinPE_test':True,'fully_qualified_ongoing_charging':False,'normal_final_off_independent_of_laptop_or_client':True,'physical_gauge_queries':120,'SPMI_READ_commands':114,'paired_observations':6,'all_finite_observers_retired_and_independently_absent':True,'G170_closed_drained_unmapped_unloaded':True,'G154_software_fastboot_complete_cycles':7,'G155_boots':6,'original_ESP_loader_restored_and_read_only_verified':True,'host_stage_reused_files':load('host-stage-intent.json')['reused_files'],'debugger':boot['result']['debugger'],'retained_owner':{'phase':3,'fault':0,'maps':2,'timer_calls':final['timer_calls'],'batches':3,'TX':50,'RX':48,'last_command':4,'next_command_after_fresh_snapshot':5,'FV_and_restart_attempts_consumed':True,'physical_enable_after_test':0},'partition_flashes':0,'same_boot_PAS_retries':0,'gauge_init38_requests':0,'OEM10000_requests':0,'all_six_full_goal_areas_complete':False,'inference':'An explicit AP-side0->1 edge after the fixed FV correction is sufficient to start charging in this boot/configuration. G176 shows the original internal recovery setter is deliberately a success/no-op under AP control. The precise origin of the initial disabled condition is not established.','limits':['One bounded90s WinPE run,not an ongoing production charger or a full battery cycle.','Only the programmed300mA FCC is qualified here; no larger current or aggregate gauge-current calibration is established.','Full Windows automatic startup,repeat fresh boots,USB attach/detach,charger types,thermal/voltage cutoffs and sustained charging remain to qualify.','Proper PnP/resource/power/gauge producers and a Windows battery class remain incomplete.','Transport uncertainty remains uncertainty; kernel-timed normal off is not a guarantee after transport failure.'],'next':'Preserve the proven fixed4470/off-on initialization. Prepare bounded sustained low-current qualification with physical thermal/voltage monitoring and safe off; then repeat startup/USB transitions and integrate normal Windows resource/power/battery ownership. Retain this owner until the next entire package is immediately ready.'}
emit('native-analysis.json',native);emit('loader-restoration.json',v)
emit('native-job-summary.json',{'session':analysis['session'],'jobs':{'cycle':load('cycle-intent.json')['job'],'loader_inspection':load('final-loader-inspection-intent.json')['job']},'all_native_cycle_requests_terminal':True,'raw_snapshots_independently_decoded':5,'raw_paired_observations_independently_decoded':6})
# Preserve the corrected analysis parser and this exporter; deployed source did not change.
for name in ['analyze-wire.c','export-evidence.py']:shutil.copyfile(w/name,ex/name)
(ex/'README.txt').write_text('''G177: first controlled charging response in native WinPE

The fixed AP sequence off/5s/on/90s/off starts real charging. Native wire frames
prove exactly0,1,0 at property24; all replies succeed. The measured gaps are
5.010416s and90.007970s. The retained kernel timer drives normal off independently
of this helper,USB control or laptop. Physical2646bit0 follows0,1,1,0 in the
four locally timed paired observations. No arbitrary property/value/duration
or raw-packet interface is exposed. FV4470mV is independently verified first.

phase          state       currents mA   cell mV       remaining mAh
initial off    DISABLED      8/0         3513/3515     59/18
early enabled  FULLON      227/134       3536/3548     59/17
late enabled   FULLON      233/129       3551/3562     62/19
after off      DISABLED     15/0         3533/3537     64/20

Both discharge flags clear while enabled; temperatures stay31.4/about33C.
The first gauge moves2->3% by the late sample. At the short post-off point the
flags have not yet returned; only the physical disabled bit/state and low
current are qualified there. Raw gauge current and the sign-inverted OnePlus
API column remain distinguished. No aggregate pack-current calibration is
claimed. Configuration remains mode40,FCC300mA,FV4470mV,CDP throughout.

G176 motivates the different test: original6009abb0 detects state7/enabled1
and calls its internal off/on recovery, but6009ab40->600b8410 deliberately
returns success under AP control without changing hardware. EarlierG170 sent
on while already on; it never qualified this explicit AP0->1 edge. The edge
is sufficient in this native test; the precise initial-inhibit cause and actual
live firmware callback/platform selection are not established by static code.

Six pairedG167/G160 observations,including fresh pre/postFV admission,perform
114fixedSPMI READs and120physical gauge queries. Each finite observer retires
and is separately absent. All raw records independently decode. Config wrapper
and gauge final-status interrupt time prove the intended intervals; result QPC
timestamps use another epoch and are not compared directly. No new recording,
full partition backup or repeated control action is used for this proof.

The oldG170 owner closes/drains/unmaps/unloads cleanly before the seventh
autonomous healthy-WinPE->bootloader-fastboot->unchangedG155->freshWinPE cycle.
SixthG155 boot/session7f43c53bf3c59c648c3424853efc2b83 passes fresh DSP admission.
The ordinary ESP loader is restored and independently inspected afterward.
No partition flash or same-boot PAS retry. The qualified fastboot method depends
on responsive WinPE; it is not universal hard-hang recovery.

G177 remains READY,fault0,2maps,3batches,TX50/RX48,lastcmd4,next5 after a fresh
cookie snapshot. FV/restart attempts are consumed. Hardware is off after the
bounded test. Keep this owner until the complete next package is immediately
ready; never reopen/reload it or replay consumed native controller scripts.
DebuggerPID1196,pipeOpenG80,logG177-20261026-013811/kd.txt; debug task is triggerless.

Validation:708 actual-core ASan/UBSan cases,97 actual-driver callback cases with
ASan/UBSan and separatelyTSan/50 threaded shutdown rounds,42Go pass events,
103actual-C ABI checks compiled with ARM64 WDK. Tests cover rejected initial
off,no-retry RPC uncertainty,cancellation while replies are pending,cancellation
in the off interval,late timers and independent normal finaloff. Exported C
objects and all3new Go tools reproduce byte for byte. Private native model
fixtures are identified in evidence/G177/private-model-inputs.json.

This proves bounded low-current charging in WinPE. Sustained charging,repeat
startup,USB/charger changes,thermal/voltage transitions,normal Windows automatic
startup,proper resource/PnP/power ownership and battery-class integration remain
open. All six full goal areas remain incomplete. Next prepare sustained bounded
low-current qualification with physical monitoring and safe off,then qualify
startup/USB changes and normal Windows ownership. Preserve touch,300%,Never,
test certificate and default recovery WinPE. No gauge-init38 or OEM10000 path.

Build/test: tests/run.py --output <new-dir>. tests/run-native.py also needs the
three private fixtures. Go tests run in client/. build.py takes --output and
--toolchain-receipt pointing to the pinnedG135 compile receipt. Source/pin and
tool flags are in evidence/G177/readiness.json and cycle-build.json. Native
orchestration scripts retain consumed intent guards/current-session assumptions;
they are historical qualification sources,not scripts to rerun blindly.
''')
emit('source-export-pins.json',{str(f.relative_to(ex)):sha(f)for f in sorted(ex.rglob('*'))if f.is_file()})
print({'charging_observed':True,'wire_seconds':[wire['off_to_on_us']/1e6,wire['on_to_off_us']/1e6],'paired_observations':6,'finite_observers_retired':True,'owner_retained_READY':True,'all_six_goal_areas_complete':False})
