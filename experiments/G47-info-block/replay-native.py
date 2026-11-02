"""Replay every actual cleanup core against saved G47 native MMIO boundaries."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--native',type=Path,required=True);p.add_argument('--binding',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
s=json.loads(a.native.read_text());r=s['trial'];assert s['safe_exit_verified']and r['restored']==1 and r['operation_code']==r['restore_error']==0

def value(v):
 if isinstance(v,bool):return str(int(v))
 if isinstance(v,list):return '{'+','.join(map(str,v))+'}'
 if isinstance(v,str):return str(int(v,16))
 return str(v)
def fields(r,m):return ''.join('.'+k+'='+value(r[j])+','for k,j in m.items())
def trace(r):return '.TraceCount='+str(len(r['trace']))+',.Trace={'+','.join('{%d,0x%x,0x%x}'%(x['kind'],int(x['address'],16),x['value'])for x in r['trace'])+'},'
base=dict(Code='operation_code',Stage='stage',Reads='register_reads')
obs=dict(base,Writes='observer_write_attempts',Polls='polls',Commands='observer_READ_commands',Completion='completion',Revision='revision',Anchor='anchor',Identity='identity',Status='pmic_status_raw',Configuration='configuration')
standard=dict(base,RestoreError='restore_error',Restored='restored',Writes='register_write_attempts')
rs=dict(standard,RequestAddress='request_address',RequestData='request_data',MsgId='message_id',Completion='completion',Response='response',Triggered='trigger_attempted',Mutated='mutated',Before='before',After='after')
power=dict(Code='operation_code',RestoreError='restore_error',Restored='restored',Stage='stage',TxnCount='transaction_count',PmicCount='pmic_count',EnableAttempted='enable_attempted',ReleaseAttempted='release_attempted',PreflightVerified='preflight_verified',OnVerified='on_verified',OffVerified='off_verified',RscUncertain='RSC_uncertain',ObserverUncertain='observer_uncertain',SourceStatusBaseline='source_status_baseline',ClientBefore='client_before',ClientOn='client_on',ClientAfter='client_after',GuardBefore='guards_before',GuardAfter='guards_after',Waits1ms='waits_1ms',Waits10ms='waits_10ms')
spi=dict(standard,DirtyPins='dirty_pins',VoteDirty='vote_dirty',BeforeClock='clock_before',AfterClock='clock_after',BeforePins='pins_before',DuringPins='pins_during',AfterPins='pins_after',Identity='identity',VoteEnabled='enabled_vote')
engine=dict(standard,Dirty='dirty',Before='before',During='during',After='after',DfsBefore='DFS_before',DfsAfter='DFS_after',Index='clock_index',SourceHz='source_hz',BusHz='bus_hz',GuardBefore='guards_before',GuardAfter='guards_after')
touch=dict(standard,InfoLength='info_length',HeaderLengthValid='header_length_valid',FullBlockChecksumValid='full_IC_info_checksum_verified',AnalogDirty='analog_dirty',ResetDirty='reset_dirty',CommandAttempted='command_attempted',TransportOk='transport_ok',IdentityOk='identity_ok',BusQuiescent='bus_quiescent',LengthsSaved='lengths_saved',LengthsRestored='lengths_restored',LengthsDirty='lengths_dirty',IrqAcked='GPIO_IRQ_acknowledged',StartCode='start_code',StepCode='step_code',State='state',Steps='steps',TxDone='tx_done',RxDone='rx_done',CancelSent='cancel_sent',AbortSent='abort_sent',BeforePins='pins_before',OnPins='pins_on',AfterPins='pins_after',LengthsBefore='lengths_before',LengthsAfter='lengths_after',CommandHistory='command_history',WaitCounts='wait_counts',Tx='wire_TX',Rx='wire_RX')
sp=r['spi'];t=r['touch'];e=sp['engine'];assert t['command_attempted']==1 and t['identity_ok']==0 and t['ROM_PID']==t['patch_PID']==''
block=lambda r,m:'{'+fields(r,m)+trace(r)+'}'
text='static const G47_TRIAL_RESULT Expected={.Power={'+fields(r,power)+'.Transactions={'+','.join(block(x,rs)for x in r['transactions'])+'},.Pmic={'+','.join(block(x,obs)for x in r['PMIC'])+'}},.Spi={'+fields(sp,spi)+trace(sp)+'.Engine='+block(e,engine)+'},.Touch={'+fields(t,touch)+trace(t)+'.PoweredPmic='+block(t['powered_PMIC'],obs)+'},.PoweredHookCalled='+str(r['powered_hook_called'])+',.SafeRelease='+str(r['safe_release'])+'};\n'
(a.output/'native-recovery-fixture.h').write_text(text)
names=['g47_observer.c','g47_rsc.c','g47_power.c','g47_spi.c','g47_engine.c','g47_touch.c','geni_fifo.c','replay-native.c'];exe=a.output/'replay'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.output.resolve()),'-I',str(a.binding.resolve()),*[str(W/n)for n in names],'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stdout,q.stderr);report=json.loads(q.stdout)
expected_events=sum(len(x['trace'])for x in[sp,e,t,t['powered_PMIC'],*r['PMIC'],*r['transactions']]);assert report['events']==expected_events
report.update(ASan_UBSan=True,source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in names},native_state_sha256=hashlib.sha256(a.native.read_bytes()).hexdigest(),native_job=s['jobs']['info-block-trial']['id'],binding_sha256=hashlib.sha256((a.binding/'g47_binding.h').read_bytes()).hexdigest(),native_commands_submitted=0,limits=['All recorded MMIO/pin values are replay inputs; the replay performs no phone operations.','This replays one complete242-byte IC-info read, checksum and cleanup. Report addresses still require separate bounds/source interpretation.'])
(a.output/'replay.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
