"""Replay the consumed G41 touch failure through the unchanged actual C cores."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--native',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
W=Path(__file__).resolve().parent;s=json.loads(a.native.read_text());r=s['trial']['touch']
assert s['outcome']=='identity_verified' and not s['safe_exit_verified']
scalars={'Code':'operation_code','RestoreError':'restore_error','Restored':'restored','Stage':'stage','Reads':'register_reads','Writes':'register_write_attempts','AnalogDirty':'analog_dirty','ResetDirty':'reset_dirty','CommandAttempted':'command_attempted','TransportOk':'transport_ok','IdentityOk':'identity_ok','BusQuiescent':'bus_quiescent','LengthsSaved':'lengths_saved','LengthsRestored':'lengths_restored','LengthsDirty':'lengths_dirty','IrqAcked':'GPIO_IRQ_acknowledged','StartCode':'start_code','StepCode':'step_code','State':'state','Steps':'steps','TxDone':'tx_done','RxDone':'rx_done','CancelSent':'cancel_sent','AbortSent':'abort_sent'}
arrays={'BeforePins':'pins_before','OnPins':'pins_on','AfterPins':'pins_after','LengthsBefore':'lengths_before','LengthsAfter':'lengths_after','CommandHistory':'command_history','WaitCounts':'wait_counts','Tx':'wire_TX','Rx':'wire_RX'}
fields=['.%s=%d'%(c,r[j])for c,j in scalars.items()]
fields+=['.TraceCount=%d'%len(r['trace'])]
fields+=['.%s={%s}'%(c,','.join(map(str,r[j])))for c,j in arrays.items()]
assert r['ROM_PID']=='BERLIN'and r['patch_PID']=='9966'and r['sensor_id']==255
fields+=['.Version={.rom_pid='+json.dumps(r['ROM_PID'])+',.patch_pid='+json.dumps(r['patch_PID'])+',.rom_vid={'+','.join(map(str,r['ROM_VID']))+'},.patch_vid={'+','.join(map(str,r['patch_VID']))+'},.sensor_id='+str(r['sensor_id'])+'}']
assert sum(r['wire_RX'][8:34])==int.from_bytes(bytes(r['wire_RX'][34:36]),'little')==1181
fields+=['.Trace={'+','.join('{%d,0x%x,0x%x}'%(e['kind'],int(e['address'],16),e['value'])for e in r['trace'])+'}']
(a.output/'native-touch-fixture.h').write_text('static const G41_TOUCH_RESULT Expected={'+','.join(fields)+'};\n')
names=['g41_touch.c','geni_fifo.c','replay-touch.c'];exe=a.output/'replay-touch'
cmd=['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.output.resolve()),*[str(W/n)for n in names],'-o',str(exe.resolve())]
q=subprocess.run(cmd,capture_output=True,text=True);assert q.returncode==0,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert q.returncode==0 and not q.stderr,(q.returncode,q.stdout,q.stderr)
report=json.loads(q.stdout);assert report['passed']
report.update(ASan_UBSan=True,source_sha256={n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in names},native_state_sha256=hashlib.sha256(a.native.read_bytes()).hexdigest(),native_commands_submitted=0,limits=['Saved native MMIO boundaries are replay inputs, not new physical observations.','Powered PMIC confirmation is one recorded successful callback boundary; its observer MMIO is outside this touch-only replay.','The recorded physical identity/complete transfer is reproduced; no new hardware transaction or cleanup is performed by this replay.'])
(a.output/'replay.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
