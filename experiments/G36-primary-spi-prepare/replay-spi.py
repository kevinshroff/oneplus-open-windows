"""Replay the actual portable SPI preparation core over the saved native trace."""
import argparse,hashlib,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--native',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
s=json.loads(a.native.read_text());row=s['jobs']['spi-prepare'];q=json.loads(row['receipt']['output']);assert q['ok'];r=q['result'];assert r['operation_code']==r['restore_error']==0 and r['restored']==1
fields={'Code':r['operation_code'],'RestoreError':r['restore_error'],'Restored':r['restored'],'Stage':r['stage'],'Reads':r['register_reads'],'Writes':r['register_write_attempts'],'TraceCount':len(r['trace']),'DirtyPins':r['dirty_pins'],'VoteDirty':r['vote_dirty'],'BeforeClock':r['clock_before'],'AfterClock':r['clock_after'],'BeforePins':r['pins_before'],'DuringPins':r['pins_during'],'AfterPins':r['pins_after'],'Identity':r['identity'],'VoteEnabled':r['enabled_vote']}
text='static const G36_SPI_RESULT Expected={\n'
for key,value in fields.items():text+='.'+key+'='+('{'+','.join(map(str,value))+'}'if isinstance(value,list)else str(value))+',\n'
text+='.Trace={'+','.join('{%d,0x%x,0x%x}'%(e['kind'],int(e['address'],16),e['value'])for e in r['trace'])+'}};\n';(a.output/'spi-native-fixture.h').write_text(text)
exe=a.output/'replay';subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(a.output.resolve()),str(W/'g36_spi.c'),str(W/'replay-spi.c'),'-o',str(exe.resolve())],check=True,capture_output=True,text=True)
run=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert run.returncode==0 and not run.stderr,(run.stdout,run.stderr);report=json.loads(run.stdout)
report.update(core_sha256=hashlib.sha256((W/'g36_spi.c').read_bytes()).hexdigest(),native_state_sha256=hashlib.sha256(a.native.read_bytes()).hexdigest(),native_job=row['id'],ASan_UBSan=True,all_output_fields_and_reads_writes_match=True,native_commands_submitted=0,limits=['The recorded MMIO trace is a modeled boundary; actual hardware permission/levels are proven by separate native receipts.'])
(a.output/'replay.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
