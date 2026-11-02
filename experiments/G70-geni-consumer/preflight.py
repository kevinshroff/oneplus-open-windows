"""Seal current source, modeled evidence, binding and ARM64 inputs before linking."""
from pathlib import Path
import hashlib,json,re
W=Path(__file__).resolve().parent;P=W/'private';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
# The qualified clock algorithm is unchanged; this trial adds a real bounded consumer.
assert (W/'g70_clock.c').read_text()==(W.parent/'root-status-G69/g69_clock.c').read_text().replace('G69','G70').replace('g69','g70')
checks={}
for name in ['clock-model-01','consumer-model-01','driver-model-01','client-policy-01']:
 m=json.loads((P/name/'tests.json').read_text());assert m['passed'] and m['native_operations']==0
 for n,h in m.get('source_sha256',{}).items():assert sha(W/n)==h,(name,n)
 if 'driver_source_sha256' in m:assert sha(W/'g70_driver.c')==m['driver_source_sha256']
 checks[name]=m['cases']
assert checks=={'clock-model-01':4704,'consumer-model-01':1056,'driver-model-01':68,'client-policy-01':280}
table=(P/'acpi-01/acpitabl.dat').read_bytes();binding=P/'acpi-01/g70_binding.h';assert bytes(int(x,16)for x in re.findall(r'0x([0-9a-f]{2})',binding.read_text()))==table
assert len(table)==768 and hashlib.sha256(table).hexdigest()=='4079f58af46d7c8e262973283a055ac0c7cc3d5208165cfb599884e621e75f39'
assert json.loads((P/'driver-model-01/tests.json').read_text())['binding_sha256']==sha(binding)
fixture=P/'driver-model-01/MODEL-NOT-NATIVE.bin';assert sha(fixture)==json.loads((P/'client-policy-01/tests.json').read_text())['fixture_sha256']
for name in ['compile-01','client-objects-01']:
 m=json.loads((P/name/'compile.json').read_text());assert m['binding_sha256']==sha(binding)
 for n,h in m['headers'].items():assert sha(W/n)==h
 for row in m['objects']:assert sha(W/row['source'])==row['source_sha256'] and sha(P/name/row['object'])==row['sha256']
assert r'ACPI\OPEN0070' in (W/'OpenG70.inf').read_text() and 'DriverVer=10/22/2026,0.0.70.0' in (W/'OpenG70.inf').read_text()
r={'passed':True,'checks':checks,'clock_algorithm_unchanged_from_native_G69':True,'table_sha256':hashlib.sha256(table).hexdigest(),'table_bytes':768,'raw_GSI':389,'map_count':4,'assigned_IRQ_recorded_not_connected':True,'native_G70_controller_probe_qualified':False};(W/'preflight.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
