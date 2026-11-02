"""Return the audited, restored single native clock trial to preserved G17."""
from pathlib import Path
import json
from relay import Relay
W=Path(__file__).resolve().parent
b=json.loads((W/'boot-resource.json').read_text());p=json.loads((W/'resource-boot-preparation.json').read_text())
a=json.loads((W/'native-cycle-audit.json').read_text());n=json.loads((W/'native-clock.json').read_text())
assert b['root']['x_is_ramdisk']and b['all_six_GPTs_byte_identical_to_baseline']
assert p['G17_default_and_all_original_BCD_keys_values_unchanged']
assert a['passed']and a['native_finite_clock_cycle_and_restoration_qualified']and n['post_cycle_cached_query_byte_identical']
c=a['report_after']['clock'];assert c['restored']==1 and c['restore_error']==c['dirty_mask']==c['active']==0
R=Relay('return-to-G17.json',phone_session=b['session']);s=R.s
s.update(phase='return_reboot_requested',starting_session=b['session'],expectation='original G17 default after consumed one-time sequence',protected_partition_writes=0);R.persist()
r=R.op('single-return-reboot','phone','reboot');assert r['status']=='ok'
s.update(phase='return_reboot_acknowledged',reboot=r);R.persist();print(s['phase'],flush=True)
