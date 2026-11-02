"""Return a proved RAM session through the preserved original default once."""
from pathlib import Path
import json
from relay import Relay
W=Path(__file__).resolve().parent
b=json.loads((W/'boot-ram.json').read_text());p=json.loads((W/'one-time-boot-preparation.json').read_text())
assert b['phase']=='fresh_boot_root_and_all_protected_metadata_verified'and b['root']['x_is_ramdisk']and b['all_six_GPTs_byte_identical_to_baseline']
assert p['G17_default_and_all_original_BCD_keys_values_unchanged']
R=Relay('return-to-G17.json',phone_session=b['session']);s=R.s
s.update(phase='return_reboot_requested',starting_session=b['session'],expectation='original G17 default after the consumed one-time sequence',protected_partition_writes=0);R.persist()
r=R.op('single-return-reboot','phone','reboot');assert r['status']=='ok';s.update(phase='return_reboot_acknowledged',reboot=r);R.persist();print(s['phase'],flush=True)
