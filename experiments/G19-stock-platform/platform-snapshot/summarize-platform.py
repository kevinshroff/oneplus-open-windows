"""Describe observed register states; do not convert differing snapshots into a cause."""
from pathlib import Path
import json
W=Path(__file__).resolve().parent;r=json.loads((W/'platform-live-initial.json').read_text());g=r['GICD'];u=r['UFS_HCI'];bit=1<<(297%32)
r['UFS_interrupt_first_snapshot']={'GIC_ID':297,'bank_bit':hex(bit),'group1_bit_set':bool(g['0x171000a4']&bit),'enabled':bool(g['0x17100124']&bit),'pending':bool(g['0x17100224']&bit),'active':bool(g['0x17100324']&bit),'trigger':'edge' if g['0x17100c48']&(2<<((297%16)*2)) else 'level','routing_affinity_raw':[g['0x17106948'],g['0x1710694c']],'routing_IRM':bool(g['0x17106948']&0x80000000),'HCI_IS':u['0x1d84020'],'HCI_IE':u['0x1d84024'],'UTRL_doorbell':u['0x1d84058'],'UTRL_completion_notification':u['0x1d84064']}
recheck=json.loads((W/'socinfo-live-result.json').read_text())['GICD_UFS_recheck'];r['later_snapshot_raw']=recheck
r['observed_changes']=[{'address':k,'first':r['GICD'].get(k,r['UFS_HCI'].get(k)),'later':v} for k,v in recheck.items() if r['GICD'].get(k,r['UFS_HCI'].get(k))!=v]
r['causal_limit']='Two native stops show GIC interrupt297 and HCI interrupt enables on, then off, while pending/active/doorbell/completion fields remain clear. A driver path, idle power transition or debugger-stop timing has not been distinguished. This does not prove the cause of the earlier stall. Correlate a controlled I/O wake and the compiled enable/disable paths; capture the same uncached registers during a real fault.'
(W/'platform-live-initial.json').write_text(json.dumps(r,indent=2)+'\n')
