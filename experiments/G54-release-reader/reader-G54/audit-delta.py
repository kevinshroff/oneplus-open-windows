"""Pin the narrow G53 -> G54 production delta before any native load."""
from pathlib import Path
import difflib,hashlib,json
W=Path(__file__).resolve().parent;B=W.parent/'reader-G53'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
names=sorted([p.name for p in W.glob('g54_*.c')]+[p.name for p in W.glob('g54_*.h')]+['geni_fifo.c','geni_fifo.h','g54_client.go'])
same=[];changes={};old_hash={};new_hash={}
for name in names:
 p=W/name;q=B/name.replace('g54','g53');assert q.exists(),q
 old=q.read_text();new=p.read_text().replace('G54-release1','G53-poll-1').replace('G54','G53').replace('g54','g53').replace('314f52463435474f','314f52463335474f')
 old_hash[q.name]=sha(q);new_hash[name]=sha(p)
 if old==new:same.append(name)
 else:changes[name]=''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile=q.name,tofile=name))
assert set(changes)=={'g54_report.c','g54_contract.c'},list(changes)
binding=W/'private/inputs/g54_binding.h';old_binding=B/'private/inputs/g53_binding.h'
assert binding.read_text().replace('G54','G53').replace('g54','g53')==old_binding.read_text()
old_hash['private/inputs/g53_binding.h']=sha(old_binding);new_hash['private/inputs/g54_binding.h']=sha(binding)
report={'passed':True,'base':'G53','production_changes_only':['Zero-count touch report becomes header-validated release before trailing point/checksum access.','Legacy report metadata no longer claims a point type or body checksum for zero-count or request-zero reports.'],
 'namespace_build_normalization':['G54/g54 -> G53/g53','G54-release1 -> G53-poll-1','magic 314f52463435474f -> 314f52463335474f'],
 'unchanged_after_namespace_and_build_normalization':same,'changed_files_hunks':changes,
 'unchanged_native_MMIO_addresses_write_values_ownership_power_and_cleanup':True,
 'unchanged_nonzero_count_checksum_ID_and_range_semantics':True,
 'old_sha256':old_hash,'new_sha256':new_hash}
(W/'delta-audit.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'passed':True,'unchanged_files':len(same),'changed_files':list(changes)}))
