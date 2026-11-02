"""Independent Mac backup hash before reusing the VM's owned temporary image."""
from pathlib import Path
import hashlib,json,subprocess
W=Path(__file__).resolve().parent;B=W.parent/'gpio-G23/private/G23-gpio-input-v1.wim';p=W/'WIM-source-backup.json';assert not p.exists();h=hashlib.sha256()
with B.open('rb')as f:
 for b in iter(lambda:f.read(8<<20),b''):h.update(b)
assert B.stat().st_size==592882167 and h.hexdigest()=='bf8da75a5ff96af9c65fb5f059e6cbb8206595aeeee9c5057e31e31bd4e30250'
d={'phase':'Mac_retained_independent_source_backup_verified','retained_source':str(B.resolve()),'source_bytes':B.stat().st_size,'source_sha256':h.hexdigest(),'phone_operations':0};p.write_text(json.dumps(d,indent=2)+'\n');print(json.dumps(d))
