from pathlib import Path
import json,hashlib
from ops import q,good,ps,HOST
w=Path(__file__).resolve().parent;p=w/'private';f=p/'G182-release.zip';h=hashlib.sha256(f.read_bytes()).hexdigest()
good(q('put-G182-release','host','put',session=HOST,file=f,path=f.name,timeout=25))
text=r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$base=Join-Path $env:USERPROFILE 'Downloads\Open-G17\payloads';$z=Join-Path $base 'G182-release.zip'
if((Get-FileHash -LiteralPath $z -Algorithm SHA256).Hash.ToLowerInvariant() -ne '__HASH__'){throw 'Release archive identity'}
foreach($n in @('Boot-G182.ps1','G182-release.json','boot-G182-resources.img')){if(Test-Path -LiteralPath (Join-Path $base $n)){throw 'Existing G182 staging needs observation'}}
Expand-Archive -LiteralPath $z -DestinationPath $base
$errors=@()
foreach($n in @('Boot-G182.ps1','Refresh-Debugger-G182.ps1','G182-Restore-EEM.ps1')){$tok=$null;$parse=$null;[Management.Automation.Language.Parser]::ParseFile((Join-Path $base $n),[ref]$tok,[ref]$parse)|Out-Null;$errors+=@($parse)}
if($errors.Count){throw 'Native script parse error'}
& (Join-Path $base 'Boot-G182.ps1') -VerifyOnly|Out-Null
$kd='C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe'
$owners=@(Get-NetUDPEndpoint -LocalPort 50000|Select-Object -ExpandProperty OwningProcess -Unique)
if($owners.Count -ne 1 -or $owners[0] -ne 11836 -or (Get-Process -Id 11836).Path -ne $kd){throw 'Debugger ownership changed'}
$proc=Get-CimInstance Win32_Process -Filter 'ProcessId=11836'
if($proc.CommandLine -notlike '*npipe:pipe=OpenG80,hidden*' -or $proc.CommandLine.IndexOf('G181-20261026-040102\kd.txt',[StringComparison]::OrdinalIgnoreCase) -lt 0){throw 'Debugger log/pipe mismatch'}
# Independently retained qualified G155 rollback image; no original files replaced.
$old=Join-Path $env:USERPROFILE 'Downloads\Open-G155-MainAuth\boot-G155-main-auth.img'
if((Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'ccdfa94277975cc37b1f3f316d08a401b3127a93d148226412eecfb02d524a6a'){throw 'Rollback image identity'}
@{phase='G182_immediate_launch_ready';files=12;debugger_pid=11836;utc=[DateTime]::UtcNow.ToString('o');partition_flashes=0}|ConvertTo-Json -Compress
'''.replace('__HASH__',h)
r=ps('host-boot-stage',text);v=json.loads(r['output']);assert v['phase']=='G182_immediate_launch_ready';(p/'host-ready.json').write_text(json.dumps(v,indent=2)+'\n');print(v)
