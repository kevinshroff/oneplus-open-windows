from pathlib import Path
import json,hashlib
from ops import q,good,ps,HOST,P
w=Path(__file__).resolve().parent
for local,remote in [(w/'Refresh-Debugger-G182.ps1','Refresh-Debugger-G182.ps1'),(P/'G182-release-v2.json','G182-release.json')]:good(q('corrected-put-'+remote,'host','put',session=HOST,file=local,path=remote,timeout=20))
text=r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$base=Join-Path $env:USERPROFILE 'Downloads\Open-G17\payloads'
& (Join-Path $base 'Boot-G182.ps1') -VerifyOnly|Out-Null
$tok=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile((Join-Path $base 'Refresh-Debugger-G182.ps1'),[ref]$tok,[ref]$errors)|Out-Null;if($errors.Count){throw 'Corrected script parse'}
$fb=Join-Path $env:USERPROFILE 'Downloads\platform-tools\fastboot.exe'
if((Get-FileHash -LiteralPath $fb -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'b2d9cbff4ce9ae7eb448cfc831bafc867935f50f5be38f8f81057fd7eb3b8d86'){throw 'Fastboot executable identity'}
$devices=([string](& $fb devices 2>&1|Out-String)).Trim();if($LASTEXITCODE -ne 0){throw 'Mode query failed'}
if($devices -match '^DEVICE_SERIAL\s+fastboot$'){& (Join-Path $base 'Boot-G182.ps1')}elseif($devices.Length -eq 0){@{phase='G182_fixed_package_ready_phone_left_fastboot';partition_flashes=0;utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress}else{throw 'Unexpected fastboot identity'}
'''
r=ps('corrected-native-launch',text,timeout=80);v=json.loads(r['output']);(P/'corrected-launch.json').write_text(json.dumps(v,indent=2)+'\n');print(v)
