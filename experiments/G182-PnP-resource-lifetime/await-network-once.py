from ops import ps,P
import json
r=ps('await-project-EEM',r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$end=[DateTime]::UtcNow.AddSeconds(45)
do{$a=@(Get-NetAdapter -IncludeHidden|Where-Object{$_.InterfaceDescription -like 'Windows KDNET USB-EEM Network Adapter*' -and $_.Status -eq 'Up'});if($a.Count -eq 1){break};Start-Sleep -Seconds 2}while([DateTime]::UtcNow -lt $end)
$network=$null;if($a.Count -eq 1){$network=& (Join-Path $env:USERPROFILE 'Downloads\Open-G17\payloads\G182-Restore-EEM.ps1')|ConvertFrom-Json}
$log='C:\Users\PUBLIC_USER\Downloads\OnePlusOpen-BootRepair-G80\debug\G182-20261026-045608\kd.txt'
$t=@(Get-Content -LiteralPath $log -Tail 30|Where-Object{$_ -match 'Windows Kernel Version|Kernel base|Connected to|Debuggee|G182_INITIAL_ATTACH|Bugcheck|Break instruction|fatal'})
@{connected_EEM=$a.Count;network=$network;kernel_text=($t -join "`n");utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Depth 5 -Compress
''',timeout=65);v=json.loads(r['output']);(P/'current-network.json').write_text(json.dumps(v,indent=2)+'\n');print(v)
