# Read-only policy/image helpers. Dot sourcing defines functions only.
function Need($ok,[string]$why){if(!$ok){throw $why}}
function Hash([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function Prop([string]$id,[string]$key){(Get-PnpDeviceProperty -InstanceId $id -KeyName $key -ErrorAction Stop).Data}
function Read-Policy([string]$id){
 $resolved=[string](Prop $id 'DEVPKEY_Device_Driver');Need ($resolved -cmatch '^\{4d36e972-e325-11ce-bfc1-08002be10318\}\\[0-9]{4}$') 'Actual NET software key required'
 $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(('SYSTEM\CurrentControlSet\Control\Class\'+$resolved),$false);Need ($null -ne $key) 'Current software key missing'
 $match=$true
 try{$values=[ordered]@{};foreach($spec in @(@('IdlePowerSave','DWord',0),@('BandCapability','DWord',1),@('p2pDisable','DWord',1),@('StaWirelessMode','String','7'))){$name=$spec[0];if($key.GetValueNames() -ccontains $name){$kind=[string]$key.GetValueKind($name);$value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}else{$kind='Absent';$value=$null};$values[$name]=[pscustomobject]@{kind=$kind;value=$value};if($kind -cne $spec[1] -or $value -cne $spec[2]){$match=$false}}}finally{$key.Dispose()}
 $power=& powercfg.exe /query SCHEME_CURRENT SUB_PCIEXPRESS;$powerMatch=($LASTEXITCODE -eq 0 -and ([regex]::Matches(($power -join "`n"),'0x00000000')).Count -eq 2)
 [pscustomobject]@{resolved_driver_software_key=$resolved;values=$values;powercfg_ASPM_AC_DC_zero=$powerMatch;typed_policy_matches=$match;expected_policy_matches=($match -and $powerMatch);read_only=$true}
}
function Read-Binding([string]$id){
 $inf=[string](Prop $id 'DEVPKEY_Device_DriverInfPath');Need ($inf -match '^oem[0-9]+\.inf$') 'Actual published INF filename required'
 $v=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\qcwlan';$raw=[string]$v.ImagePath
 if($raw.StartsWith('\SystemRoot\',[StringComparison]::OrdinalIgnoreCase)){$image=Join-Path $env:SystemRoot $raw.Substring(12)}elseif($raw.StartsWith('C:\',[StringComparison]::OrdinalIgnoreCase)){$image=$raw}else{throw 'Unqualified actual image namespace'}
 [pscustomobject]@{Inf=$inf;InfSHA256=(Hash (Join-Path $env:SystemRoot ('INF\'+$inf)));version=[string](Prop $id 'DEVPKEY_Device_DriverVersion');image=[IO.Path]::GetFullPath($image);image_sha256=(Hash $image);image_scope='selected on-disk service image; loaded-byte identity not independently read';serviceStart=[int]$v.Start;serviceState=[string](Get-Service qcwlan).Status}
}
function Assert-FreshNormal($j){
 $boot=[BitConverter]::ToUInt32([BitConverter]::GetBytes([Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]0x7ffe02c4)),0)
 Need ($boot -gt 167 -and $boot -eq $j.BootId -and $env:SystemRoot -ieq 'C:\Windows' -and $env:PROCESSOR_ARCHITECTURE -ieq 'ARM64' -and [Environment]::Is64BitProcess -and !(Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\MiniNT')) 'Actual new normal ARM64 epoch required'
 Need ($j.phone_session -cmatch '^[0-9a-f]{32}$' -and $j.root_nonce -cmatch '^[0-9a-f]{32}$') 'Fresh root-observed session/nonce required'
 $dev=@(Get-PnpDevice -PresentOnly|Where-Object {$_.InstanceId -like 'PCI\VEN_17CB&DEV_1107*'});Need ($dev.Count -eq 1 -and $dev[0].InstanceId -ceq $j.instance_id) 'One exact actual present WLAN instance required'
}
