# Source qualification only. No device opens/queries.
param([switch]$CompileReviewedSource,[string]$SourcePinsSha256)
$ErrorActionPreference='Stop'
if(!$CompileReviewedSource){'INERT: no compilation/device calls';return}
$p=Join-Path $PSScriptRoot 'SOURCE-PINS.json';if((Get-FileHash $p).Hash.ToLowerInvariant() -cne $SourcePinsSha256){throw 'Exact pins required'};$m=Get-Content $p -Raw|ConvertFrom-Json
foreach($f in $m.files.PSObject.Properties){if((Get-FileHash (Join-Path $PSScriptRoot $f.Name)).Hash.ToLowerInvariant() -cne $f.Value){throw 'Source changed'}}
foreach($n in @('Query-Once.ps1','Native-Compile-Only.ps1')){$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $n),[ref]$t,[ref]$e);if($e.Count){throw ('AST failed '+$n)}}
if([string](& (Join-Path $PSScriptRoot 'Query-Once.ps1')) -notlike 'INERT:*'){throw 'Default not inert'}
Add-Type -TypeDefinition (Get-Content (Join-Path $PSScriptRoot 'CeGetter.cs') -Raw)
$r=[G1342CeGetter]::CodecOnly()
[ordered]@{codec_pass=$r.codec_pass;native_CS_compiled=1;PS_AST=2;default_inert=$true;source_sha256=$m.files;device_calls=0;runtime_approval=$false}|ConvertTo-Json -Depth 5 -Compress
