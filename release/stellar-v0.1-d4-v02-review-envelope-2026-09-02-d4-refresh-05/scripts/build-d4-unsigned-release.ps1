[CmdletBinding()]
param([Parameter(Mandatory=$false)][string]$OutputRoot=(Join-Path $PSScriptRoot '..\..\release\stellar-v0.1-d4-reviewed-unsigned'))
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..\..')).Path
$output=[IO.Path]::GetFullPath($OutputRoot)
if(-not $output.StartsWith($repo,[StringComparison]::OrdinalIgnoreCase)){throw 'D4_OUTPUT_MUST_REMAIN_IN_REPOSITORY'}
if(Test-Path -LiteralPath $output){throw 'D4_IMMUTABLE_RELEASE_ALREADY_EXISTS'}

$entries=[Collections.Generic.List[object]]::new()
function Add-ReleaseFile([string]$source,[string]$relative,[string]$kind){
  $resolved=(Resolve-Path -LiteralPath $source).Path
  $sourceItem=Get-Item -LiteralPath $resolved -Force
  if($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "D4_SOURCE_REPARSE_REFUSED: $resolved"}
  if($sourceItem.LinkType){throw "D4_SOURCE_LINK_REFUSED: $resolved"}
  $destination=Join-Path $output $relative
  New-Item -ItemType Directory -Path (Split-Path $destination) -Force|Out-Null
  Copy-Item -LiteralPath $resolved -Destination $destination
  $copied=Get-Item -LiteralPath $destination -Force
  $entries.Add([ordered]@{path=$relative.Replace('\','/');kind=$kind;bytes=$copied.Length;sha256=('sha256:'+(Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLower());imports=@();signers=@()})
}

New-Item -ItemType Directory -Path $output|Out-Null
$v='native\stellar\v0_1'
Add-ReleaseFile (Join-Path $repo "$v\evidence\d3-v02-build\linked-services\AegisStellarCustodian.exe") 'bin/AegisStellarCustodian.exe' 'service'
Add-ReleaseFile (Join-Path $repo "$v\evidence\d3-v02-build\linked-services\AegisStellarExecutionBroker.exe") 'bin/AegisStellarExecutionBroker.exe' 'broker'
Add-ReleaseFile (Join-Path $repo 'native\stellar\.out\phase-a-final\run-1\stellar-native-runner.exe') 'bin/stellar-native-runner.exe' 'runner'
Add-ReleaseFile (Join-Path $repo 'native\stellar\.out\phase-a-final\host\stellar-native-compiler.exe') 'bin/stellar-native-compiler.exe' 'compiler'
Add-ReleaseFile (Join-Path $repo "$v\stdlib\stellar.stdlib.json") 'stdlib/stellar.stdlib.json' 'stdlib'
Get-ChildItem (Join-Path $repo "$v\schemas") -File|Sort-Object Name|ForEach-Object{Add-ReleaseFile $_.FullName "schemas/$($_.Name)" 'schema'}
Get-ChildItem (Join-Path $repo "$v\service") -Filter '*.canonical.json' -File|Sort-Object Name|ForEach-Object{Add-ReleaseFile $_.FullName "policy/$($_.Name)" 'canonical-policy'}
Add-ReleaseFile (Join-Path $repo "$v\service\t7d-d2-service-runtime.canonical.json") 'config/service-runtime.canonical.json' 'config'
Add-ReleaseFile (Join-Path $repo "$v\service\service-contract-adapter.ts") 'adapter/service-contract-adapter.ts' 'adapter'
Get-ChildItem (Join-Path $repo "$v\service\tools") -Filter '*.ps1' -File|Sort-Object Name|ForEach-Object{Add-ReleaseFile $_.FullName "scripts/$($_.Name)" 'script'}
Get-ChildItem (Join-Path $repo 'docs') -Filter 'STELLAR_WINDOWS_X64_V0_1_*.md' -File|Sort-Object Name|ForEach-Object{Add-ReleaseFile $_.FullName "docs/$($_.Name)" 'documentation'}
$imports=[ordered]@{schema='stellar.t7d-static-imports/v0.1';status='UNSIGNED_REVIEW_INPUT';binaries=@('AegisStellarCustodian.exe','AegisStellarExecutionBroker.exe','stellar-native-runner.exe','stellar-native-compiler.exe');inspection='required before signing'}
$importsPath=Join-Path $output 'evidence/static-imports.json';New-Item -ItemType Directory -Path (Split-Path $importsPath) -Force|Out-Null;$imports|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $importsPath -Encoding utf8NoBOM
$entries.Add([ordered]@{path='evidence/static-imports.json';kind='static-imports';bytes=(Get-Item $importsPath).Length;sha256=('sha256:'+(Get-FileHash -Algorithm SHA256 $importsPath).Hash.ToLower());imports=@();signers=@()})
$manifest=[ordered]@{schema='stellar.t7d-reviewed-unsigned-release/v0.1';releaseId='stellar-v0.1-d4';status='REVIEWED_UNSIGNED_INPUT_NOT_INSTALLABLE';signingPolicies=@('LAB_SELF_SIGNED','EXTERNAL_SIGNER');certificateMinted=$false;trustModified=$false;files=@($entries|Sort-Object path)}
$manifestPath=Join-Path $output 'UNSIGNED-RELEASE-MANIFEST.json';$manifest|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
$manifestHash='sha256:'+(Get-FileHash -Algorithm SHA256 $manifestPath).Hash.ToLower()
[ordered]@{schema='stellar.t7d-immutable-release-marker/v0.1';manifestHash=$manifestHash;reviewRequired=$true;installable=$false;reason='No release signature or trusted signer evidence. No certificate was minted or trusted.'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $output 'IMMUTABILITY.json') -Encoding utf8NoBOM
Get-ChildItem $output -Recurse -File|ForEach-Object{$_.IsReadOnly=$true}
[ordered]@{output=$output;manifestHash=$manifestHash;files=$entries.Count;mutationsOutsideOutput=0}|ConvertTo-Json -Compress
