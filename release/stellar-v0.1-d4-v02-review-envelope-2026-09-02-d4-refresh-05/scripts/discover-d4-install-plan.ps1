[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateScript({[IO.Path]::IsPathFullyQualified($_)})][string]$PackageRoot,
  [Parameter(Mandatory=$true)][ValidateScript({[IO.Path]::IsPathFullyQualified($_)})][string]$ExternalAuthorityPem,
  [Parameter(Mandatory=$true)][ValidateScript({[IO.Path]::IsPathFullyQualified($_)})][string]$ExternalPinJson
)
$ErrorActionPreference='Stop'
$node=(Get-Command node.exe -ErrorAction Stop).Source
$emitter=Join-Path $PSScriptRoot 'emit-d4-install-plan.ts'
& $node --import tsx $emitter $PackageRoot $ExternalAuthorityPem $ExternalPinJson
if($LASTEXITCODE -ne 0){throw "T7D_DISCOVERY_FAILED_NATIVE_EXIT_$LASTEXITCODE"}
