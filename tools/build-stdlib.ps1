param(
  [Parameter(Mandatory = $true)][string]$StdlibRoot,
  [Parameter(Mandatory = $true)][string]$OutputDirectory,
  [string]$VerifyLock
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Utf8NoBom([string]$PathValue, [string]$Content) {
  [System.IO.File]::WriteAllText($PathValue, $Content, [System.Text.UTF8Encoding]::new($false))
}
function Get-FileHashValue([string]$PathValue) {
  $algorithm = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.IO.File]::ReadAllBytes($PathValue)
    return 'sha256:' + ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()
  }
  finally { $algorithm.Dispose() }
}
function Get-TextHashValue([string]$TextValue) {
  $algorithm = [System.Security.Cryptography.SHA256]::Create()
  try { $bytes = [Text.Encoding]::UTF8.GetBytes($TextValue); return 'sha256:' + ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
  finally { $algorithm.Dispose() }
}
function Invoke-Checked([string]$Executable, [string[]]$Arguments, [string]$Label) {
  $captured = & $Executable @Arguments 2>&1
  if ($LASTEXITCODE -ne 0) { throw "$Label failed with exit code $LASTEXITCODE.`n$($captured -join [Environment]::NewLine)" }
  return @($captured)
}
function Resolve-ContainedFile([string]$Root, [string]$Relative, [string]$Label) {
  if ([IO.Path]::IsPathRooted($Relative) -or $Relative -split '[\\/]' -contains '..') { throw "$Label path escapes the standard-library root." }
  $candidate = (Resolve-Path -LiteralPath (Join-Path $Root $Relative)).Path
  $prefix = $Root.TrimEnd('\') + '\'
  if (-not $candidate.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not [IO.File]::Exists($candidate)) { throw "$Label path is not a contained regular file." }
  return $candidate
}
function Get-MangledSymbol([string]$Module, [string]$Name, [object[]]$Parameters, [string]$Result) {
  $moduleHex = ([BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($Module))).Replace('-','').ToLowerInvariant()
  $nameHex = ([BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($Name))).Replace('-','').ToLowerInvariant()
  $signature = $Name + '(' + (($Parameters | ForEach-Object { [string]$_ }) -join ',') + ')->Result(' + $Result + ')'
  $suffix = (Get-TextHashValue $signature).Substring(7,16)
  return "stellar_v01_m${moduleHex}_s${nameHex}_h${suffix}"
}
function Assert-ExactProperties([object]$Value, [string[]]$Expected, [string]$Label) {
  $actual = @($Value.PSObject.Properties.Name | Sort-Object)
  $wanted = @($Expected | Sort-Object)
  if (($actual -join '|') -ne ($wanted -join '|')) { throw "$Label has missing, duplicate, or unknown fields." }
}
function Normalize-Evidence([string[]]$Lines) {
  $text = ($Lines -join "`n").Replace("`r", '')
  $text = [regex]::Replace($text, '(?im)^Dump of file .+$', 'Dump of object')
  return $text.Trim() + "`n"
}

$stdlibPath = (Resolve-Path -LiteralPath $StdlibRoot).Path
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
[IO.Directory]::CreateDirectory($outputPath) | Out-Null
$manifestPath = Resolve-ContainedFile $stdlibPath 'stellar.stdlib.json' 'manifest'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-ExactProperties $manifest @('schema','name','version','target','profile','abi','pureRelics','capabilityDescriptors') 'standard-library manifest'
if ($manifest.schema -ne 'stellar.stdlib/v0.1' -or $manifest.version -notmatch '^0\.1\.[0-9]+$' -or $manifest.target -ne 'windows-x86_64-msvc' -or $manifest.profile -ne 'stellar-lab-v0' -or $manifest.abi -ne 'stellar-win64-v0.1') { throw 'Standard-library manifest compatibility mismatch.' }
if (@($manifest.pureRelics).Count -ne 3) { throw 'Exactly three pure core RELICs are required in Tranche 3.' }

$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$installation = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $installation) { throw 'MSVC x64 tools are required.' }
$dev = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
$lines = & $env:ComSpec /d /s /c ('call "' + $dev + '" -arch=x64 -host_arch=x64 >nul && set')
if ($LASTEXITCODE -ne 0) { throw 'MSVC environment initialization failed.' }
foreach ($line in $lines) { $at = $line.IndexOf('='); if ($at -gt 0) { [Environment]::SetEnvironmentVariable($line.Substring(0,$at),$line.Substring($at+1),'Process') } }
$ml64 = (Get-Command ml64.exe -ErrorAction Stop).Source
$dumpbin = (Get-Command dumpbin.exe -ErrorAction Stop).Source
$assemblerVersion = (Get-Item -LiteralPath $ml64).VersionInfo.FileVersion
$dumpbinVersion = (Get-Item -LiteralPath $dumpbin).VersionInfo.FileVersion
$toolchainCanonical = "{`"assembler`":`"ml64.exe`",`"assemblerVersion`":`"$assemblerVersion`",`"dumpbin`":`"dumpbin.exe`",`"dumpbinVersion`":`"$dumpbinVersion`",`"target`":`"windows-x86_64-msvc`"}"
$toolchainHash = Get-TextHashValue $toolchainCanonical

$relicReports = [ordered]@{}
$lockRelics = [ordered]@{}
$assembledSources = [Collections.Generic.List[string]]::new()
$allSymbols = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($entry in $manifest.pureRelics) {
  Assert-ExactProperties $entry @('name','version','interface','source') "RELIC $($entry.name) manifest entry"
  if ($entry.version -notmatch '^0\.1\.[0-9]+$') { throw "RELIC $($entry.name) version is incompatible." }
  $interfacePath = Resolve-ContainedFile $stdlibPath ([string]$entry.interface) "RELIC $($entry.name) interface"
  $sourcePath = Resolve-ContainedFile $stdlibPath ([string]$entry.source) "RELIC $($entry.name) source"
  $interface = Get-Content -LiteralPath $interfacePath -Raw | ConvertFrom-Json
  Assert-ExactProperties $interface @('schema','name','version','target','profile','abi','exports','effects','imports') "RELIC $($entry.name) interface"
  if ($interface.schema -ne 'stellar.relic-interface/v0.1' -or $interface.name -ne $entry.name -or $interface.version -ne $entry.version -or $interface.target -ne $manifest.target -or $interface.profile -ne $manifest.profile -or $interface.abi -ne $manifest.abi) { throw "RELIC $($entry.name) interface identity mismatch." }
  if (@($interface.effects).Count -ne 0 -or @($interface.imports).Count -ne 0) { throw "RELIC $($entry.name) must remain zero-effect and zero-import." }
  $expectedSymbols = [Collections.Generic.List[string]]::new()
  $exportNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($export in $interface.exports) {
    Assert-ExactProperties $export @('name','parameters','result') "RELIC $($entry.name) export"
    if (-not $exportNames.Add([string]$export.name)) { throw "RELIC $($entry.name) has a duplicate export symbol." }
    $symbol = Get-MangledSymbol ([string]$entry.name) ([string]$export.name) @($export.parameters) ([string]$export.result)
    if (-not $allSymbols.Add($symbol)) { throw "Standard-library symbol collision: $symbol" }
    $expectedSymbols.Add($symbol)
  }
  $first = Join-Path $outputPath ("run-1\" + $entry.name)
  $second = Join-Path $outputPath ("run-2\" + $entry.name)
  [IO.Directory]::CreateDirectory($first) | Out-Null; [IO.Directory]::CreateDirectory($second) | Out-Null
  $firstObject = Join-Path $first ($entry.name + '.obj'); $secondObject = Join-Path $second ($entry.name + '.obj')
  Invoke-Checked $ml64 @('/nologo','/c',("/Fo" + $firstObject),$sourcePath) "assemble $($entry.name) run 1" | Out-Null
  Invoke-Checked $ml64 @('/nologo','/c',("/Fo" + $secondObject),$sourcePath) "assemble $($entry.name) run 2" | Out-Null
  $symbols1 = Normalize-Evidence (Invoke-Checked $dumpbin @('/nologo','/symbols',$firstObject) "symbols $($entry.name) run 1")
  $symbols2 = Normalize-Evidence (Invoke-Checked $dumpbin @('/nologo','/symbols',$secondObject) "symbols $($entry.name) run 2")
  $disassembly1 = Normalize-Evidence (Invoke-Checked $dumpbin @('/nologo','/disasm',$firstObject) "disassembly $($entry.name) run 1")
  $disassembly2 = Normalize-Evidence (Invoke-Checked $dumpbin @('/nologo','/disasm',$secondObject) "disassembly $($entry.name) run 2")
  $undefined = @([regex]::Matches($symbols1, '(?im)^.*UNDEF.*External.*\|\s*(\S+)\s*$') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
  $defined = @([regex]::Matches($symbols1, '(?im)^.*SECT[0-9A-F]+.*External.*\|\s*(\S+)\s*$') | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notmatch '^@feat\.' } | Sort-Object -Unique)
  $expected = @($expectedSymbols | Sort-Object)
  if ($undefined.Count -ne 0) { throw "RELIC $($entry.name) has undefined external symbols: $($undefined -join ', ')" }
  if (($defined -join '|') -ne ($expected -join '|')) { throw "RELIC $($entry.name) object/interface symbol mismatch. Defined: $($defined -join ', ')" }
  $objectHash1 = Get-FileHashValue $firstObject; $objectHash2 = Get-FileHashValue $secondObject
  $normalizedIdentical = $symbols1 -eq $symbols2 -and $disassembly1 -eq $disassembly2
  if (-not $normalizedIdentical) { throw "RELIC $($entry.name) normalized object evidence is nondeterministic." }
  $evidenceCanonical = "{`"abi`":`"$($manifest.abi)`",`"disassemblyHash`":`"$(Get-TextHashValue $disassembly1)`",`"interfaceHash`":`"$(Get-FileHashValue $interfacePath)`",`"sourceHash`":`"$(Get-FileHashValue $sourcePath)`",`"symbolsHash`":`"$(Get-TextHashValue $symbols1)`",`"target`":`"$($manifest.target)`"}"
  $relicReport = [ordered]@{
    version = [string]$entry.version; target = [string]$manifest.target; profile = [string]$manifest.profile; abi = [string]$manifest.abi
    sourceHash = Get-FileHashValue $sourcePath; interfaceHash = Get-FileHashValue $interfacePath; objectHash = $objectHash1
    symbolsHash = Get-TextHashValue $symbols1; disassemblyHash = Get-TextHashValue $disassembly1; evidenceHash = Get-TextHashValue $evidenceCanonical
    definedSymbols = $defined; undefinedExternalSymbols = $undefined; effects = @(); disassembly = $disassembly1
    objectEmitted = $true; executableLinked = $false
    reproducibility = [ordered]@{ objectByteIdentical = $objectHash1 -eq $objectHash2; normalizedEvidenceIdentical = $true; note = if ($objectHash1 -eq $objectHash2) { 'Raw COFF objects are byte-identical for two outputs under this pinned toolchain.' } else { 'Raw COFF object bytes differ by object path/toolchain metadata; normalized symbols and disassembly are byte-identical.' } }
  }
  $relicReports[[string]$entry.name] = $relicReport
  $lockRelics[[string]$entry.name] = [ordered]@{ sourceHash=$relicReport.sourceHash; interfaceHash=$relicReport.interfaceHash; objectEvidenceHash=$relicReport.evidenceHash; symbolsHash=$relicReport.symbolsHash; disassemblyHash=$relicReport.disassemblyHash; reproducibleObjectHash=if($relicReport.reproducibility.objectByteIdentical){$relicReport.objectHash}else{$null} }
  $assembledSources.Add([string]$entry.source)
}

if (@($manifest.capabilityDescriptors).Count -ne 1) { throw 'Exactly one separate ConsoleWrite capability descriptor is expected.' }
$consoleEntry = $manifest.capabilityDescriptors[0]
Assert-ExactProperties $consoleEntry @('name','descriptor','source','compiled','authorized') 'ConsoleWrite manifest entry'
if ($consoleEntry.name -ne 'windows.console' -or $consoleEntry.compiled -ne $false -or $consoleEntry.authorized -ne $false) { throw 'ConsoleWrite manifest entry must remain unauthorized and uncompiled.' }
$consolePath = Resolve-ContainedFile $stdlibPath ([string]$consoleEntry.descriptor) 'ConsoleWrite descriptor'
$consoleSourcePath = Resolve-ContainedFile $stdlibPath ([string]$consoleEntry.source) 'ConsoleWrite source'
$console = Get-Content -LiteralPath $consolePath -Raw | ConvertFrom-Json
Assert-ExactProperties $console @('schema','name','version','target','profile','abi','capability','exports','allowedImports','relationContractRequired','custodianStewardAuthenticationRequired','osProcessIsolationRequired','authorized','compiled','executionEnabled') 'ConsoleWrite capability descriptor'
if ($console.schema -ne 'stellar.capability-relic/v0.1' -or $console.name -ne 'windows.console' -or $console.version -notmatch '^0\.1\.[0-9]+$' -or $console.target -ne $manifest.target -or $console.profile -ne $manifest.profile -or $console.abi -ne $manifest.abi -or $console.capability -ne 'windows.console.write' -or $console.relationContractRequired -ne $true -or $console.custodianStewardAuthenticationRequired -ne $true -or $console.osProcessIsolationRequired -ne $true -or $console.authorized -ne $false -or $console.compiled -ne $false -or $console.executionEnabled -ne $false) { throw 'ConsoleWrite capability descriptor identity, authorization, or isolation mismatch.' }
if (@($console.exports).Count -ne 1) { throw 'ConsoleWrite must expose exactly one capability-gated symbol.' }
Assert-ExactProperties $console.exports[0] @('name','parameters','result') 'ConsoleWrite export'
if ($console.exports[0].name -ne 'console_write' -or (@($console.exports[0].parameters) -join '|') -ne 'slice(u32,65536)' -or $console.exports[0].result -ne 'i64') { throw 'ConsoleWrite export ABI mismatch.' }
if (@($console.allowedImports).Count -ne 1) { throw 'ConsoleWrite import allowlist mismatch.' }
Assert-ExactProperties $console.allowedImports[0] @('dll','symbols') 'ConsoleWrite import allowlist'
if ($console.allowedImports[0].dll -ne 'KERNEL32.dll' -or (@($console.allowedImports[0].symbols) -join '|') -ne 'WriteFile') { throw 'ConsoleWrite import allowlist mismatch.' }
$consoleReport = [ordered]@{ name='windows.console'; capability='windows.console.write'; allowedImports=@([ordered]@{dll='KERNEL32.dll';symbols=@('WriteFile')}); relationContractRequired=$true; custodianStewardAuthenticationRequired=$true; osProcessIsolationRequired=$true; authorized=$false; compiled=$false; executionEnabled=$false }

$lockCore = [ordered]@{ schema='stellar.stdlib-lock/v0.1'; manifestHash=Get-FileHashValue $manifestPath; target=[string]$manifest.target; profile=[string]$manifest.profile; abi=[string]$manifest.abi; toolchainHash=$toolchainHash; relics=$lockRelics; consoleDescriptorHash=Get-FileHashValue $consolePath; consoleSourceHash=Get-FileHashValue $consoleSourcePath }
$lockCoreJson = $lockCore | ConvertTo-Json -Depth 20 -Compress
$lock = [ordered]@{ schema='stellar.stdlib-lock/v0.1'; integrity=Get-TextHashValue $lockCoreJson; manifestHash=$lockCore.manifestHash; target=$lockCore.target; profile=$lockCore.profile; abi=$lockCore.abi; toolchainHash=$lockCore.toolchainHash; relics=$lockCore.relics; consoleDescriptorHash=$lockCore.consoleDescriptorHash; consoleSourceHash=$lockCore.consoleSourceHash }
$lockJson = $lock | ConvertTo-Json -Depth 20 -Compress
if ($VerifyLock) {
  $expectedLock = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $VerifyLock).Path).Trim()
  if ($expectedLock -ne $lockJson) { throw 'Standard-library lock integrity/tamper verification failed.' }
}
Write-Utf8NoBom (Join-Path $outputPath 'stellar.stdlib.lock.json') ($lockJson + "`n")
$report = [ordered]@{
  schema='stellar.stdlib-verification/v0.1'; target=[string]$manifest.target; profile=[string]$manifest.profile; abi=[string]$manifest.abi
  manifestHash=Get-FileHashValue $manifestPath; toolchain=[ordered]@{assembler='ml64.exe';assemblerVersion=$assemblerVersion;dumpbin='dumpbin.exe';dumpbinVersion=$dumpbinVersion};toolchainHash=$toolchainHash
  relics=$relicReports; consoleWrite=$consoleReport; assembledSources=@($assembledSources); executionEnabled=$false; homeostasis='NOT_EVALUATED'; lockIntegrity=$lock.integrity
}
Write-Utf8NoBom (Join-Path $outputPath 'stdlib-verification.json') (($report | ConvertTo-Json -Depth 30 -Compress) + "`n")
