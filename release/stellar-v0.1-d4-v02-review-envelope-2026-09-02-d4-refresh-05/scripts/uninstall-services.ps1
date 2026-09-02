[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([switch]$RemoveData)
$ErrorActionPreference='Stop'
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'T7C_ADMINISTRATOR_REQUIRED'}
Remove-NetFirewallRule -DisplayName 'AEGIS Stellar Custodian outbound deny','AEGIS Stellar Execution Broker outbound deny' -ErrorAction SilentlyContinue
foreach($service in @('AegisStellarExecutionBroker','AegisStellarCustodian')){if(Get-Service -Name $service -ErrorAction SilentlyContinue){if($PSCmdlet.ShouldProcess($service,'Stop and delete service')){Stop-Service -Name $service -Force -ErrorAction SilentlyContinue;sc.exe delete $service|Out-Null}}}
if($RemoveData -and $PSCmdlet.ShouldProcess('C:\ProgramData\AEGIS\Stellar\v0.1','Remove service data after service deletion')){Remove-Item -LiteralPath 'C:\ProgramData\AEGIS\Stellar\v0.1' -Recurse -Force}
