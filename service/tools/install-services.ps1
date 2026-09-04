[CmdletBinding()]
param([switch]$Apply,[string]$ReviewedPlanPath,[string]$JournalPath)
$ErrorActionPreference='Stop'
if($Apply -and (-not $ReviewedPlanPath -or -not $JournalPath)){throw 'T7D_REVIEWED_PLAN_AND_JOURNAL_REQUIRED'}
throw 'T7D_D4_APPLY_CLOSED_REVIEW_ONLY_USE_SEPARATE_DISCOVERY_TOOL'
