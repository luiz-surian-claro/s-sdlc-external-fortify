#Requires -Version 5.1
<#
.SYNOPSIS
    Exibe estatísticas da Application no Fortify on Demand.

.DESCRIPTION
    Consulta o FoD e exibe:
      - Número total de releases da Application
      - Contagem de scans (SAST e SCA) agrupados por status:
        Queued, In Progress, Completed, Failed, Cancelled

.EXAMPLE
    .\fortify-stats.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# VARIÁVEIS DE DIRETÓRIO
# ============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$EnvFile   = Join-Path $ScriptDir '.env'
$ToolsDir  = Join-Path $ScriptDir '.tools'
$LogsDir   = Join-Path $ScriptDir 'logs'

. (Join-Path $ScriptDir 'fortify-common.ps1')
Initialize-LogFile -LogsDir $LogsDir -ScriptName 'fortify-stats'

# ============================================================================
# CARREGAR .env
# ============================================================================

Import-FodEnv -EnvFile $EnvFile

# ============================================================================
# INSTALAR / LOCALIZAR fcli
# ============================================================================

$Fcli = Get-FcliPath -ToolsDir $ToolsDir -FcliVersion $FCLI_VERSION

# ============================================================================
# LOGIN NO FORTIFY ON DEMAND
# ============================================================================

Connect-FodSession -Fcli $Fcli -FodUrl $FOD_URL -ClientId $FOD_CLIENT_ID -ClientSecret $FOD_CLIENT_SECRET

# ============================================================================
# LISTAR RELEASES
# ============================================================================

Write-LogStep "Consultando Application: $FOD_APPLICATION_NAME"

$releases = & $Fcli fod release list --app $FOD_APPLICATION_NAME -o json |
    Out-String | ConvertFrom-Json

if (-not $releases -or $releases.Count -eq 0) {
    Write-LogWarn "Nenhuma release encontrada para Application $FOD_APPLICATION_NAME"
    Disconnect-FodSession -Fcli $Fcli
    exit 0
}

Write-LogInfo "Releases encontradas: $($releases.Count)"

# ============================================================================
# COLETAR SCANS DE CADA RELEASE
# ============================================================================

Write-LogStep "Coletando dados de scans"

# analysisStatusType values observed from the FoD API
$statusMap = @{
    'Queued'      = 'Queued'
    'In_Progress' = 'In Progress'
    'InProgress'  = 'In Progress'
    'Running'     = 'In Progress'
    'Completed'   = 'Completed'
    'Passed'      = 'Completed'
    'Failed'      = 'Failed'
    'Cancelled'   = 'Cancelled'
    'Canceled'    = 'Cancelled'
}

$scanCounts = @{
    'Queued'      = 0
    'In Progress' = 0
    'Completed'   = 0
    'Failed'      = 0
    'Cancelled'   = 0
    'Other'       = 0
}

# Counts by scan type (Static = SAST, Open Source/SCA, etc.)
$typeCounts = @{}

$totalScans = 0
$releaseIndex = 0

foreach ($release in $releases) {
    $releaseId   = $release.releaseId
    $releaseName = $release.releaseName
    $releaseIndex++

    $pct = [int]($releaseIndex / $releases.Count * 100)
    Write-Progress -Activity "Coletando scans de $FOD_APPLICATION_NAME" `
        -Status "($releaseIndex/$($releases.Count)) $releaseName" `
        -PercentComplete $pct

    $scans = & $Fcli fod rest call "/api/v3/releases/$releaseId/scans" --no-paging -o json |
        Out-String | ConvertFrom-Json

    if (-not $scans -or $scans.Count -eq 0) {
        continue
    }

    foreach ($scan in $scans) {
        # FoD uses 'analysisStatusType', not 'scanStatusType'
        $rawStatus    = $scan.analysisStatusType
        $normalStatus = if ($rawStatus -and $statusMap.ContainsKey($rawStatus)) { $statusMap[$rawStatus] } else { 'Other' }
        $scanCounts[$normalStatus]++

        $scanType = if ($scan.scanType) { $scan.scanType } else { 'Unknown' }
        if (-not $typeCounts.ContainsKey($scanType)) { $typeCounts[$scanType] = 0 }
        $typeCounts[$scanType]++

        $totalScans++
    }
}

Write-Progress -Activity "Coletando scans de $FOD_APPLICATION_NAME" -Completed

# ============================================================================
# EXIBIR RESUMO
# ============================================================================

Write-LogStep "Estatisticas: $FOD_APPLICATION_NAME"

$pad = 20

$summaryLines = @(
    ""
    ("  {0,-$pad} {1}" -f "Releases:", $releases.Count)
    ("  {0,-$pad} {1}" -f "Total de scans:", $totalScans)
    ""
    "  Scans por status:"
    ("    {0,-$pad} {1}" -f "Queued:",      $scanCounts['Queued'])
    ("    {0,-$pad} {1}" -f "In Progress:", $scanCounts['In Progress'])
    ("    {0,-$pad} {1}" -f "Completed:",   $scanCounts['Completed'])
    ("    {0,-$pad} {1}" -f "Failed:",      $scanCounts['Failed'])
    ("    {0,-$pad} {1}" -f "Cancelled:",   $scanCounts['Cancelled'])
)
if ($scanCounts['Other'] -gt 0) {
    $summaryLines += ("    {0,-$pad} {1}" -f "Other:", $scanCounts['Other'])
}

if ($typeCounts.Count -gt 0) {
    $summaryLines += ""
    $summaryLines += "  Scans por tipo:"
    foreach ($type in ($typeCounts.Keys | Sort-Object)) {
        $summaryLines += ("    {0,-$pad} {1}" -f "${type}:", $typeCounts[$type])
    }
}
$summaryLines += ""

foreach ($line in $summaryLines) {
    Write-Host $line
    Write-LogLine $line
}

Write-LogInfo "Execucao finalizada com sucesso"

# ============================================================================
# LOGOUT
# ============================================================================

Disconnect-FodSession -Fcli $Fcli
