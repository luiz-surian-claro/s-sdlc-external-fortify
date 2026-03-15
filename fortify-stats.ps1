#Requires -Version 5.1
<#
.SYNOPSIS
    Exibe estatísticas de todas as Applications do user group FOD_APP_GROUP
    no Fortify on Demand.

.DESCRIPTION
    Consulta o FoD e exibe, para cada Application do grupo:
      - Número de releases
      - Contagem de scans agrupados por status:
        Queued, In Progress, Completed, Failed, Cancelled
    Além de um resumo global ao final.

.EXAMPLE
    .\fortify-stats-applications.ps1
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
Initialize-LogFile -LogsDir $LogsDir -ScriptName 'fortify-stats-applications'

# ============================================================================
# CARREGAR .env
# ============================================================================

Import-FodEnv -EnvFile $EnvFile `
    -RequiredVars @('FOD_URL', 'FOD_CLIENT_ID', 'FOD_CLIENT_SECRET', 'FOD_APP_GROUP', 'FCLI_VERSION')

# ============================================================================
# INSTALAR / LOCALIZAR fcli
# ============================================================================

$Fcli = Get-FcliPath -ToolsDir $ToolsDir -FcliVersion $FCLI_VERSION

# ============================================================================
# LOGIN NO FORTIFY ON DEMAND
# ============================================================================

Connect-FodSession -Fcli $Fcli -FodUrl $FOD_URL -ClientId $FOD_CLIENT_ID -ClientSecret $FOD_CLIENT_SECRET

# Obter token OAuth para chamadas REST diretas à API FoD
$fodApiBase     = $FOD_URL -replace '://', '://api.'
$tokenBody      = "grant_type=client_credentials&scope=api-tenant&client_id=$FOD_CLIENT_ID&client_secret=$FOD_CLIENT_SECRET"
$FodBearerToken = (Invoke-RestMethod -Uri "$fodApiBase/oauth/token" `
    -Method POST -Body $tokenBody `
    -ContentType 'application/x-www-form-urlencoded' `
    -UseBasicParsing).access_token
$FodAuthHeader = @{ Authorization = "Bearer $FodBearerToken" }

# ============================================================================
# RESOLVER ID DO USER GROUP
# ============================================================================

Write-LogStep "Consultando user group: $FOD_APP_GROUP"

$groupsResp = Invoke-RestMethod -Uri "$fodApiBase/api/v3/user-management/user-groups?limit=50" `
    -Headers $FodAuthHeader -UseBasicParsing
$FodGroup = $groupsResp.items | Where-Object { $_.name -eq $FOD_APP_GROUP } | Select-Object -First 1

if (-not $FodGroup) {
    Write-LogError "User group '$FOD_APP_GROUP' nao encontrado no FoD. Verifique FOD_APP_GROUP no .env"
    Disconnect-FodSession -Fcli $Fcli
    exit 1
}

$FodGroupId = $FodGroup.id
Write-LogInfo "User group '$FOD_APP_GROUP' encontrado: ID=$FodGroupId"

# ============================================================================
# LISTAR TODAS AS APPLICATIONS DO GRUPO (com paginação)
# ============================================================================

Write-LogStep "Listando applications do grupo '$FOD_APP_GROUP'"

$allApps = [System.Collections.Generic.List[object]]::new()
$offset  = 0
$limit   = 50

do {
    $resp = Invoke-RestMethod `
        -Uri "$fodApiBase/api/v3/user-group-application-access/${FodGroupId}?limit=$limit&offset=$offset" `
        -Headers $FodAuthHeader `
        -UseBasicParsing
    if ($resp.items) {
        foreach ($item in $resp.items) { $allApps.Add($item) }
    }
    $offset += $limit
} while ($resp.items -and $resp.items.Count -eq $limit)

if ($allApps.Count -eq 0) {
    Write-LogWarn "Nenhuma application encontrada no grupo '$FOD_APP_GROUP'"
    Disconnect-FodSession -Fcli $Fcli
    exit 0
}

Write-LogInfo "Applications encontradas: $($allApps.Count)"

# ============================================================================
# COLETAR DADOS DE RELEASES E SCANS POR APPLICATION
# ============================================================================

Write-LogStep "Coletando dados de releases e scans"

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

$globalCounts = @{
    'Queued'      = 0
    'In Progress' = 0
    'Completed'   = 0
    'Failed'      = 0
    'Cancelled'   = 0
    'Other'       = 0
}
$globalReleases = 0
$globalScans    = 0

# Per-app rows for the detail table
$appRows = [System.Collections.Generic.List[object]]::new()

$appIndex = 0
foreach ($app in $allApps) {
    $appName = $app.applicationName
    $appIndex++

    $pct = [int]($appIndex / $allApps.Count * 100)
    Write-Progress -Activity "Coletando dados de '$FOD_APP_GROUP'" `
        -Status "($appIndex/$($allApps.Count)) $appName" `
        -PercentComplete $pct

    # Releases para esta application
    $releases = & $Fcli fod release list --app $appName -o json 2>&1 | Out-String | ConvertFrom-Json
    $releaseCount = if ($releases) { @($releases).Count } else { 0 }
    $globalReleases += $releaseCount

    $appScanCounts = @{
        'Queued'      = 0
        'In Progress' = 0
        'Completed'   = 0
        'Failed'      = 0
        'Cancelled'   = 0
        'Other'       = 0
    }

    foreach ($release in @($releases)) {
        $releaseId = $release.releaseId
        if (-not $releaseId) { continue }

        $scans = & $Fcli fod rest call "/api/v3/releases/$releaseId/scans" --no-paging -o json 2>&1 |
            Out-String | ConvertFrom-Json

        foreach ($scan in @($scans)) {
            if (-not $scan -or -not $scan.analysisStatusType) { continue }
            $rawStatus    = $scan.analysisStatusType
            $normalStatus = if ($statusMap.ContainsKey($rawStatus)) { $statusMap[$rawStatus] } else { 'Other' }
            $appScanCounts[$normalStatus]++
            $globalCounts[$normalStatus]++
            $globalScans++
        }
    }

    $appRows.Add([PSCustomObject]@{
        Application  = $appName
        Releases     = $releaseCount
        Queued       = $appScanCounts['Queued']
        InProgress   = $appScanCounts['In Progress']
        Completed    = $appScanCounts['Completed']
        Failed       = $appScanCounts['Failed']
        Cancelled    = $appScanCounts['Cancelled']
        Other        = $appScanCounts['Other']
    })
}

Write-Progress -Activity "Coletando dados de '$FOD_APP_GROUP'" -Completed

# ============================================================================
# EXIBIR TABELA POR APPLICATION
# ============================================================================

Write-LogStep "Estatisticas por Application — Grupo: $FOD_APP_GROUP"

$header = "{0,-60} {1,8} {2,8} {3,11} {4,10} {5,7} {6,10} {7,6}" -f `
    'Application', 'Releases', 'Queued', 'In Progress', 'Completed', 'Failed', 'Cancelled', 'Other'
$divider = '-' * ($header.Length)

Write-Host ""
Write-Host $header
Write-Host $divider
Write-LogLine ""
Write-LogLine $header
Write-LogLine $divider

foreach ($row in ($appRows | Sort-Object Application)) {
    $line = "{0,-60} {1,8} {2,8} {3,11} {4,10} {5,7} {6,10} {7,6}" -f `
        $row.Application, $row.Releases, $row.Queued, $row.InProgress,
        $row.Completed, $row.Failed, $row.Cancelled, $row.Other
    Write-Host $line
    Write-LogLine $line
}

# ============================================================================
# EXIBIR RESUMO GLOBAL
# ============================================================================

Write-LogStep "Resumo Global — Grupo: $FOD_APP_GROUP"

$pad = 24
$summaryLines = @(
    ""
    ("  {0,-$pad} {1}" -f "Grupo:",             $FOD_APP_GROUP)
    ("  {0,-$pad} {1}" -f "Applications:",       $allApps.Count)
    ("  {0,-$pad} {1}" -f "Total de releases:",  $globalReleases)
    ("  {0,-$pad} {1}" -f "Total de scans:",     $globalScans)
    ""
    "  Scans por status:"
    ("    {0,-$pad} {1}" -f "Queued:",            $globalCounts['Queued'])
    ("    {0,-$pad} {1}" -f "In Progress:",       $globalCounts['In Progress'])
    ("    {0,-$pad} {1}" -f "Completed:",         $globalCounts['Completed'])
    ("    {0,-$pad} {1}" -f "Failed:",            $globalCounts['Failed'])
    ("    {0,-$pad} {1}" -f "Cancelled:",         $globalCounts['Cancelled'])
)
if ($globalCounts['Other'] -gt 0) {
    $summaryLines += ("    {0,-$pad} {1}" -f "Other:", $globalCounts['Other'])
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
