#Requires -Version 5.1
<#
.SYNOPSIS
    Atribui todas as vulnerabilidades de todas as releases de uma Application
    FoD para um usuário específico.

.DESCRIPTION
    Para cada release da Application definida por FOD_APPLICATION_NAME, lista
    todas as vulnerabilidades visíveis e faz um bulk update via REST API para
    setar o "Assigned User" no FoD.

.PARAMETER AssignUser
    Username do FoD para atribuição. Padrão: luiz.surian

.EXAMPLE
    .\fortify-assign.ps1

.EXAMPLE
    .\fortify-assign.ps1 -AssignUser outro.usuario
#>

[CmdletBinding()]
param(
    [string]$AssignUser = 'luiz.surian'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Máximo de vulnIds por chamada REST (evita payloads muito grandes)
$BatchSize = 500

# ============================================================================
# VARIÁVEIS DE DIRETÓRIO
# ============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$EnvFile   = Join-Path $ScriptDir '.env'
$ToolsDir  = Join-Path $ScriptDir '.tools'

. (Join-Path $ScriptDir 'fortify-common.ps1')

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
# RESOLVER USERID NUMERICO
# ============================================================================

Write-LogInfo "Buscando userId para '$AssignUser'..."

$AssignUserId = (& $Fcli fod rest call "/api/v3/users?filters=userName:$AssignUser" --no-paging -o json |
    Out-String | ConvertFrom-Json | Select-Object -First 1).userId

if (-not $AssignUserId) {
    Write-LogError "Usuario '$AssignUser' nao encontrado no FoD"
    Disconnect-FodSession -Fcli $Fcli
    exit 1
}

Write-LogInfo "UserId resolvido: $AssignUserId"

# ============================================================================
# LISTAR RELEASES DA APPLICATION
# ============================================================================

Write-LogStep "Listando releases da Application $FOD_APPLICATION_NAME"

$releases = & $Fcli fod release list --app $FOD_APPLICATION_NAME -o json |
    Out-String | ConvertFrom-Json

if (-not $releases -or $releases.Count -eq 0) {
    Write-LogWarn "Nenhuma release encontrada para Application $FOD_APPLICATION_NAME"
    Disconnect-FodSession -Fcli $Fcli
    exit 0
}

Write-LogInfo "Releases encontradas: $($releases.Count)"

# ============================================================================
# CONTADORES GLOBAIS
# ============================================================================

$totalReleases         = 0
$totalReleasesComVulns = 0
$totalVulns            = 0
$totalAtribuidas       = 0

# ============================================================================
# PROCESSAR CADA RELEASE
# ============================================================================

foreach ($release in $releases) {
    $releaseId   = $release.releaseId
    $releaseName = $release.releaseName

    Write-LogStep "Release: $releaseName (ID: $releaseId)"

    $totalReleases++

    # -------------------------------------------------------------------------
    # Listar todas as vulnerabilidades visíveis da release
    # -------------------------------------------------------------------------

    Write-LogInfo "Buscando vulnerabilidades..."

    $vulns = (& $Fcli fod issue list --rel $releaseId -o json | Out-String) |
        ConvertFrom-Json

    if (-not $vulns -or $vulns.Count -eq 0) {
        Write-LogInfo "Nenhuma vulnerabilidade encontrada. Pulando..."
        continue
    }

    $vulnIds = $vulns | Select-Object -ExpandProperty id
    Write-LogInfo "Vulnerabilidades encontradas: $($vulnIds.Count)"

    # -------------------------------------------------------------------------
    # Bulk update em batches via REST API
    # -------------------------------------------------------------------------

    $updated = 0
    $batches  = [System.Collections.Generic.List[object]]::new()

    for ($i = 0; $i -lt $vulnIds.Count; $i += $BatchSize) {
        $end   = [Math]::Min($i + $BatchSize - 1, $vulnIds.Count - 1)
        $batches.Add($vulnIds[$i..$end])
    }

    Write-LogInfo "Atribuindo a '$AssignUser' em $($batches.Count) lote(s) de ate $BatchSize..."

    foreach ($batch in $batches) {
        $bodyObj = [ordered]@{
            userId            = $AssignUserId
            vulnerabilityIds  = @($batch)
            attributes        = @()
        }
        $bodyJson = $bodyObj | ConvertTo-Json -Compress

        & $Fcli fod rest call "/api/v3/releases/$releaseId/vulnerabilities/bulk-edit" `
            -X POST `
            -d $bodyJson `
            --no-paging | Out-Null

        if ($LASTEXITCODE -ne 0) {
            Write-LogError "Falha ao atualizar lote para release '$releaseName'. Pulando lote..."
            continue
        }

        $updated += $batch.Count
    }

    Write-LogInfo "Atribuicao concluida: $updated/$($vulnIds.Count) vulnerabilidades"

    $totalReleasesComVulns++
    $totalVulns       += $vulnIds.Count
    $totalAtribuidas  += $updated
}

# ============================================================================
# RESUMO
# ============================================================================

Write-LogStep "Resumo da execucao"

Write-LogInfo "Application     : $FOD_APPLICATION_NAME"
Write-LogInfo "Usuario atribuido: $AssignUser"
Write-LogInfo "Releases processadas: $totalReleases / $($releases.Count) ($totalReleasesComVulns com vulnerabilidades)"
Write-LogInfo "Vulnerabilidades atribuidas: $totalAtribuidas / $totalVulns"

Write-Host ""
Write-LogInfo "Execucao finalizada com sucesso"

# ============================================================================
# LOGOUT
# ============================================================================

Disconnect-FodSession -Fcli $Fcli
