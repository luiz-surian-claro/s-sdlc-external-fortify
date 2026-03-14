#Requires -Version 5.1
<#
.SYNOPSIS
    Exclui todas as releases de uma Application no Fortify on Demand.

.DESCRIPTION
    Lista todas as releases da Application definida por FOD_APPLICATION_NAME
    e as exclui via fcli. Solicita confirmacao antes de prosseguir.

.PARAMETER Force
    Pula a confirmacao interativa e exclui diretamente.

.EXAMPLE
    .\fortify-delete-releases.ps1

.EXAMPLE
    .\fortify-delete-releases.ps1 -Force
#>

[CmdletBinding()]
param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
# LISTAR RELEASES DA APPLICATION
# ============================================================================

Write-LogStep "Listando releases da Application $FOD_APPLICATION_NAME"

$releases = & $Fcli fod release list --app $FOD_APPLICATION_NAME -o json |
    Out-String | ConvertFrom-Json

if (-not $releases -or $releases.Count -eq 0) {
    Write-LogWarn "Nenhuma release encontrada para Application $FOD_APPLICATION_NAME. Nada a excluir."
    Disconnect-FodSession -Fcli $Fcli
    exit 0
}

Write-LogInfo "Releases encontradas: $($releases.Count)"
foreach ($r in $releases) {
    Write-Host "  - [$($r.releaseId)] $($r.releaseName)"
}

# ============================================================================
# CONFIRMAÇÃO
# ============================================================================

if (-not $Force) {
    Write-Host ""
    Write-LogWarn "ATENCAO: Esta operacao ira excluir PERMANENTEMENTE $($releases.Count) release(s) e todos os dados associados (scans, vulnerabilidades, artefatos)."
    $confirm = Read-Host "Digite 'CONFIRMAR' para prosseguir"
    if ($confirm -ne 'CONFIRMAR') {
        Write-LogInfo "Operacao cancelada pelo usuario."
        Disconnect-FodSession -Fcli $Fcli
        exit 0
    }
}

# ============================================================================
# EXCLUIR RELEASES
# ============================================================================

Write-LogStep "Excluindo releases da Application $FOD_APPLICATION_NAME"

$deleted = 0
$failed  = 0

foreach ($release in $releases) {
    $releaseId   = $release.releaseId
    $releaseName = $release.releaseName

    Write-LogInfo "Excluindo release '$releaseName' (ID: $releaseId)..."

    & $Fcli fod release delete $releaseId 2>&1 | Out-Host

    if ($LASTEXITCODE -eq 0) {
        Write-LogInfo "Release '$releaseName' excluida com sucesso."
        $deleted++
    } else {
        Write-LogError "Falha ao excluir release '$releaseName' (ID: $releaseId)."
        $failed++
    }
}

# ============================================================================
# RESUMO
# ============================================================================

Write-LogStep "Resumo"
Write-LogInfo "Releases excluidas com sucesso : $deleted"
if ($failed -gt 0) {
    Write-LogWarn "Releases com falha na exclusao  : $failed"
}

Disconnect-FodSession -Fcli $Fcli
Write-LogInfo "Sessao FoD encerrada."

if ($failed -gt 0) {
    exit 1
}
