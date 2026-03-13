#Requires -Version 5.1
<#
.SYNOPSIS
    Atribui todas as vulnerabilidades de todas as releases de uma Application
    FoD para um usuário específico.

.DESCRIPTION
    Para cada release da Application definida por FOD_APPLICATION_ID, lista
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

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

function Write-LogInfo  { param([string]$Message) Write-Host "[INFO]  $Message" }
function Write-LogWarn  { param([string]$Message) Write-Host "[WARN]  $Message" -ForegroundColor Yellow }
function Write-LogError { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }
function Write-LogStep  { param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 64)
    Write-Host "  $Message"
    Write-Host ("=" * 64)
}

# ============================================================================
# CARREGAR .env
# ============================================================================

if (-not (Test-Path $EnvFile)) {
    Write-LogError "Arquivo .env nao encontrado em: $EnvFile"
    exit 1
}

$EnvVars = @{}
Get-Content $EnvFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith('#')) {
        $parts = $line -split '=', 2
        if ($parts.Count -eq 2) {
            $EnvVars[$parts[0].Trim()] = $parts[1].Trim()
        }
    }
}

$FOD_URL            = $EnvVars['FOD_URL']
$FOD_CLIENT_ID      = $EnvVars['FOD_CLIENT_ID']
$FOD_CLIENT_SECRET  = $EnvVars['FOD_CLIENT_SECRET']
$FOD_APPLICATION_ID = $EnvVars['FOD_APPLICATION_ID']
$FCLI_VERSION       = $EnvVars['FCLI_VERSION']
$FOD_INSECURE       = ($EnvVars['FOD_INSECURE'] -eq 'true')

$RequiredVars = @('FOD_URL', 'FOD_CLIENT_ID', 'FOD_CLIENT_SECRET', 'FOD_APPLICATION_ID', 'FCLI_VERSION')
$Missing = @()
foreach ($var in $RequiredVars) {
    if (-not $EnvVars[$var]) { $Missing += $var }
}
if ($Missing.Count -gt 0) {
    Write-LogError "Variaveis obrigatorias nao definidas no .env: $($Missing -join ', ')"
    exit 1
}

if ($FOD_INSECURE) {
    Write-LogWarn "FOD_INSECURE=true: validacao de certificado SSL desabilitada (bypass Netskope)."
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

# ============================================================================
# INSTALAR / LOCALIZAR fcli
# ============================================================================

Write-LogStep "Preparando fcli"

New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null

$Fcli = $null
$FcliExeName = if ($IsLinux -or $IsMacOS) { 'fcli' } else { 'fcli.exe' }

$FcliInPath = Get-Command $FcliExeName -ErrorAction SilentlyContinue
if ($FcliInPath) {
    $Fcli = $FcliInPath.Source
    Write-LogInfo "fcli encontrado no PATH: $Fcli"
}

if (-not $Fcli) {
    $FcliLocal = Join-Path $ToolsDir $FcliExeName
    if (Test-Path $FcliLocal) {
        $Fcli = $FcliLocal
        Write-LogInfo "fcli encontrado em: $Fcli"
    }
}

if (-not $Fcli) {
    Write-LogInfo "fcli nao encontrado. Baixando versao $FCLI_VERSION..."

    $FcliBaseUrl = "https://github.com/fortify/fcli/releases/download/$FCLI_VERSION"
    $FcliArchive = if ($IsLinux) { 'fcli-linux.tgz' } elseif ($IsMacOS) { 'fcli-mac.tgz' } else { 'fcli-windows.zip' }
    $FcliArchivePath = Join-Path $ToolsDir $FcliArchive

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "$FcliBaseUrl/$FcliArchive" -OutFile $FcliArchivePath -UseBasicParsing

    if ($FcliArchive -match '\.zip$') {
        Expand-Archive -Path $FcliArchivePath -DestinationPath $ToolsDir -Force
    } else {
        tar -xzf $FcliArchivePath -C $ToolsDir
    }

    $Fcli = Join-Path $ToolsDir $FcliExeName
    if (-not (Test-Path $Fcli)) {
        Write-LogError "Falha ao extrair fcli para: $Fcli"
        exit 1
    }
    Write-LogInfo "fcli instalado em: $Fcli"
}

& $Fcli -V

# ============================================================================
# LOGIN NO FORTIFY ON DEMAND
# ============================================================================

Write-LogStep "Conectando ao Fortify on Demand"

& $Fcli fod session login `
    --url $FOD_URL `
    --client-id $FOD_CLIENT_ID `
    --client-secret $FOD_CLIENT_SECRET

if ($LASTEXITCODE -ne 0) {
    Write-LogError "Falha ao conectar com Fortify on Demand"
    exit 1
}

Write-LogInfo "Conectado ao FoD com sucesso"

# ============================================================================
# LISTAR RELEASES DA APPLICATION
# ============================================================================

Write-LogStep "Listando releases da Application $FOD_APPLICATION_ID"

$releases = & $Fcli fod release list --app $FOD_APPLICATION_ID -o json |
    ConvertFrom-Json |
    Select-Object -ExpandProperty value

if (-not $releases -or $releases.Count -eq 0) {
    Write-LogWarn "Nenhuma release encontrada para Application $FOD_APPLICATION_ID"
    & $Fcli fod session logout 2>$null
    exit 0
}

Write-LogInfo "Releases encontradas: $($releases.Count)"

# ============================================================================
# CONTADORES GLOBAIS
# ============================================================================

$totalReleases    = 0
$totalVulns       = 0
$totalAtribuidas  = 0

# ============================================================================
# PROCESSAR CADA RELEASE
# ============================================================================

foreach ($release in $releases) {
    $releaseId   = $release.id
    $releaseName = $release.name

    Write-LogStep "Release: $releaseName (ID: $releaseId)"

    # -------------------------------------------------------------------------
    # Listar todas as vulnerabilidades visíveis da release
    # -------------------------------------------------------------------------

    Write-LogInfo "Buscando vulnerabilidades..."

    $vulns = & $Fcli fod issue list --rel $releaseId -o json |
        ConvertFrom-Json |
        Select-Object -ExpandProperty value

    if (-not $vulns -or $vulns.Count -eq 0) {
        Write-LogInfo "Nenhuma vulnerabilidade encontrada. Pulando..."
        continue
    }

    $vulnIds = $vulns | Select-Object -ExpandProperty vulnId
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
            vulnIds            = @($batch)
            assignedUser       = $AssignUser
            userAssignmentType = 'SpecificUser'
        }
        $bodyJson = $bodyObj | ConvertTo-Json -Compress

        & $Fcli fod rest call "/api/v3/releases/$releaseId/vulnerabilities/audit" `
            -X PUT `
            -d $bodyJson | Out-Null

        if ($LASTEXITCODE -ne 0) {
            Write-LogError "Falha ao atualizar lote para release '$releaseName'. Pulando lote..."
            continue
        }

        $updated += $batch.Count
    }

    Write-LogInfo "Atribuicao concluida: $updated/$($vulnIds.Count) vulnerabilidades"

    $totalReleases++
    $totalVulns       += $vulnIds.Count
    $totalAtribuidas  += $updated
}

# ============================================================================
# RESUMO
# ============================================================================

Write-LogStep "Resumo da execucao"

Write-LogInfo "Application ID  : $FOD_APPLICATION_ID"
Write-LogInfo "Usuario atribuido: $AssignUser"
Write-LogInfo "Releases processadas: $totalReleases / $($releases.Count)"
Write-LogInfo "Vulnerabilidades atribuidas: $totalAtribuidas / $totalVulns"

Write-Host ""
Write-LogInfo "Execucao finalizada com sucesso"

# ============================================================================
# LOGOUT
# ============================================================================

Write-LogInfo "Encerrando sessao FoD..."
& $Fcli fod session logout 2>$null
