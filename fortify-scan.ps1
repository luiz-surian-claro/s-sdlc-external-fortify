#Requires -Version 5.1
<#
.SYNOPSIS
    Script para clonar repositórios GitLab, empacotar em .zip e submeter
    scan SAST/SCA ao Fortify on Demand via fcli.

.DESCRIPTION
    Baixa o fcli se não encontrado localmente, clona repositórios GitLab,
    compacta em .zip, cria/reutiliza releases na application CNPJ-ALPHA
    (ID 179337) e inicia scans SAST no Fortify on Demand.

.PARAMETER Repos
    Uma ou mais URLs de repositórios GitLab, ou caminho para um arquivo
    de texto com uma URL por linha.

.EXAMPLE
    .\fortify-scan.ps1 https://gitlab.claro.com.br/grupo/meu-projeto.git

.EXAMPLE
    .\fortify-scan.ps1 repo1.git repo2.git repo3.git

.EXAMPLE
    .\fortify-scan.ps1 repos.txt
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Repos
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# VARIÁVEIS DE DIRETÓRIO
# ============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$EnvFile   = Join-Path $ScriptDir '.env'
$ToolsDir  = Join-Path $ScriptDir '.tools'
$WorkDir   = Join-Path $ScriptDir '.work'

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

function Invoke-Cleanup {
    Write-LogInfo "Encerrando sessao FoD..."
    & $Fcli fod session logout 2>$null
}

# ============================================================================
# CARREGAR .env
# ============================================================================

if (-not (Test-Path $EnvFile)) {
    Write-LogError "Arquivo .env nao encontrado em: $EnvFile"
    Write-LogError "Crie o arquivo .env com as variaveis FOD_URL, FOD_CLIENT_ID, FOD_CLIENT_SECRET, GITLAB_URL, GITLAB_TOKEN, FOD_APPLICATION_ID, FCLI_VERSION"
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

# Exportar como variáveis do script
$FOD_URL            = $EnvVars['FOD_URL']
$FOD_CLIENT_ID      = $EnvVars['FOD_CLIENT_ID']
$FOD_CLIENT_SECRET  = $EnvVars['FOD_CLIENT_SECRET']
$FOD_APPLICATION_ID = $EnvVars['FOD_APPLICATION_ID']
$GITLAB_TOKEN       = $EnvVars['GITLAB_TOKEN']
$GITLAB_URL         = $EnvVars['GITLAB_URL']
$FCLI_VERSION       = $EnvVars['FCLI_VERSION']
$FOD_INSECURE       = ($EnvVars['FOD_INSECURE'] -eq 'true')

# Validar variáveis obrigatórias
$RequiredVars = @('FOD_URL', 'FOD_CLIENT_ID', 'FOD_CLIENT_SECRET', 'FOD_APPLICATION_ID', 'GITLAB_TOKEN', 'FCLI_VERSION')
$Missing = @()
foreach ($var in $RequiredVars) {
    if (-not $EnvVars[$var]) {
        $Missing += $var
    }
}
if ($Missing.Count -gt 0) {
    Write-LogError "Variaveis obrigatorias nao definidas no .env: $($Missing -join ', ')"
    exit 1
}

if ($FOD_INSECURE) {
    Write-LogWarn "FOD_INSECURE=true: validacao de certificado SSL desabilitada (bypass Netskope)."
    # Necessario para Invoke-WebRequest em PS 5.1 (nao suporta -SkipCertificateCheck)
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

# ============================================================================
# MONTAR LISTA DE REPOSITÓRIOS
# ============================================================================

$RepoList = [System.Collections.Generic.List[string]]::new()

foreach ($arg in $Repos) {
    if (Test-Path $arg -PathType Leaf) {
        Get-Content $arg | ForEach-Object {
            $line = ($_ -replace '#.*', '').Trim()
            if ($line) { $RepoList.Add($line) }
        }
    } else {
        $RepoList.Add($arg)
    }
}

if ($RepoList.Count -eq 0) {
    Write-LogError "Nenhum repositorio fornecido."
    exit 1
}

Write-LogInfo "Repositorios a processar ($($RepoList.Count)):"
foreach ($r in $RepoList) {
    Write-Host "  - $r"
}

# ============================================================================
# INSTALAR / LOCALIZAR fcli
# ============================================================================

Write-LogStep "Preparando fcli"

New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

$Fcli = $null
$FcliExeName = if ($IsLinux -or $IsMacOS) { 'fcli' } else { 'fcli.exe' }

# Verificar no PATH
$FcliInPath = Get-Command $FcliExeName -ErrorAction SilentlyContinue
if ($FcliInPath) {
    $Fcli = $FcliInPath.Source
    Write-LogInfo "fcli encontrado no PATH: $Fcli"
}

# Verificar no diretório de ferramentas
if (-not $Fcli) {
    $FcliLocal = Join-Path $ToolsDir $FcliExeName
    if (Test-Path $FcliLocal) {
        $Fcli = $FcliLocal
        Write-LogInfo "fcli encontrado em: $Fcli"
    }
}

# Baixar se não encontrado
if (-not $Fcli) {
    Write-LogInfo "fcli nao encontrado. Baixando versao $FCLI_VERSION..."

    $FcliBaseUrl = "https://github.com/fortify/fcli/releases/download/$FCLI_VERSION"

    if ($IsLinux) {
        $FcliArchive = 'fcli-linux.tgz'
    } elseif ($IsMacOS) {
        $FcliArchive = 'fcli-mac.tgz'
    } else {
        $FcliArchive = 'fcli-windows.zip'
    }

    $FcliDownloadUrl = "$FcliBaseUrl/$FcliArchive"
    $FcliArchivePath = Join-Path $ToolsDir $FcliArchive

    Write-LogInfo "Baixando de: $FcliDownloadUrl"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $FcliDownloadUrl -OutFile $FcliArchivePath -UseBasicParsing

    if ($FcliArchive -match '\.zip$') {
        Expand-Archive -Path $FcliArchivePath -DestinationPath $ToolsDir -Force
    } else {
        # Para .tgz no PowerShell, usar tar (disponível no Windows 10+)
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

$LoginArgs = @(
    'fod', 'session', 'login',
    '--url', $FOD_URL,
    '--client-id', $FOD_CLIENT_ID,
    '--client-secret', $FOD_CLIENT_SECRET
)

& $Fcli @LoginArgs

if ($LASTEXITCODE -ne 0) {
    Write-LogError "Falha ao conectar com Fortify on Demand"
    exit 1
}

Write-LogInfo "Conectado ao FoD com sucesso"

# Registrar cleanup para execução no final
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    & $Fcli fod session logout 2>$null
}

# ============================================================================
# FUNÇÕES DE PROCESSAMENTO
# ============================================================================

function Get-RepoName {
    param([string]$Url)
    $name = [System.IO.Path]::GetFileNameWithoutExtension($Url)
    if ($name.EndsWith('.git')) {
        $name = $name.Substring(0, $name.Length - 4)
    }
    return $name
}

function Get-OrCreateRelease {
    param([string]$ReleaseName)

    Write-LogInfo "Verificando release '$ReleaseName' na application $FOD_APPLICATION_ID..."

    # Verificar se ja existe
    $releaseId = (& $Fcli fod release list --app $FOD_APPLICATION_ID `
        -q "releaseName=='$ReleaseName'" `
        -o "expr={releaseId}" 2>&1 | Select-Object -First 1).ToString().Trim()

    if ($releaseId -match '^\d+$') {
        Write-LogInfo "Release existente encontrado: ID=$releaseId"
        return $releaseId
    }

    Write-LogInfo "Release nao encontrado. Criando release '$ReleaseName'..."

    & $Fcli fod release create "${FOD_APPLICATION_ID}:${ReleaseName}" `
        --sdlc-status Development `
        --store new_release | Out-Host

    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Falha ao criar release '$ReleaseName'"
        return $null
    }

    $releaseId = (& $Fcli fod release get "::new_release::" `
        -o "expr={releaseId}" 2>&1 | Select-Object -First 1).ToString().Trim()

    if ($releaseId -match '^\d+$') {
        Write-LogInfo "Release criado: ID=$releaseId"
        return $releaseId
    }

    Write-LogError "Falha ao obter ID do release para '$ReleaseName'"
    return $null
}

# ============================================================================
# PROCESSAR CADA REPOSITÓRIO
# ============================================================================

foreach ($RepoUrl in $RepoList) {
    $RepoName    = Get-RepoName $RepoUrl
    $RepoVarName = $RepoName -replace '[^a-zA-Z0-9_]', '_'
    $ZipFile     = Join-Path $WorkDir "$RepoName.zip"

    Write-LogStep "Processando: $RepoName"

    # ========================================================================
    # 1. Baixar arquivo zip diretamente do GitLab
    # ========================================================================

    Write-LogInfo "Baixando arquivo do repositorio $RepoUrl..."

    $repoUri     = [Uri]$RepoUrl
    $gitlabBase  = "$($repoUri.Scheme)://$($repoUri.Authority)"
    $projectPath = $repoUri.AbsolutePath.TrimStart('/') -replace '\.git$', ''
    $encodedPath = [Uri]::EscapeDataString($projectPath)
    $archiveUrl  = "$gitlabBase/api/v4/projects/$encodedPath/repository/archive.zip"

    if (Test-Path $ZipFile) { Remove-Item -Force $ZipFile }

    try {
        Invoke-WebRequest -Uri $archiveUrl `
            -Headers @{ 'PRIVATE-TOKEN' = $GITLAB_TOKEN } `
            -OutFile $ZipFile `
            -UseBasicParsing
    } catch {
        Write-LogError "Falha ao baixar zip de $RepoUrl. Pulando..."
        continue
    }

    $ZipSize   = (Get-Item $ZipFile).Length
    $ZipSizeMB = [math]::Round($ZipSize / 1MB, 2)
    Write-LogInfo "Pacote gerado: $ZipFile (${ZipSizeMB} MB)"

    # ========================================================================
    # 3. Obter ou criar release no FoD
    # ========================================================================

    $ReleaseId = Get-OrCreateRelease -ReleaseName $RepoName

    if (-not $ReleaseId) {
        Write-LogError "Nao foi possivel obter/criar release para '$RepoName'. Pulando..."
        continue
    }

    # ========================================================================
    # 3b. Configurar SAST + SCA se ainda nao configurado
    # ========================================================================

    Write-LogInfo "Configurando SAST+SCA para release $ReleaseId..."

    & $Fcli fod sast-scan setup `
        --rel $ReleaseId `
        --assessment-type "Static Assessment" `
        --frequency Subscription `
        --audit-preference Automated `
        --oss | Out-Host

    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Falha ao configurar SAST+SCA para $RepoName"
        continue
    }

    # ========================================================================
    # 4. Iniciar scan SAST (inclui SCA pelo flag --oss configurado no setup)
    # ========================================================================

    Write-LogInfo "Iniciando scans SAST e SCA no release $ReleaseId..."

    & $Fcli fod sast-scan start `
        --rel $ReleaseId `
        -f $ZipFile `
        --store "sast_scan_$RepoVarName" | Out-Host

    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Falha ao iniciar scan SAST+SCA para $RepoName"
        continue
    }

    Write-LogInfo "Scans SAST e SCA iniciados com sucesso para $RepoName"
    Write-LogInfo "Acompanhe em: $FOD_URL/Redirect/Releases/$ReleaseId"

    Write-LogInfo "Processamento de $RepoName finalizado"
}

# ============================================================================
# RESUMO
# ============================================================================

Write-LogStep "Resumo da execucao"

Write-LogInfo "Repositorios processados: $($RepoList.Count)"
Write-LogInfo "Application ID: $FOD_APPLICATION_ID (CNPJ-ALPHA)"
Write-LogInfo "ZIPs gerados em: $WorkDir"
Write-LogInfo "Para acompanhar os scans, acesse: $FOD_URL"

Write-Host ""
Write-LogInfo "Execucao finalizada com sucesso"

# Cleanup
Invoke-Cleanup
