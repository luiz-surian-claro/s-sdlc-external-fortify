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
$LogsDir   = Join-Path $ScriptDir 'logs'

. (Join-Path $ScriptDir 'fortify-common.ps1')
Initialize-LogFile -LogsDir $LogsDir -ScriptName 'fortify-scan'

# ============================================================================
# CARREGAR .env
# ============================================================================

Import-FodEnv -EnvFile $EnvFile `
    -RequiredVars @('FOD_URL', 'FOD_CLIENT_ID', 'FOD_CLIENT_SECRET', 'FOD_APPLICATION_NAME', 'FOD_APP_TYPE', 'FOD_APP_CRITICALITY', 'FOD_SDLC_STATUS', 'GITLAB_TOKEN', 'FCLI_VERSION')

# ============================================================================
# MONTAR LISTA DE REPOSITÓRIOS
# ============================================================================

$RepoList = [System.Collections.Generic.List[string]]::new()

function Resolve-RepoUrl {
    param([string]$Entry)
    if ($Entry -match '^https?://') {
        return $Entry
    }
    # Bare repo name/path: use GITLAB_URL as base
    if (-not $GITLAB_URL) {
        Write-LogError "Entrada '$Entry' nao e uma URL completa e GITLAB_URL nao esta definido no .env"
        exit 1
    }
    $base = $GITLAB_URL.TrimEnd('/')
    $path = $Entry.TrimStart('/')
    return "$base/$path"
}

foreach ($arg in $Repos) {
    if (Test-Path $arg -PathType Leaf) {
        Get-Content $arg | ForEach-Object {
            $line = ($_ -replace '#.*', '').Trim()
            if ($line) { $RepoList.Add((Resolve-RepoUrl $line)) }
        }
    } else {
        $RepoList.Add((Resolve-RepoUrl $arg))
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

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$Fcli = Get-FcliPath -ToolsDir $ToolsDir -FcliVersion $FCLI_VERSION

# ============================================================================
# LOGIN NO FORTIFY ON DEMAND
# ============================================================================

Connect-FodSession -Fcli $Fcli -FodUrl $FOD_URL -ClientId $FOD_CLIENT_ID -ClientSecret $FOD_CLIENT_SECRET

# ============================================================================
# FUNÇÕES DE PROCESSAMENTO
# ============================================================================

function Get-RepoName {
    param([string]$Url)
    $repoUri = [Uri]$Url
    # Split path into non-empty segments
    $segments = $repoUri.AbsolutePath.TrimStart('/').Split('/') | Where-Object { $_ }
    # Skip the first segment (e.g. 'Claro-Brasil') and join the rest with '_'
    $name = ($segments | Select-Object -Skip 1) -join '_'
    # Remove .git suffix
    $name = $name -replace '\.git$', ''
    return $name
}

function Get-OrCreateRelease {
    param([string]$ReleaseName)

    Write-LogInfo "Verificando release '$ReleaseName' na application $FOD_APPLICATION_NAME..."

    # Verificar se ja existe
    $releaseId = (& $Fcli fod release list --app $FOD_APPLICATION_NAME `
        -q "releaseName=='$ReleaseName'" `
        -o "expr={releaseId}" 2>&1 | Select-Object -First 1).ToString().Trim()

    if ($releaseId -match '^\d+$') {
        Write-LogInfo "Release existente encontrado: ID=$releaseId"
        return $releaseId
    }

    Write-LogInfo "Release nao encontrado. Criando release '$ReleaseName'..."

    & $Fcli fod release create "${FOD_APPLICATION_NAME}:${ReleaseName}" `
        --sdlc-status $FOD_SDLC_STATUS `
        --app-type $FOD_APP_TYPE `
        --app-criticality $FOD_APP_CRITICALITY `
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

    $ZipFile = ConvertTo-ValidZip -FilePath $ZipFile -WorkDir $WorkDir
    if (-not $ZipFile) {
        Write-LogError "Arquivo invalido ou falha na conversao para '$RepoName'. Pulando..."
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
        --oss `
        --use-aviator | Out-Host

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
Write-LogInfo "Application: $FOD_APPLICATION_NAME"
Write-LogInfo "ZIPs gerados em: $WorkDir"
Write-LogInfo "Para acompanhar os scans, acesse: $FOD_URL"

Write-Host ""
Write-LogInfo "Execucao finalizada com sucesso"

# Cleanup
Disconnect-FodSession -Fcli $Fcli
