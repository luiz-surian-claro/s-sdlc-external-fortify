#Requires -Version 5.1
<#
.SYNOPSIS
    Script para clonar repositórios GitLab, empacotar em .zip e submeter
    scan SAST/SCA ao Fortify on Demand via fcli, criando uma Application
    por repositório.

.DESCRIPTION
    Para cada repositório informado, cria (ou reutiliza) uma Application no
    Fortify on Demand cujo nome é derivado da nomenclatura group_repo da URL
    GitLab. O Release é nomeado com a branch padrão do repositório (main ou
    master), detectada automaticamente via API GitLab. Todas as Applications
    são criadas sob o grupo definido em FOD_APP_GROUP (ex.: CNPJ-ALPHA).

.PARAMETER Repos
    Uma ou mais URLs de repositórios GitLab, ou caminho para um arquivo
    de texto com uma URL por linha.

.EXAMPLE
    .\fortify-scan-applications.ps1 https://gitlab.claro.com.br/grupo/meu-projeto.git

.EXAMPLE
    .\fortify-scan-applications.ps1 repo1.git repo2.git repo3.git

.EXAMPLE
    .\fortify-scan-applications.ps1 repos.txt
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Repos,
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
$WorkDir   = Join-Path $ScriptDir '.work'
$LogsDir   = Join-Path $ScriptDir 'logs'

. (Join-Path $ScriptDir 'fortify-common.ps1')
Initialize-LogFile -LogsDir $LogsDir -ScriptName 'fortify-scan-applications'

# ============================================================================
# CARREGAR .env
# ============================================================================

Import-FodEnv -EnvFile $EnvFile `
    -RequiredVars @('FOD_URL', 'FOD_CLIENT_ID', 'FOD_CLIENT_SECRET', 'FOD_APP_GROUP', 'FOD_APP_TYPE', 'FOD_APP_CRITICALITY', 'FOD_SDLC_STATUS', 'GITLAB_TOKEN', 'FCLI_VERSION')

# ============================================================================
# MONTAR LISTA DE REPOSITÓRIOS
# ============================================================================

$RepoList = [System.Collections.Generic.List[string]]::new()

function Resolve-RepoUrl {
    param([string]$Entry)
    if ($Entry -match '^https?://') {
        return $Entry
    }
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

# Obter token OAuth para chamadas REST diretas à API FoD
# FOD_URL (ex: http://ams.fortify.com) -> API base (ex: http://api.ams.fortify.com)
$fodApiBase     = $FOD_URL -replace '://', '://api.'
$tokenBody      = "grant_type=client_credentials&scope=api-tenant&client_id=$FOD_CLIENT_ID&client_secret=$FOD_CLIENT_SECRET"
$FodBearerToken = (Invoke-RestMethod -Uri "$fodApiBase/oauth/token" `
    -Method POST -Body $tokenBody `
    -ContentType 'application/x-www-form-urlencoded' `
    -UseBasicParsing).access_token

# Resolver o ID numérico do user group pelo nome (FOD_APP_GROUP)
$FodAuthHeader = @{ Authorization = "Bearer $FodBearerToken" }
$groupsResp    = Invoke-RestMethod -Uri "$fodApiBase/api/v3/user-management/user-groups?limit=50" `
    -Headers $FodAuthHeader -UseBasicParsing
$FodGroupId    = ($groupsResp.items | Where-Object { $_.name -eq $FOD_APP_GROUP } | Select-Object -First 1).id
if (-not $FodGroupId) {
    Write-LogError "User group '$FOD_APP_GROUP' nao encontrado no FoD. Verifique FOD_APP_GROUP no .env"
    exit 1
}
Write-LogInfo "User group '$FOD_APP_GROUP' encontrado: ID=$FodGroupId"

# ============================================================================
# FUNÇÕES DE PROCESSAMENTO
# ============================================================================

function Get-RepoName {
    param([string]$Url)
    $repoUri  = [Uri]$Url
    $segments = $repoUri.AbsolutePath.TrimStart('/').Split('/') | Where-Object { $_ }
    # Skip the first segment (org root, e.g. 'Claro-Brasil') and join the rest with '_'
    $name = ($segments | Select-Object -Skip 1) -join '_'
    $name = $name -replace '\.git$', ''
    return $name
}

function Get-DefaultBranch {
    param([string]$RepoUrl)

    $repoUri     = [Uri]$RepoUrl
    $gitlabBase  = "$($repoUri.Scheme)://$($repoUri.Authority)"
    $projectPath = $repoUri.AbsolutePath.TrimStart('/') -replace '\.git$', ''
    $encodedPath = [Uri]::EscapeDataString($projectPath)
    $apiUrl      = "$gitlabBase/api/v4/projects/$encodedPath"

    try {
        $projectInfo = Invoke-RestMethod -Uri $apiUrl `
            -Headers @{ 'PRIVATE-TOKEN' = $GITLAB_TOKEN } `
            -UseBasicParsing
        $branch = $projectInfo.default_branch
        if ($branch) {
            Write-LogInfo "Branch padrao detectada: '$branch'"
            return $branch
        }
    } catch {
        Write-LogWarn "Nao foi possivel consultar API GitLab para '$RepoUrl': $_"
    }

    Write-LogWarn "Branch padrao nao determinada. Usando 'main'."
    return 'main'
}

function Get-OrCreateApplication {
    param([string]$AppName, [string]$BranchName)

    Write-LogInfo "Verificando application '$AppName' (grupo: $FOD_APP_GROUP)..."

    $appId = (Invoke-FcliCommand @('fod','app','list','-q',"applicationName=='$AppName'",'-o','expr={applicationId}') -Silent | Select-Object -First 1).ToString().Trim()

    if ($appId -match '^\d+$') {
        Write-LogInfo "Application existente encontrada: ID=$appId"
        return $appId
    }

    Write-LogInfo "Application nao encontrada. Criando '$AppName' com release '$BranchName'..."

    Invoke-FcliCommand @('fod','app','create',$AppName,'--release',$BranchName,'--type',$FOD_APP_TYPE,'--criticality',$FOD_APP_CRITICALITY,'--status',$FOD_SDLC_STATUS,'--store','new_app')

    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Falha ao criar application '$AppName'"
        return $null
    }

    $appId = (Invoke-FcliCommand @('fod','app','get','::new_app::','-o','expr={applicationId}') -Silent | Select-Object -First 1).ToString().Trim()

    if (-not ($appId -match '^\d+$')) {
        Write-LogError "Falha ao obter ID da application '$AppName'"
        return $null
    }

    Write-LogInfo "Application criada: ID=$appId"

    # Assign user group - fcli --groups flag is a no-op at create time, so we
    # use the REST API directly: POST /api/v3/user-group-application-access/{groupId}
    # The group ID is resolved once per script run (see $FodGroupId below)
    Write-LogInfo "Atribuindo grupo '$FOD_APP_GROUP' (ID: $FodGroupId) a application $appId..."
    try {
        $null = Invoke-WebRequest `
            -Uri "$fodApiBase/api/v3/user-group-application-access/$FodGroupId" `
            -Method POST `
            -Headers @{ Authorization = "Bearer $FodBearerToken"; 'Content-Type' = 'application/json' } `
            -Body "{`"applicationId`": $appId}" `
            -UseBasicParsing
        Write-LogInfo "Grupo atribuido com sucesso"
    } catch {
        Write-LogWarn "Falha ao atribuir grupo para '$AppName': $_"
    }

    return $appId
}

function Get-OrCreateRelease {
    param([string]$AppName, [string]$ReleaseName)

    Write-LogInfo "Verificando release '$ReleaseName' na application '$AppName'..."

    $releaseId = (Invoke-FcliCommand @('fod','release','list','--app',$AppName,'-q',"releaseName=='$ReleaseName'",'-o','expr={releaseId}') -Silent | Select-Object -First 1).ToString().Trim()

    if ($releaseId -match '^\d+$') {
        Write-LogInfo "Release existente encontrado: ID=$releaseId"
        return $releaseId
    }

    Write-LogInfo "Release nao encontrado. Criando release '$ReleaseName'..."

    Invoke-FcliCommand @('fod','release','create',"${AppName}:${ReleaseName}",'--sdlc-status',$FOD_SDLC_STATUS,'--app-type',$FOD_APP_TYPE,'--app-criticality',$FOD_APP_CRITICALITY,'--store','new_release')

    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Falha ao criar release '$ReleaseName'"
        return $null
    }

    $releaseId = (Invoke-FcliCommand @('fod','release','get','::new_release::','-o','expr={releaseId}') -Silent | Select-Object -First 1).ToString().Trim()

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
    # 1. Detectar branch padrão via API GitLab
    # ========================================================================

    $Branch = Get-DefaultBranch -RepoUrl $RepoUrl

    # ========================================================================
    # 2. Verificar se a Application já existe (antes de baixar o ZIP)
    # ========================================================================

    $existingAppId = (Invoke-FcliCommand @('fod','app','list','-q',"applicationName=='$RepoName'",'-o','expr={applicationId}') -Silent | Select-Object -First 1).ToString().Trim()

    if ($existingAppId -match '^\d+$') {
        if (-not $Force) {
            Write-LogWarn "Application '$RepoName' ja existe (ID=$existingAppId). Pulando (use -Force para forcar novo scan)."
            continue
        }
        Write-LogInfo "Application '$RepoName' ja existe (ID=$existingAppId). -Force ativo, prosseguindo..."
    }

    # ========================================================================
    # 3. Baixar arquivo zip da branch padrão
    # ========================================================================

    Write-LogInfo "Baixando arquivo da branch '$Branch' ($RepoUrl)..."

    $repoUri     = [Uri]$RepoUrl
    $gitlabBase  = "$($repoUri.Scheme)://$($repoUri.Authority)"
    $projectPath = $repoUri.AbsolutePath.TrimStart('/') -replace '\.git$', ''
    $encodedPath = [Uri]::EscapeDataString($projectPath)
    $archiveUrl  = "$gitlabBase/api/v4/projects/$encodedPath/repository/archive.zip?sha=$Branch"

    if (Test-Path $ZipFile) { Remove-Item -Force $ZipFile }

    try {
        Invoke-WebRequest -Uri $archiveUrl `
            -Headers @{ 'PRIVATE-TOKEN' = $GITLAB_TOKEN } `
            -OutFile $ZipFile `
            -UseBasicParsing `
            -TimeoutSec 300
    } catch {
        Write-LogError "Falha ao baixar zip de $RepoUrl (branch: $Branch). Pulando..."
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
    # 4. Obter ou criar a Application no FoD
    # ========================================================================

    $AppId = Get-OrCreateApplication -AppName $RepoName -BranchName $Branch

    if (-not $AppId) {
        Write-LogError "Nao foi possivel obter/criar application para '$RepoName'. Pulando..."
        continue
    }

    # ========================================================================
    # 5. Obter ou criar o Release nomeado com a branch
    # ========================================================================

    $ReleaseId = Get-OrCreateRelease -AppName $RepoName -ReleaseName $Branch

    if (-not $ReleaseId) {
        Write-LogError "Nao foi possivel obter/criar release '$Branch' para '$RepoName'. Pulando..."
        continue
    }

    # ========================================================================
    # 6. Configurar SAST + SCA se ainda nao configurado
    # ========================================================================

    Write-LogInfo "Configurando SAST+SCA para release $ReleaseId..."

    Invoke-FcliCommand @('fod','sast-scan','setup','--rel',$ReleaseId,'--assessment-type','Static Assessment','--frequency','Subscription','--audit-preference','Automated','--oss','--use-aviator')

    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Falha ao configurar SAST+SCA para $RepoName"
        continue
    }

    # ========================================================================
    # 7. Iniciar scan SAST (inclui SCA pelo flag --oss configurado no setup)
    # ========================================================================

    Write-LogInfo "Iniciando scans SAST e SCA no release $ReleaseId..."

    Invoke-FcliCommand @('fod','sast-scan','start','--rel',$ReleaseId,'-f',$ZipFile,'--store',"sast_scan_$RepoVarName")

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
Write-LogInfo "Grupo de Applications: $FOD_APP_GROUP"
Write-LogInfo "ZIPs gerados em: $WorkDir"
Write-LogInfo "Para acompanhar os scans, acesse: $FOD_URL"

Write-Host ""
Write-LogInfo "Execucao finalizada com sucesso"

# Cleanup
Disconnect-FodSession -Fcli $Fcli
