#Requires -Version 5.1
<#
.SYNOPSIS
    Funções auxiliares compartilhadas pelos scripts Fortify on Demand.

.DESCRIPTION
    Exporta: Write-Log*, Import-FodEnv, Get-FcliPath, Connect-FodSession,
    Disconnect-FodSession. Deve ser carregado via dot-sourcing:

        . (Join-Path $ScriptDir 'fortify-common.ps1')
#>

# ============================================================================
# FUNÇÕES DE LOG
# ============================================================================

$script:LogFile = $null

function Initialize-LogFile {
    param(
        [Parameter(Mandatory)] [string]$LogsDir,
        [Parameter(Mandatory)] [string]$ScriptName
    )
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $script:LogFile = Join-Path $LogsDir "${ScriptName}_${timestamp}.log"
    Write-LogInfo "Log gravado em: $($script:LogFile)"
}

function Write-LogLine {
    param([string]$Line)
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $Line -Encoding UTF8 }
}

function Write-LogInfo  {
    param([string]$Message)
    $line = "[INFO]  $Message"
    Write-Host $line
    Write-LogLine $line
}
function Write-LogWarn  {
    param([string]$Message)
    $line = "[WARN]  $Message"
    Write-Host $line -ForegroundColor Yellow
    Write-LogLine $line
}
function Write-LogError {
    param([string]$Message)
    $line = "[ERROR] $Message"
    Write-Host $line -ForegroundColor Red
    Write-LogLine $line
}
function Write-LogStep  {
    param([string]$Message)
    $sep = '=' * 64
    Write-Host ""
    Write-Host $sep
    Write-Host "  $Message"
    Write-Host $sep
    Write-LogLine ""
    Write-LogLine $sep
    Write-LogLine "  $Message"
    Write-LogLine $sep
}

# ============================================================================
# CARREGAR .env E VALIDAR VARIÁVEIS
# ============================================================================

function Import-FodEnv {
    <#
    .SYNOPSIS
        Carrega o arquivo .env e define as variáveis no escopo do chamador.
    .PARAMETER EnvFile
        Caminho para o arquivo .env.
    .PARAMETER RequiredVars
        Lista de variáveis obrigatórias a validar. Padrão cobre os scripts
        de assign e delete; o scan adiciona GITLAB_TOKEN.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$EnvFile,

        [string[]]$RequiredVars = @(
            'FOD_URL', 'FOD_CLIENT_ID', 'FOD_CLIENT_SECRET',
            'FOD_APPLICATION_NAME', 'FCLI_VERSION'
        )
    )

    if (-not (Test-Path $EnvFile)) {
        Write-LogError "Arquivo .env nao encontrado em: $EnvFile"
        Write-LogError "Crie o arquivo .env com as variaveis: $($RequiredVars -join ', ')"
        exit 1
    }

    $vars = @{}
    Get-Content $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#')) {
            $parts = $line -split '=', 2
            if ($parts.Count -eq 2) {
                $vars[$parts[0].Trim()] = $parts[1].Trim()
            }
        }
    }

    $missing = @()
    foreach ($v in $RequiredVars) {
        if (-not $vars[$v]) { $missing += $v }
    }
    if ($missing.Count -gt 0) {
        Write-LogError "Variaveis obrigatorias nao definidas no .env: $($missing -join ', ')"
        exit 1
    }

    # Exportar todas as variáveis no escopo do chamador
    foreach ($key in $vars.Keys) {
        Set-Variable -Name $key -Value $vars[$key] -Scope 1
    }

    # FOD_INSECURE como booleano
    $insecure = ($vars['FOD_INSECURE'] -eq 'true')
    Set-Variable -Name 'FOD_INSECURE' -Value $insecure -Scope 1
    if ($insecure) {
        Write-LogWarn "FOD_INSECURE=true: validacao de certificado SSL desabilitada (bypass Netskope)."
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
}

# ============================================================================
# VALIDAR / CONVERTER ARQUIVO ZIP
# ============================================================================

function ConvertTo-ValidZip {
    <#
    .SYNOPSIS
        Garante que o arquivo seja um ZIP válido para o Fortify on Demand.
        Se o servidor retornar gzip/tar.gz, extrai e reempacota como ZIP.
    .PARAMETER FilePath
        Caminho do arquivo baixado.
    .PARAMETER WorkDir
        Diretório de trabalho para arquivos temporários.
    #>
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string]$WorkDir
    )

    # Ler os primeiros 4 bytes para detectar o formato
    $header = New-Object byte[] 4
    $stream = [System.IO.File]::OpenRead($FilePath)
    $stream.Read($header, 0, 4) | Out-Null
    $stream.Close()

    # ZIP magic: PK (0x50 0x4B)
    if ($header[0] -eq 0x50 -and $header[1] -eq 0x4B) {
        return $FilePath
    }

    # GZIP magic: 0x1F 0x8B
    if ($header[0] -eq 0x1F -and $header[1] -eq 0x8B) {
        Write-LogWarn "Arquivo baixado em formato gzip, convertendo para zip..."

        $baseName   = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
        $tarGzPath  = Join-Path $WorkDir "$baseName.tar.gz"
        $extractDir = Join-Path $WorkDir "${baseName}_src"

        Move-Item -Path $FilePath -Destination $tarGzPath
        New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

        tar -xzf $tarGzPath -C $extractDir
        if ($LASTEXITCODE -ne 0) {
            Write-LogError "Falha ao extrair $tarGzPath"
            return $null
        }

        Push-Location $extractDir
        try {
            Compress-Archive -Path * -DestinationPath $FilePath -Force
        } finally {
            Pop-Location
        }

        if (-not (Test-Path $FilePath)) {
            Write-LogError "Falha ao criar ZIP a partir do conteudo extraido"
            return $null
        }

        Remove-Item -Recurse -Force $extractDir
        Remove-Item -Force $tarGzPath

        Write-LogInfo "Arquivo convertido para ZIP: $FilePath"
        return $FilePath
    }

    Write-LogError "Formato de arquivo desconhecido (nao e ZIP nem GZIP): $FilePath"
    return $null
}

# ============================================================================
# INSTALAR / LOCALIZAR fcli
# ============================================================================

function Get-FcliPath {
    <#
    .SYNOPSIS
        Localiza ou baixa o binário fcli. Retorna o caminho do executável.
    .PARAMETER ToolsDir
        Diretório onde o fcli será armazenado se precisar ser baixado.
    .PARAMETER FcliVersion
        Versão do fcli a baixar caso não seja encontrado localmente ou no PATH.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ToolsDir,

        [Parameter(Mandatory)]
        [string]$FcliVersion
    )

    Write-LogStep "Preparando fcli"

    New-Item -ItemType Directory -Path $ToolsDir -Force | Out-Null

    $FcliExeName = if ((Test-Path variable:IsLinux) -and $IsLinux -or
                       (Test-Path variable:IsMacOS) -and $IsMacOS) { 'fcli' } else { 'fcli.exe' }

    # Verificar no PATH
    $FcliInPath = Get-Command $FcliExeName -ErrorAction SilentlyContinue
    if ($FcliInPath) {
        Write-LogInfo "fcli encontrado no PATH: $($FcliInPath.Source)"
        & $FcliInPath.Source -V | Out-Host
        return $FcliInPath.Source
    }

    # Verificar no diretório de ferramentas
    $FcliLocal = Join-Path $ToolsDir $FcliExeName
    if (Test-Path $FcliLocal) {
        Write-LogInfo "fcli encontrado em: $FcliLocal"
        & $FcliLocal -V | Out-Host
        return $FcliLocal
    }

    # Baixar
    Write-LogInfo "fcli nao encontrado. Baixando versao $FcliVersion..."

    $FcliBaseUrl    = "https://github.com/fortify/fcli/releases/download/$FcliVersion"
    $FcliArchive    = if ((Test-Path variable:IsLinux) -and $IsLinux) { 'fcli-linux.tgz' } `
                      elseif ((Test-Path variable:IsMacOS) -and $IsMacOS) { 'fcli-mac.tgz' } `
                      else { 'fcli-windows.zip' }
    $FcliArchivePath = Join-Path $ToolsDir $FcliArchive

    Write-LogInfo "Baixando de: $FcliBaseUrl/$FcliArchive"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "$FcliBaseUrl/$FcliArchive" -OutFile $FcliArchivePath -UseBasicParsing

    if ($FcliArchive -match '\.zip$') {
        Expand-Archive -Path $FcliArchivePath -DestinationPath $ToolsDir -Force
    } else {
        tar -xzf $FcliArchivePath -C $ToolsDir
    }

    if (-not (Test-Path $FcliLocal)) {
        Write-LogError "Falha ao extrair fcli para: $FcliLocal"
        exit 1
    }

    Write-LogInfo "fcli instalado em: $FcliLocal"
    & $FcliLocal -V | Out-Host
    return $FcliLocal
}

# ============================================================================
# LOGIN / LOGOUT
# ============================================================================

function Connect-FodSession {
    <#
    .SYNOPSIS
        Realiza login no Fortify on Demand via fcli.
    #>
    param(
        [Parameter(Mandatory)] [string]$Fcli,
        [Parameter(Mandatory)] [string]$FodUrl,
        [Parameter(Mandatory)] [string]$ClientId,
        [Parameter(Mandatory)] [string]$ClientSecret
    )

    Write-LogStep "Conectando ao Fortify on Demand"

    & $Fcli fod session login `
        --url $FodUrl `
        --client-id $ClientId `
        --client-secret $ClientSecret

    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Falha ao conectar com Fortify on Demand"
        exit 1
    }

    Write-LogInfo "Conectado ao FoD com sucesso"
}

function Disconnect-FodSession {
    <#
    .SYNOPSIS
        Realiza logout do Fortify on Demand via fcli.
    #>
    param(
        [Parameter(Mandatory)] [string]$Fcli
    )

    Write-LogInfo "Encerrando sessao FoD..."
    & $Fcli fod session logout 2>$null
}
