# s-sdlc-external-fortify

Scripts de automação para submeter scans **SAST** (Static Application Security Testing) e **SCA** (Open Source / OSS) ao **Fortify on Demand (FoD)** a partir de repositórios GitLab, utilizando o [fcli](https://github.com/fortify/fcli).

---

## Scripts disponíveis

| Script | Descrição |
| --- | --- |
| `fortify-scan.ps1` | Baixa repositórios GitLab, cria releases e submete scans SAST+SCA ao FoD |
| `fortify-assign.ps1` | Atribui todas as vulnerabilidades de todas as releases a um usuário FoD |
| `fortify-delete-releases.ps1` | Exclui todas as releases da Application no FoD |
| `fortify-common.ps1` | Helper interno com funções compartilhadas (não executar diretamente) |

---

## Como funciona

### `fortify-scan.ps1`

Para cada repositório informado, o script executa os seguintes passos:

1. **Localiza ou baixa o `fcli`** — verifica no `PATH` e em `.tools/`; se não encontrado, faz o download da versão definida em `FCLI_VERSION`.
2. **Autentica no FoD** via Client Credentials (`FOD_CLIENT_ID` / `FOD_CLIENT_SECRET`).
3. **Baixa o código-fonte** diretamente da API do GitLab como arquivo `.zip` (branch padrão).
4. **Cria ou reutiliza um Release** no FoD dentro da Application definida por `FOD_APPLICATION_NAME`. Se a Application não existir, ela é criada automaticamente com `FOD_APP_TYPE` e `FOD_APP_CRITICALITY`.
5. **Configura e inicia o scan SAST+SCA** (`fcli fod sast-scan setup` + `start`).

Ao final, a sessão FoD é encerrada automaticamente.

### `fortify-assign.ps1`

Para cada release da Application, lista todas as vulnerabilidades e realiza um bulk update via REST API para atribuí-las ao usuário informado.

### `fortify-delete-releases.ps1`

Lista todas as releases da Application e as exclui permanentemente. Solicita confirmação interativa antes de prosseguir (use `-Force` para pular).

> **Atenção:** a exclusão de todas as releases também remove a Application do FoD. Ao recriar releases com `fortify-scan.ps1`, a Application será recriada automaticamente.

---

## Pré-requisitos

- PowerShell 5.1 ou superior (Windows, Linux ou macOS)
- Acesso de rede ao GitLab e ao Fortify on Demand
- Conta de serviço no FoD com permissão para criar applications/releases e iniciar scans
- Token GitLab (`read_api` é suficiente) com acesso aos repositórios

> O `fcli` é baixado automaticamente caso não esteja disponível no `PATH`.

---

## Configuração

Crie um arquivo `.env` na raiz do repositório (nunca commitar este arquivo):

```dotenv
# Fortify on Demand - Credenciais
FOD_URL=https://ams.fortify.com
FOD_CLIENT_ID=<seu-client-id>
FOD_CLIENT_SECRET=<seu-client-secret>

# Fortify on Demand - Application
FOD_APPLICATION_NAME=<nome-da-application-no-fod>
FOD_APP_TYPE=Web
FOD_APP_CRITICALITY=High

# SDLC Status das releases criadas
FOD_SDLC_STATUS=Production

# GitLab
GITLAB_URL=https://gitlab.exemplo.com.br
GITLAB_TOKEN=<seu-token-privado-gitlab>

# Versão do fcli a baixar caso não esteja instalado
FCLI_VERSION=v3.15.0

# Usuário padrão para atribuição de vulnerabilidades (fortify-assign.ps1)
FOD_ASSIGN_USER=

# Opcional: desabilita validação de certificado SSL (ex.: bypass Netskope)
# FOD_INSECURE=true
```

| Variável | Obrigatória | Descrição |
| --- | --- | --- |
| `FOD_URL` | Sim | URL base do Fortify on Demand |
| `FOD_CLIENT_ID` | Sim | Client ID da conta de serviço FoD |
| `FOD_CLIENT_SECRET` | Sim | Client Secret da conta de serviço FoD |
| `FOD_APPLICATION_NAME` | Sim | Nome da Application no FoD onde os releases serão criados |
| `FOD_APP_TYPE` | Sim | Tipo da Application ao criar (valores: `Web`, `ThickClient`, `Mobile`, `Microservice`) |
| `FOD_APP_CRITICALITY` | Sim | Criticidade de negócio ao criar a Application (valores: `High`, `Medium`, `Low`) |
| `FOD_SDLC_STATUS` | Sim | Status SDLC das releases criadas (valores: `Development`, `QA`, `Production`, `Retired`) |
| `GITLAB_TOKEN` | Sim | Personal/Project Access Token do GitLab |
| `GITLAB_URL` | Não | URL base do GitLab (usado para resolver URLs relativas) |
| `FCLI_VERSION` | Sim | Versão do fcli a baixar (ex.: `v3.15.0`) |
| `FOD_ASSIGN_USER` | Não | Usuário padrão para atribuição de vulnerabilidades em `fortify-assign.ps1` |
| `FOD_INSECURE` | Não | `true` para desabilitar validação SSL (bypass de proxy TLS) |

---

## Uso dos scripts

### Uso: `fortify-scan.ps1`

#### Repositório único

```powershell
.\fortify-scan.ps1 https://gitlab.exemplo.com.br/grupo/meu-projeto.git
```

#### Múltiplos repositórios na mesma execução

```powershell
.\fortify-scan.ps1 https://gitlab.exemplo.com.br/grupo/repo-a.git https://gitlab.exemplo.com.br/grupo/repo-b.git
```

#### A partir de um arquivo de texto

Crie um arquivo com uma URL por linha (linhas em branco e comentários com `#` são ignorados):

```text
# repos.txt
https://gitlab.exemplo.com.br/grupo/repo-a.git
https://gitlab.exemplo.com.br/grupo/repo-b.git
https://gitlab.exemplo.com.br/grupo/repo-c.git
```

```powershell
.\fortify-scan.ps1 repos.txt
```

### Uso: `fortify-assign.ps1`

```powershell
# Atribuir ao usuário padrão (luiz.surian)
.\fortify-assign.ps1

# Atribuir a outro usuário
.\fortify-assign.ps1 -AssignUser outro.usuario
```

### Uso: `fortify-delete-releases.ps1`

```powershell
# Com confirmação interativa
.\fortify-delete-releases.ps1

# Sem confirmação (ex.: pipelines CI/CD)
.\fortify-delete-releases.ps1 -Force
```

---

## Estrutura de diretórios

```text
fortify-common.ps1          # Helper compartilhado (dot-sourced pelos outros scripts)
fortify-scan.ps1            # Script principal de scan
fortify-assign.ps1          # Script de atribuição de vulnerabilidades
fortify-delete-releases.ps1 # Script de exclusão de releases
repos/                      # Arquivos de listas de repositórios
.tools/                     # fcli baixado automaticamente (ignorado pelo git)
.work/                      # ZIPs dos repositórios gerados durante a execução (ignorado pelo git)
logs/                       # Arquivos de log gerados por cada execução (ignorado pelo git)
.env                        # Variáveis de configuração (ignorado pelo git)
```

---

## Acompanhando os scans

Após a execução, acesse o FoD e navegue até a Application / Release correspondente ao nome do repositório para acompanhar o progresso dos scans SAST e SCA.
