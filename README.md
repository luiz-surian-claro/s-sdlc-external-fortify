# s-sdlc-external-fortify

Script de automação para submeter scans **SAST** (Static Application Security Testing) e **SCA** (Open Source / OSS) ao **Fortify on Demand (FoD)** a partir de repositórios GitLab, utilizando o [fcli](https://github.com/fortify/fcli).

---

## Como funciona

Para cada repositório informado, o script executa os seguintes passos:

1. **Localiza ou baixa o `fcli`** — verifica no `PATH` e em `.tools/`; se não encontrado, faz o download da versão definida em `FCLI_VERSION`.
2. **Autentica no FoD** via Client Credentials (`FOD_CLIENT_ID` / `FOD_CLIENT_SECRET`).
3. **Baixa o código-fonte** diretamente da API do GitLab como arquivo `.zip` (branch padrão).
4. **Cria ou reutiliza um Release** no FoD dentro da Application definida por `FOD_APPLICATION_ID`, usando o nome do repositório como nome do release.
5. **Configura e inicia o scan SAST** (`fcli fod sast-scan setup` + `start`).
6. **Inicia o scan SCA/OSS** (`fcli fod oss-scan start`).

Ao final, a sessão FoD é encerrada automaticamente.

---

## Pré-requisitos

- PowerShell 5.1 ou superior (Windows, Linux ou macOS)
- Acesso de rede ao GitLab e ao Fortify on Demand
- Conta de serviço no FoD com permissão para criar releases e iniciar scans
- Token GitLab (`read_api` é suficiente) com acesso aos repositórios

> O `fcli` é baixado automaticamente caso não esteja disponível no `PATH`.

---

## Configuração

Crie um arquivo `.env` na raiz do repositório (nunca commitar este arquivo):

```dotenv
# Fortify on Demand
FOD_URL=https://api.ams.fortify.com
FOD_CLIENT_ID=<seu-client-id>
FOD_CLIENT_SECRET=<seu-client-secret>
FOD_APPLICATION_ID=<id-da-application-no-fod>

# GitLab
GITLAB_URL=https://gitlab.exemplo.com.br
GITLAB_TOKEN=<seu-token-privado-gitlab>

# Versão do fcli a baixar caso não esteja instalado
FCLI_VERSION=v3.14.3

# Opcional: desabilita validação de certificado SSL (ex.: bypass Netskope)
# FOD_INSECURE=true
```

| Variável | Obrigatória | Descrição |
| --- | --- | --- |
| `FOD_URL` | Sim | URL base da API do Fortify on Demand |
| `FOD_CLIENT_ID` | Sim | Client ID da conta de serviço FoD |
| `FOD_CLIENT_SECRET` | Sim | Client Secret da conta de serviço FoD |
| `FOD_APPLICATION_ID` | Sim | ID numérico da Application no FoD onde os releases serão criados |
| `GITLAB_TOKEN` | Sim | Personal/Project Access Token do GitLab |
| `GITLAB_URL` | Não | URL base do GitLab (informativo, não utilizado diretamente) |
| `FCLI_VERSION` | Sim | Versão do fcli a baixar (ex.: `v3.14.3`) |
| `FOD_INSECURE` | Não | `true` para desabilitar validação SSL (bypass de proxy TLS) |

---

## Uso

### Repositório único

```powershell
.\fortify-scan.ps1 https://gitlab.exemplo.com.br/grupo/meu-projeto.git
```

### Múltiplos repositórios na mesma execução

```powershell
.\fortify-scan.ps1 https://gitlab.exemplo.com.br/grupo/repo-a.git https://gitlab.exemplo.com.br/grupo/repo-b.git
```

### A partir de um arquivo de texto

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

---

## Estrutura de diretórios gerada

```text
.tools/     # fcli baixado automaticamente (ignorado pelo git)
.work/      # ZIPs dos repositórios gerados durante a execução (ignorado pelo git)
.env        # Variáveis de configuração (ignorado pelo git)
```

---

## Acompanhando os scans

Após a execução, acesse o FoD e navegue até a Application / Release correspondente ao nome do repositório para acompanhar o progresso dos scans SAST e SCA.
