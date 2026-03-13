#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# fortify-scan.sh
# Script para clonar repositórios GitLab, empacotar em .zip e submeter
# scan SAST/SCA ao Fortify on Demand via fcli.
#
# Uso:
#   ./fortify-scan.sh <repo1> [repo2] [repo3] ...
#
# Exemplos:
#   ./fortify-scan.sh https://gitlab.corp.clarobr/grupo/meu-projeto.git
#   ./fortify-scan.sh repo1.git repo2.git repo3.git
#   ./fortify-scan.sh repos.txt   (arquivo com um repo por linha)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
TOOLS_DIR="${SCRIPT_DIR}/.tools"
WORK_DIR="${SCRIPT_DIR}/.work"

# ============================================================================
# FUNÇÕES AUXILIARES
# ============================================================================

log_info()  { echo "[INFO]  $*"; }
log_warn()  { echo "[WARN]  $*"; }
log_error() { echo "[ERROR] $*" >&2; }
log_step()  { echo ""; echo "════════════════════════════════════════════════════════════════"; echo "  $*"; echo "════════════════════════════════════════════════════════════════"; }

cleanup() {
  log_info "Encerrando sessão FoD..."
  "${FCLI}" fod session logout 2>/dev/null || true
}

# ============================================================================
# CARREGAR .env
# ============================================================================

if [ ! -f "${ENV_FILE}" ]; then
  log_error "Arquivo .env não encontrado em: ${ENV_FILE}"
  log_error "Crie o arquivo .env com as variáveis FOD_URL, FOD_CLIENT_ID, FOD_CLIENT_SECRET, GITLAB_URL, GITLAB_TOKEN, FOD_APPLICATION_ID, FCLI_VERSION"
  exit 1
fi

set -a
# shellcheck source=/dev/null
source "${ENV_FILE}"
set +a

# Validar variáveis obrigatórias
REQUIRED_VARS="FOD_URL FOD_CLIENT_ID FOD_CLIENT_SECRET FOD_APPLICATION_ID GITLAB_TOKEN FCLI_VERSION"
MISSING=""
for var in $REQUIRED_VARS; do
  eval val=\${$var:-}
  if [ -z "$val" ]; then
    MISSING="${MISSING} ${var}"
  fi
done
if [ -n "$MISSING" ]; then
  log_error "Variáveis obrigatórias não definidas no .env:${MISSING}"
  exit 1
fi

# ============================================================================
# VALIDAR PARÂMETROS
# ============================================================================

if [ "$#" -lt 1 ]; then
  echo "Uso: $0 <repo_url | arquivo_com_repos> [repo_url2] [repo_url3] ..."
  echo ""
  echo "  repo_url              URL do repositório GitLab (HTTPS)"
  echo "  arquivo_com_repos     Arquivo de texto com uma URL por linha"
  exit 1
fi

# Montar lista de repositórios: suporta arquivo ou argumentos diretos
REPOS=()
for arg in "$@"; do
  if [ -f "$arg" ]; then
    while IFS= read -r line; do
      line="$(echo "$line" | sed 's/#.*//;s/^[[:space:]]*//;s/[[:space:]]*$//')"
      [ -n "$line" ] && REPOS+=("$line")
    done < "$arg"
  else
    REPOS+=("$arg")
  fi
done

if [ "${#REPOS[@]}" -eq 0 ]; then
  log_error "Nenhum repositório fornecido."
  exit 1
fi

log_info "Repositórios a processar (${#REPOS[@]}):"
for r in "${REPOS[@]}"; do
  echo "  - $r"
done

# ============================================================================
# INSTALAR / LOCALIZAR fcli
# ============================================================================

log_step "Preparando fcli"

mkdir -p "${TOOLS_DIR}" "${WORK_DIR}"

FCLI=""
if command -v fcli &>/dev/null; then
  FCLI="$(command -v fcli)"
  log_info "fcli encontrado no PATH: ${FCLI}"
elif [ -f "${TOOLS_DIR}/fcli" ]; then
  FCLI="${TOOLS_DIR}/fcli"
  log_info "fcli encontrado em: ${FCLI}"
else
  log_info "fcli não encontrado. Baixando versão ${FCLI_VERSION}..."

  FCLI_BASE_URL="https://github.com/fortify/fcli/releases/download/${FCLI_VERSION}"

  # Detectar SO
  OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "${OS}" in
    linux*)  FCLI_TGZ="fcli-linux.tgz"  ;;
    darwin*) FCLI_TGZ="fcli-mac.tgz"    ;;
    mingw*|msys*|cygwin*) FCLI_TGZ="fcli-windows.zip" ;;
    *)
      log_error "SO não suportado: ${OS}"
      exit 1
      ;;
  esac

  FCLI_DOWNLOAD_URL="${FCLI_BASE_URL}/${FCLI_TGZ}"

  curl -fsSL -o "${TOOLS_DIR}/${FCLI_TGZ}" "${FCLI_DOWNLOAD_URL}"

  case "${FCLI_TGZ}" in
    *.tgz)
      tar -zxvOf "${TOOLS_DIR}/${FCLI_TGZ}" fcli > "${TOOLS_DIR}/fcli"
      chmod a+x "${TOOLS_DIR}/fcli"
      ;;
    *.zip)
      unzip -o "${TOOLS_DIR}/${FCLI_TGZ}" fcli.exe -d "${TOOLS_DIR}/"
      ;;
  esac

  FCLI="${TOOLS_DIR}/fcli"
  log_info "fcli instalado em: ${FCLI}"
fi

"${FCLI}" -V

# ============================================================================
# LOGIN NO FORTIFY ON DEMAND
# ============================================================================

log_step "Conectando ao Fortify on Demand"

set +x
if ! "${FCLI}" fod session login \
  --url "${FOD_URL}" \
  --client-id "${FOD_CLIENT_ID}" \
  --client-secret "${FOD_CLIENT_SECRET}"; then
  log_error "Falha ao conectar com Fortify on Demand"
  exit 1
fi
set -x

trap cleanup EXIT
log_info "Conectado ao FoD com sucesso"

# ============================================================================
# PROCESSAR CADA REPOSITÓRIO
# ============================================================================

extract_repo_name() {
  local url="$1"
  local name
  name="$(basename "$url" .git)"
  echo "$name"
}

get_or_create_release() {
  local release_name="$1"
  local release_id=""

  log_info "Verificando se release '${release_name}' já existe na application ${FOD_APPLICATION_ID}..."

  # Tentar obter o release existente
  release_id=$("${FCLI}" fod release list \
    --app "${FOD_APPLICATION_ID}" \
    --query "releaseName=='${release_name}'" \
    --output expr="{releaseId}" 2>/dev/null | head -1 | tr -d '[:space:]') || true

  if [ -n "${release_id}" ] && [ "${release_id}" != "No" ] && [ "${release_id}" != "(null)" ] && echo "${release_id}" | grep -qE '^[0-9]+$'; then
    log_info "Release existente encontrado: ID=${release_id}"
    echo "${release_id}"
    return 0
  fi

  log_info "Release não encontrado. Criando release '${release_name}'..."

  "${FCLI}" fod release create "${release_name}" \
    --app "${FOD_APPLICATION_ID}" \
    --sdlc-status Development \
    --store new_release

  release_id=$("${FCLI}" fod release get ::new_release:: \
    --output expr="{releaseId}" 2>/dev/null | head -1 | tr -d '[:space:]') || true

  if [ -z "${release_id}" ] || ! echo "${release_id}" | grep -qE '^[0-9]+$'; then
    log_error "Falha ao obter ID do release criado para '${release_name}'"
    return 1
  fi

  log_info "Release criado com sucesso: ID=${release_id}"
  echo "${release_id}"
}

for REPO_URL in "${REPOS[@]}"; do
  REPO_NAME="$(extract_repo_name "$REPO_URL")"
  REPO_WORK="${WORK_DIR}/${REPO_NAME}"
  ZIP_FILE="${WORK_DIR}/${REPO_NAME}.zip"

  log_step "Processando: ${REPO_NAME}"

  # ========================================================================
  # 1. Clonar repositório
  # ========================================================================

  log_info "Clonando ${REPO_URL}..."

  rm -rf "${REPO_WORK}"

  # Inserir token na URL para autenticação (se HTTPS)
  AUTH_URL="${REPO_URL}"
  if echo "${REPO_URL}" | grep -qE '^https?://'; then
    AUTH_URL="$(echo "${REPO_URL}" | sed "s|://|://oauth2:${GITLAB_TOKEN}@|")"
  fi

  if ! git clone --depth 1 "${AUTH_URL}" "${REPO_WORK}" 2>&1; then
    log_error "Falha ao clonar ${REPO_URL}. Pulando..."
    continue
  fi

  log_info "Repositório clonado com sucesso"

  # ========================================================================
  # 2. Compactar em .zip
  # ========================================================================

  log_info "Compactando código-fonte em ${REPO_NAME}.zip..."

  rm -f "${ZIP_FILE}"

  cd "${REPO_WORK}"
  zip -r "${ZIP_FILE}" . \
    -x ".git/*" \
    -x "*/node_modules/*" \
    -x "*/target/*" \
    -x "*/build/*" \
    -x "*/dist/*" \
    -x "*/bin/*" \
    -x "*/obj/*" \
    -x "*/.gradle/*" \
    -x "*/.mvn/*" \
    -x "*/venv/*" \
    -x "*/__pycache__/*" \
    -x "*.pyc" \
    -x "*.class" \
    -x "*.log"
  cd "${SCRIPT_DIR}"

  ZIP_SIZE=$(du -h "${ZIP_FILE}" | cut -f1)
  log_info "Pacote gerado: ${ZIP_FILE} (${ZIP_SIZE})"

  # ========================================================================
  # 3. Obter ou criar release no FoD
  # ========================================================================

  RELEASE_ID="$(get_or_create_release "${REPO_NAME}")"

  if [ -z "${RELEASE_ID}" ]; then
    log_error "Não foi possível obter/criar release para '${REPO_NAME}'. Pulando..."
    continue
  fi

  # ========================================================================
  # 4. Iniciar scan SAST + SCA
  # ========================================================================

  log_info "Iniciando scan SAST no release ${RELEASE_ID}..."

  "${FCLI}" fod sast-scan start \
    --release "${RELEASE_ID}" \
    --file "${ZIP_FILE}" \
    --store "sast_scan_${REPO_NAME}"

  log_info "Scan SAST iniciado com sucesso para ${REPO_NAME}"

  log_info "Aguardando conclusão do scan SAST..."
  if "${FCLI}" fod sast-scan wait-for "::sast_scan_${REPO_NAME}::"; then
    log_info "Scan SAST concluído para ${REPO_NAME}"
  else
    log_warn "Timeout aguardando scan SAST de ${REPO_NAME}"
    log_info "Acompanhe em: ${FOD_URL}/Redirect/Releases/${RELEASE_ID}"
  fi

  # Limpeza do clone
  rm -rf "${REPO_WORK}"

  log_info "Processamento de ${REPO_NAME} finalizado"
done

# ============================================================================
# RESUMO
# ============================================================================

log_step "Resumo da execução"

log_info "Repositórios processados: ${#REPOS[@]}"
log_info "Application ID: ${FOD_APPLICATION_ID} (CNPJ-ALPHA)"
log_info "ZIPs gerados em: ${WORK_DIR}/"
log_info "Para acompanhar os scans, acesse: ${FOD_URL}"

echo ""
log_info "Execução finalizada com sucesso"
