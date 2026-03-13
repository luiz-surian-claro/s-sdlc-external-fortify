#!/usr/bin/env bash

set -euo pipefail

########################################
# VALIDAÇÃO DE PARÂMETROS
########################################

if [ "$#" -lt 6 ]; then
  echo "Uso: $0 <SOURCE_REPO> <DEST_GROUP_ID> <DEST_REPO_NAME> <BRANCH> <COMMIT> <PROJECT_ID> [SCANNERS]"
  echo "SCANNERS (opcional): lista separada por vírgula com 1 ou N ferramentas."
  echo "Exemplo: gitleaks,detect-secrets,trufflehog,gitguardian-shield,semgrep"
  exit 1
fi

SOURCE_REPO="$1"
DEST_GROUP_ID="$2"
DEST_REPO_NAME="$3"
BRANCH="$4"
COMMIT="$5"
PROJECT_ID="$6"
SCANNERS_INPUT="${7:-gitleaks,detect-secrets,trufflehog,gitguardian-shield}"

if [ -z "${GITLAB_TOKEN:-}" ]; then
  echo "Erro: variável GITLAB_TOKEN não definida."
  exit 1
fi

########################################
# CHECAGEM DE DEPENDÊNCIAS
########################################

for cmd in curl jq git syft sha256sum; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "Erro: O comando '$cmd' não foi encontrado. Instale-o antes de prosseguir."
    exit 1
  fi
done

########################################
# CONFIGURAÇÕES E VARIÁVEIS
########################################

GITLAB_API="https://gitlab.corp.clarobr/api/v4"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
TMP_ROOT="/e/tmp"
WORKDIR="$TMP_ROOT/git_delivery_${TIMESTAMP}"
TAG="snapshot-audit-${TIMESTAMP}"
SANITIZED_REPO_DIR="$WORKDIR/repo_sanitized"
SCANS_DIR="$WORKDIR/security_scans"
SCANNER_LOG_DIR="$SCANS_DIR/logs"
SCANNER_RESULT_DIR="$SCANS_DIR/results"
SCANNER_SUMMARY="$SCANS_DIR/scanner_summary_${TIMESTAMP}.txt"
REMOVED_FILES_LOG="$SCANS_DIR/removed_sensitive_files_${TIMESTAMP}.txt"
SEMGREP_JSON="$SCANNER_RESULT_DIR/semgrep.json"
SEMGREP_SARIF="$SCANNER_RESULT_DIR/semgrep.sarif"

LOGFILE="$WORKDIR/audit_delivery_${TIMESTAMP}.log"
METADATA="$WORKDIR/delivery_metadata_${TIMESTAMP}.txt"

EXECUTOR_USER=$(whoami)
EXECUTOR_HOST=$(hostname)
EXECUTOR_DATE=$(date -Iseconds)

mkdir -p "$TMP_ROOT"

if [ ! -d "$TMP_ROOT" ] || [ ! -w "$TMP_ROOT" ]; then
  echo "Erro: diretório base '$TMP_ROOT' não existe ou não possui permissão de escrita."
  exit 1
fi

cd "$TMP_ROOT"
export TMPDIR="$TMP_ROOT"

mkdir -p "$WORKDIR" "$SCANNER_LOG_DIR" "$SCANNER_RESULT_DIR"

sanitize_repo_files () {
  local target_dir="$1"

  echo "-> Removendo arquivos sensíveis (.env/chaves/certificados) do clone sanitizado..."
  : > "$REMOVED_FILES_LOG"

  while IFS= read -r file; do
    echo "$file" | tee -a "$REMOVED_FILES_LOG"
    rm -f "$file"
  done < <(
    find "$target_dir" -type f \( \
      -iname ".config" -o \
      -iname ".env" -o \
      -iname ".env.*" -o \
      -iname "*.env" -o \
      -iname "*.pem" -o \
      -iname "*.key" -o \
      -iname "*.p12" -o \
      -iname "*.pfx" -o \
      -iname "*.jks" -o \
      -iname "*.keystore" -o \
      -iname "id_rsa" -o \
      -iname "id_dsa" -o \
      -iname "id_ecdsa" -o \
      -iname "id_ed25519" \
    \)
  )

  if [ ! -s "$REMOVED_FILES_LOG" ]; then
    echo "Nenhum arquivo sensível por padrão foi encontrado para remoção." | tee -a "$REMOVED_FILES_LOG"
  else
    echo "Arquivos removidos registrados em: $REMOVED_FILES_LOG"
  fi
}

parse_scanners () {
  local raw="$1"
  raw="${raw,,}"
  raw="${raw// /,}"
  raw="${raw//;/,}"

  IFS=',' read -r -a parsed <<< "$raw"
  SELECTED_SCANNERS=()

  for scanner in "${parsed[@]}"; do
    case "$scanner" in
      gitleaks|trufflehog|detect-secrets|ggshield|semgrep)
        SELECTED_SCANNERS+=("$scanner")
        ;;
      gitguardian-shield|gitguardian|gitguardian_shield)
        SELECTED_SCANNERS+=("ggshield")
        ;;
      "")
        ;;
      *)
        echo "AVISO: Scanner '$scanner' não suportado e será ignorado."
        ;;
    esac
  done

  if [ "${#SELECTED_SCANNERS[@]}" -eq 0 ]; then
    echo "ERRO: Nenhum scanner válido selecionado. Use: gitleaks, trufflehog, detect-secrets, gitguardian-shield, semgrep"
    exit 1
  fi
}

run_secret_scanner () {
  local scanner="$1"
  local target_dir="$2"
  local status=0

  local stdout_file="$SCANNER_RESULT_DIR/${scanner}.out"
  local stderr_file="$SCANNER_LOG_DIR/${scanner}.log"

  echo "\n=== Scanner: $scanner ===" | tee -a "$SCANNER_SUMMARY"

  case "$scanner" in
    gitleaks)
      if ! command -v gitleaks &> /dev/null; then
        echo "STATUS: SKIPPED (comando gitleaks não encontrado)" | tee -a "$SCANNER_SUMMARY"
        return 0
      fi

      set +e
      gitleaks detect --source "$target_dir" --report-format json --report-path "$stdout_file" --redact --no-banner 2> "$stderr_file"
      local status=$?
      set -e

      local findings=0
      if [ -s "$stdout_file" ]; then
        findings=$(jq 'length' "$stdout_file" 2> /dev/null || echo 0)
      fi

      echo "STATUS: $status" | tee -a "$SCANNER_SUMMARY"
      echo "FINDINGS: $findings" | tee -a "$SCANNER_SUMMARY"
      if [ "$findings" -gt 0 ]; then
        echo "FILES:" | tee -a "$SCANNER_SUMMARY"
        jq -r '.[] | .File // empty' "$stdout_file" 2> /dev/null | sort -u | tee -a "$SCANNER_SUMMARY"
      fi
      ;;

    trufflehog)
      if ! command -v trufflehog &> /dev/null; then
        echo "STATUS: SKIPPED (comando trufflehog não encontrado)" | tee -a "$SCANNER_SUMMARY"
        return 0
      fi

      set +e
      trufflehog filesystem "$target_dir" --json > "$stdout_file" 2> "$stderr_file"
      local status=$?
      set -e

      local findings=0
      if [ -s "$stdout_file" ]; then
        findings=$(wc -l < "$stdout_file" | tr -d '[:space:]')
      fi

      echo "STATUS: $status" | tee -a "$SCANNER_SUMMARY"
      echo "FINDINGS: $findings" | tee -a "$SCANNER_SUMMARY"
      if [ "$findings" -gt 0 ]; then
        local trufflehog_files
        echo "FILES:" | tee -a "$SCANNER_SUMMARY"
        trufflehog_files=$(jq -r '
          .SourceMetadata?.Data?.Filesystem?.file //
          .SourceMetadata?.Data?.Filesystem?.path //
          .SourceMetadata?.Data?.Git?.file //
          .path //
          empty
        ' "$stdout_file" 2> /dev/null | sed 's#^\./##' | sort -u || true)

        if [ -n "$trufflehog_files" ]; then
          echo "$trufflehog_files" | tee -a "$SCANNER_SUMMARY"
        else
          echo "(Nenhum arquivo pôde ser extraído do output JSON do trufflehog)" | tee -a "$SCANNER_SUMMARY"
        fi
      fi
      ;;

    detect-secrets)
      if ! command -v detect-secrets &> /dev/null; then
        echo "STATUS: SKIPPED (comando detect-secrets não encontrado)" | tee -a "$SCANNER_SUMMARY"
        return 0
      fi

      set +e
      detect-secrets scan --all-files "$target_dir" > "$stdout_file" 2> "$stderr_file"
      local status=$?
      set -e

      local findings=0
      if [ -s "$stdout_file" ]; then
        findings=$(jq '[.results[] | length] | add // 0' "$stdout_file" 2> /dev/null || echo 0)
      fi

      echo "STATUS: $status" | tee -a "$SCANNER_SUMMARY"
      echo "FINDINGS: $findings" | tee -a "$SCANNER_SUMMARY"
      if [ "$findings" -gt 0 ]; then
        echo "FILES:" | tee -a "$SCANNER_SUMMARY"
        jq -r '.results | keys[]' "$stdout_file" 2> /dev/null | sort -u | tee -a "$SCANNER_SUMMARY"
      fi
      ;;

    ggshield)
      local ggshield_cmd=""
      if command -v ggshield &> /dev/null; then
        ggshield_cmd="ggshield"
      elif command -v ggshield.exe &> /dev/null; then
        ggshield_cmd="ggshield.exe"
      else
        echo "STATUS: SKIPPED (comando ggshield/ggshield.exe não encontrado)" | tee -a "$SCANNER_SUMMARY"
        return 0
      fi

      set +e
      "$ggshield_cmd" secret scan path "$target_dir" --json > "$stdout_file" 2> "$stderr_file"
      local status=$?
      set -e

      local findings=0
      if [ -s "$stdout_file" ]; then
        findings=$(jq '[.. | .filename? // empty] | length' "$stdout_file" 2> /dev/null || echo 0)
      fi

      echo "STATUS: $status" | tee -a "$SCANNER_SUMMARY"
      echo "FINDINGS: $findings" | tee -a "$SCANNER_SUMMARY"
      if [ "$findings" -gt 0 ]; then
        echo "FILES:" | tee -a "$SCANNER_SUMMARY"
        jq -r '.. | .filename? // empty' "$stdout_file" 2> /dev/null | sort -u | tee -a "$SCANNER_SUMMARY"
      fi
      ;;

    semgrep)
      if ! command -v semgrep &> /dev/null; then
        echo "STATUS: SKIPPED (comando semgrep não encontrado)" | tee -a "$SCANNER_SUMMARY"
        return 0
      fi

      set +e
      export PYTHONUTF8=1
      export PYTHONIOENCODING=utf-8
      semgrep scan \
        --config=p/default \
        --config=p/secrets \
        --config=p/ci \
        --config=p/docker \
        --config=p/kubernetes \
        --config=p/terraform \
        "$target_dir" \
        --json > "$SEMGREP_JSON" 2> "$stderr_file"
      local status_json=$?

      semgrep scan \
        --config=p/default \
        --config=p/secrets \
        --config=p/ci \
        --config=p/docker \
        --config=p/kubernetes \
        --config=p/terraform \
        "$target_dir" \
        --sarif > "$SEMGREP_SARIF" 2>> "$stderr_file"
      local status_sarif=$?
      set -e

      local status=0
      if [ "$status_json" -ne 0 ] || [ "$status_sarif" -ne 0 ]; then
        status=1
      fi

      local findings=0
      if [ -s "$SEMGREP_JSON" ]; then
        findings=$(jq '.results | length' "$SEMGREP_JSON" 2> /dev/null || echo 0)
      fi

      echo "STATUS: $status (json=$status_json sarif=$status_sarif)" | tee -a "$SCANNER_SUMMARY"
      echo "FINDINGS: $findings" | tee -a "$SCANNER_SUMMARY"
      echo "SEMGRP_JSON: $SEMGREP_JSON" | tee -a "$SCANNER_SUMMARY"
      echo "SEMGRP_SARIF: $SEMGREP_SARIF" | tee -a "$SCANNER_SUMMARY"
      if [ "$findings" -gt 0 ]; then
        echo "FILES:" | tee -a "$SCANNER_SUMMARY"
        jq -r '.results[]?.path // empty' "$SEMGREP_JSON" 2> /dev/null | sort -u | tee -a "$SCANNER_SUMMARY"
      fi
      ;;
  esac

  if [ "$status" -ne 0 ]; then
    echo "AVISO: scanner '$scanner' retornou código $status e a execução seguirá para o próximo scanner." | tee -a "$SCANNER_SUMMARY"
  fi
}

run_selected_scanners () {
  local target_dir="$1"

  parse_scanners "$SCANNERS_INPUT"

  echo "===== INÍCIO DA VARREDURA DE SEGREDOS =====" | tee -a "$SCANNER_SUMMARY"
  echo "Scanners selecionados: ${SELECTED_SCANNERS[*]}" | tee -a "$SCANNER_SUMMARY"
  echo "Diretório analisado: $target_dir" | tee -a "$SCANNER_SUMMARY"

  for scanner in "${SELECTED_SCANNERS[@]}"; do
    run_secret_scanner "$scanner" "$target_dir"
  done

  echo "===== FIM DA VARREDURA DE SEGREDOS =====" | tee -a "$SCANNER_SUMMARY"
}

########################################
# CONFIGURAÇÃO GLOBAL DE LOG
########################################
exec > >(tee -i "$LOGFILE") 2>&1

echo "===== INÍCIO DA ENTREGA PARA AUDITORIA ====="
echo "Executor: $EXECUTOR_USER"
echo "Host: $EXECUTOR_HOST"
echo "Data: $EXECUTOR_DATE"
echo "Diretório Base TMP: $TMP_ROOT"
echo "Diretório de Trabalho: $WORKDIR"
echo "Scanners selecionados: $SCANNERS_INPUT"

########################################
# CRIAR REPOSITÓRIO AUDITORIA
########################################
echo "-> Criando repositório de auditoria no GitLab..."

REPO_RESPONSE=$(curl -k --silent --show-error \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --data "name=$DEST_REPO_NAME&namespace_id=$DEST_GROUP_ID&visibility=private" \
  --request POST \
  "$GITLAB_API/projects")

DEST_REPO_URL=$(echo "$REPO_RESPONSE" | jq -r '.http_url_to_repo // empty')
DEST_PROJECT_ID=$(echo "$REPO_RESPONSE" | jq -r '.id // empty')

if [ -z "$DEST_REPO_URL" ]; then
  echo "ERRO: Falha ao criar repositório. Resposta da API:"
  echo "$REPO_RESPONSE" | jq .
  exit 1
fi

echo "-> Repositório criado com sucesso: $DEST_REPO_URL"

########################################
# CLONE E CHECKOUT
########################################
echo "-> Clonando repositório de origem..."

cd "$WORKDIR"
git clone "$SOURCE_REPO" repo
cd repo

git fetch --all --tags
git checkout "$BRANCH"

########################################
# VALIDAR COMMIT
########################################
echo "-> Validando a existência do commit na branch..."

git cat-file -e "$COMMIT^{commit}"

if ! git merge-base --is-ancestor "$COMMIT" "$BRANCH"; then
  echo "ERRO: O Commit informado não pertence ao histórico da branch '$BRANCH'."
  exit 1
fi

TREE_HASH=$(git show -s --format=%T "$COMMIT")
echo "-> Tree Hash capturado: $TREE_HASH"

########################################
# TAG NO REPO ORIGEM
########################################
echo "-> Marcando origem..."

TAG_MSG="Snapshot auditoria $TIMESTAMP
Commit original: $COMMIT
Tree Hash: $TREE_HASH
Consulte a Release correspondente no GitLab para o manual de auditoria e download dos artefatos imutáveis (Bundle, SBOM, Metadata)."

git tag -a "$TAG" "$COMMIT" -m "$TAG_MSG"
git push origin "$TAG"

########################################
# CLONE SANITIZADO + LIMPEZA + SCANNERS
########################################
echo "-> Criando clone sanitizado para auditoria..."

cd "$WORKDIR"
git clone --no-hardlinks repo "$SANITIZED_REPO_DIR"
cd "$SANITIZED_REPO_DIR"

git checkout "$COMMIT"
sanitize_repo_files "$SANITIZED_REPO_DIR"
run_selected_scanners "$SANITIZED_REPO_DIR"

########################################
# HISTÓRICO LIMPO (ORPHAN) E PUSH DESTINO
########################################
echo "-> Reescrevendo histórico para branch limpa de auditoria..."

git checkout --orphan clean-history
git add -A

if git diff --cached --quiet; then
  echo "ERRO: Após sanitização, não há conteúdo para commit no repositório de auditoria."
  exit 1
fi

git commit -m "Initial sanitized commit for audit (${COMMIT})"
git branch -M "$BRANCH"

SANITIZED_COMMIT=$(git rev-parse HEAD)
SANITIZED_TREE_HASH=$(git show -s --format=%T "$SANITIZED_COMMIT")

if git rev-parse -q --verify "refs/tags/$TAG" > /dev/null; then
  git tag -d "$TAG"
fi

git tag -a "$TAG" "$SANITIZED_COMMIT" -m "Snapshot sanitizado para auditoria\nCommit original: $COMMIT\nTree hash original: $TREE_HASH\nTree hash sanitizado: $SANITIZED_TREE_HASH"

git remote add auditoria "$DEST_REPO_URL"
git push auditoria "$BRANCH" --force
git push auditoria "$TAG" --force

cd .. # Volta para WORKDIR

########################################
# GERAÇÃO DE ARTEFATOS (SNAPSHOT, BUNDLE, SBOM)
########################################
echo "-> Gerando arquivos de auditoria imutáveis..."

git -C repo_sanitized archive --format=tar.gz -o "$WORKDIR/snapshot_${TAG}.tar.gz" "$SANITIZED_COMMIT"
git -C repo_sanitized bundle create "$WORKDIR/repo_${TAG}.bundle" "$TAG"

SYFT_PROJECT_NAME="$DEST_REPO_NAME" SYFT_PROJECT_VERSION="$TAG" syft dir:repo_sanitized -o cyclonedx-json > "$WORKDIR/sbom_${TAG}.json"

########################################
# HASHES E METADATA
########################################
echo "-> Calculando Hashes criptográficos e gerando Metadata..."

SNAPSHOT_SHA=$(sha256sum "$WORKDIR/snapshot_${TAG}.tar.gz" | awk '{print $1}')
BUNDLE_SHA=$(sha256sum "$WORKDIR/repo_${TAG}.bundle" | awk '{print $1}')
SBOM_SHA=$(sha256sum "$WORKDIR/sbom_${TAG}.json" | awk '{print $1}')

cat <<EOF > "$METADATA"
=== RELATÓRIO DE ENTREGA DE CÓDIGO FONTE ===
Source Repository: $SOURCE_REPO
Destination Repository: $DEST_REPO_URL
Branch: $BRANCH
Commit Original: $COMMIT
Tree Hash Original: $TREE_HASH
Commit Entregue (Sanitizado): $SANITIZED_COMMIT
Tree Hash Entregue (Sanitizado): $SANITIZED_TREE_HASH
Tag Auditoria: $TAG
Relatório Scanners: $SCANNER_SUMMARY
Arquivos Sensíveis Removidos: $REMOVED_FILES_LOG

=== DADOS DA EXECUÇÃO ===
Executor User: $EXECUTOR_USER
Executor Host: $EXECUTOR_HOST
Execution Date: $EXECUTOR_DATE

=== INTEGRIDADE DOS ARTEFATOS (SHA256) ===
Snapshot SHA256: $SNAPSHOT_SHA
Bundle SHA256: $BUNDLE_SHA
SBOM SHA256: $SBOM_SHA
EOF

########################################
# ASSINATURA DO METADATA (GPG/SSH)
########################################
echo "-> Verificando chave de assinatura do Git..."

SIGNING_KEY=$(git config --global --get user.signingkey || git config --get user.signingkey || true)
SIGNING_FORMAT=$(git config --global --get gpg.format || git config --get gpg.format || echo "gpg")

if [ -z "$SIGNING_KEY" ]; then
  echo "AVISO: Nenhuma chave configurada no Git. O metadata não será assinado."
else
  if [ "$SIGNING_FORMAT" = "ssh" ]; then
    echo "-> Assinando metadata com chave SSH do Git ($SIGNING_KEY)..."
    if ssh-keygen -Y sign -n file -f "$SIGNING_KEY" "$METADATA"; then
      mv "${METADATA}.sig" "${METADATA}.asc"
    else
      echo "AVISO: Falha ao usar a chave SSH. A entrega continuará sem assinatura."
    fi
  else
    echo "-> Assinando metadata com chave GPG do Git ($SIGNING_KEY)..."
    if ! gpg --local-user "$SIGNING_KEY" --armor --detach-sign "$METADATA"; then
      echo "AVISO: Falha ao assinar com a chave $SIGNING_KEY (chave privada não encontrada)."
      echo "A entrega continuará sem a assinatura GPG do metadata."
    fi
  fi
fi

########################################
# CRIAR RELEASE NO GITLAB (COM MANUAL)
########################################
echo "-> Criando Release no projeto de origem (ID: $PROJECT_ID) com manual de auditoria..."

RELEASE_NOTES=$(cat <<EOF
# 🛡️ Relatório e Manual de Auditoria - Entrega auditoria

Este snapshot foi gerado automaticamente por script para fins de auditoria e compliance.
O código contido nesta release reflete a **exata estrutura** entregue à auditoria.

## 🔍 Como auditar em caso de vazamento?

Se ocorrer um vazamento de código e houver necessidade de perícia, siga os passos abaixo para comprovar a origem:

### 1. A Prova Definitiva (Tree Hash)
O **Tree Hash** representa a estrutura exata e o conteúdo de todos os arquivos no momento da extração.
- **Tree Hash Registrado:** \`${SANITIZED_TREE_HASH}\`
- Se o código vazado for inicializado em um repositório Git limpo, o Tree Hash gerado deverá bater exatamente com o hash acima. Comando para checar no código periciado: \`git show -s --format=%T HEAD\`

### 2. Restauração via Bundle
Esta release contém um arquivo \`.bundle\`, que é um backup offline completo e criptograficamente seguro do histórico até o momento da entrega.
Para inspecionar o código entregue:
\`\`\`bash
git clone repo_${TAG}.bundle repo_auditoria
cd repo_auditoria
git log
\`\`\`

### 3. Validação de Integridade e SBOM
Faça o download do arquivo \`delivery_metadata_${TIMESTAMP}.txt\` (e sua assinatura \`.asc\`).
Ele contém os hashes SHA256 do Snapshot (tar.gz), do Bundle e do SBOM.

---
**Informações da Execução:**
- **Data:** ${EXECUTOR_DATE}
- **Executor:** ${EXECUTOR_USER}
- **Host:** ${EXECUTOR_HOST}
EOF
)

PAYLOAD_FILE="$WORKDIR/release_payload.json"
jq -n \
  --arg name "$TAG" \
  --arg tag_name "$TAG" \
  --arg description "$RELEASE_NOTES" \
  '{name: $name, tag_name: $tag_name, description: $description}' > "$PAYLOAD_FILE"

RELEASE_RESPONSE=$(curl -k --silent --show-error -w "\nHTTP_STATUS:%{http_code}" \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --header "Content-Type: application/json" \
  --data @"$PAYLOAD_FILE" \
  --request POST \
  "$GITLAB_API/projects/$PROJECT_ID/releases")

echo "   [Resposta da API - Criação da Release]:"
echo "$RELEASE_RESPONSE"

########################################
# VALIDAÇÃO DO PACKAGE REGISTRY
########################################
echo "-> Verificando status do Package Registry no projeto de origem (ID: $PROJECT_ID)..."

PROJECT_INFO=$(curl -k --silent --header "PRIVATE-TOKEN: $GITLAB_TOKEN" "$GITLAB_API/projects/$PROJECT_ID")

# Captura o nível de acesso atual (suporta a API moderna e a legada)
PKG_ACCESS=$(echo "$PROJECT_INFO" | jq -r '.packages_and_registries_access_level // .packages_enabled // empty')

if [ "$PKG_ACCESS" = "disabled" ] || [ "$PKG_ACCESS" = "false" ]; then
  echo "   [!] Package Registry está desabilitado. Habilitando via API..."
  
  ENABLE_PKG_RESPONSE=$(curl -k --silent --show-error -w "\nHTTP_STATUS:%{http_code}" \
    --request PUT \
    --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
    --data "packages_and_registries_access_level=enabled" \
    "$GITLAB_API/projects/$PROJECT_ID")
    
  if ! echo "$ENABLE_PKG_RESPONSE" | grep -q "HTTP_STATUS:200"; then
    echo "   ERRO: Falha ao habilitar o Package Registry automaticamente."
    echo "   Resposta da API: $ENABLE_PKG_RESPONSE"
    echo "   Dica: Você precisa ter nível de 'Maintainer' no projeto de origem para alterar configurações."
    exit 1
  fi
  echo "   [✓] Package Registry habilitado com sucesso!"
else
  echo "   [✓] Package Registry já está habilitado para este projeto."
fi

########################################
# UPLOAD DE ARTEFATOS (PACKAGE REGISTRY)
########################################
echo "-> Fazendo upload dos artefatos para o Generic Package Registry..."

# A versão precisa ser X.Y.Z. Usamos o Timestamp Unix (%s) para ser sempre único
PKG_NAME="auditoria-$TIMESTAMP"
PKG_VERSION="1.0.$(date +%s)"

# Essa é a URL base previsível e definitiva do seu pacote
PKG_BASE_URL="$GITLAB_API/projects/$PROJECT_ID/packages/generic/$PKG_NAME/$PKG_VERSION"

upload_asset () {
  local FILE=$1
  local BASENAME=$(basename "$FILE")
  
  echo "   Fazendo upload seguro de: $BASENAME..."
  
  # O Generic Package Registry usa PUT (--upload-file) para arquivos pesados
  UPLOAD_RESPONSE=$(curl -k --silent --show-error -w "\nHTTP_STATUS:%{http_code}" \
    --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
    --upload-file "$FILE" \
    "$PKG_BASE_URL/$BASENAME")
  
  # Checa se o status HTTP contém 201 (Created) ou 200 (OK)
  if ! echo "$UPLOAD_RESPONSE" | grep -q "HTTP_STATUS:20"; then
     echo "   ERRO no upload de $BASENAME. Resposta da API:"
     echo "$UPLOAD_RESPONSE"
     return 1
  fi
  
  # A URL de download agora é a própria URL do pacote
  FILE_URL="$PKG_BASE_URL/$BASENAME"
  
  echo "   Anexando $BASENAME na Release $TAG como Pacote..."
  
  # Usamos link_type "package" para ficar agrupado visualmente de forma correta
  LINK_PAYLOAD=$(jq -n \
    --arg name "$BASENAME" \
    --arg url "$FILE_URL" \
    --arg link_type "package" \
    '{
      name: $name, 
      url: $url, 
      link_type: $link_type
    }')
  
  LINK_RESPONSE=$(curl -k --silent -w "\nHTTP_STATUS:%{http_code}" \
    --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
    --header "Content-Type: application/json" \
    --data "$LINK_PAYLOAD" \
    --request POST \
    "$GITLAB_API/projects/$PROJECT_ID/releases/$TAG/assets/links")
    
  echo "   [Resposta da API - Anexo]:"
  echo "$LINK_RESPONSE"
}

upload_asset "$WORKDIR/snapshot_${TAG}.tar.gz"
upload_asset "$WORKDIR/repo_${TAG}.bundle"
upload_asset "$WORKDIR/sbom_${TAG}.json"
upload_asset "$METADATA"
upload_asset "$SCANNER_SUMMARY"
upload_asset "$REMOVED_FILES_LOG"

if [ -f "$SEMGREP_JSON" ]; then
  upload_asset "$SEMGREP_JSON"
fi

if [ -f "$SEMGREP_SARIF" ]; then
  upload_asset "$SEMGREP_SARIF"
fi

if [ -f "${METADATA}.asc" ]; then
  upload_asset "${METADATA}.asc"
fi


########################################
# PROTEGER A TAG (BLOQUEIO DE DELEÇÃO)
########################################
echo "-> Aplicando regra de segurança: Protegendo a Tag contra deleção..."

# Protege a tag definindo que "Ninguém" (access_level: 0) tem permissão para 
# recriá-la ou movê-la, e bloqueando a deleção padrão.
PROTECT_PAYLOAD=$(jq -n \
  --arg name "$TAG" \
  --argjson create_access_level 0 \
  '{name: $name, create_access_level: $create_access_level}')

PROTECT_RESPONSE=$(curl -k --silent --show-error -w "\nHTTP_STATUS:%{http_code}" \
  --request POST \
  --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  --header "Content-Type: application/json" \
  --data "$PROTECT_PAYLOAD" \
  "$GITLAB_API/projects/$PROJECT_ID/protected_tags")

if echo "$PROTECT_RESPONSE" | grep -q "HTTP_STATUS:201\|HTTP_STATUS:200"; then
  echo "   [✓] Tag '$TAG' protegida com sucesso!"
  echo "       Apenas usuários avançados via painel de configurações podem desproteger para apagar."
elif echo "$PROTECT_RESPONSE" | grep -q "already exists"; then
  echo "   [✓] A regra de proteção para '$TAG' já existe."
else
  echo "   [!] AVISO: Não foi possível proteger a tag via API. Resposta:"
  echo "$PROTECT_RESPONSE"
fi

########################################
# FINALIZAÇÃO
########################################
echo "===== ENTREGA FINALIZADA COM SUCESSO ====="
echo "Diretório com os arquivos mantidos localmente (para backup da auditoria):"
ls -lh "$WORKDIR"
