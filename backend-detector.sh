#!/bin/bash
# backend-detector.sh
# Classifica repositórios da organização como backend ou não,
# com base em arquivos de manifesto e dependências específicas por linguagem.
#
# Melhorias aplicadas:
#   - Fix: parsing de CRITERIA (bug de array em string)
#   - Fix: compatibilidade de data com macOS (date -d → python3)
#   - Fix: relatório salvo dentro de $OUTPUT_DIR
#   - Add: rate limit handling com backoff automático
#   - Add: log de qual dependência classificou o repo como backend
#   - Add: timestamp e metadados no relatório
#   - Add: guard contra lista de repos vazia por linguagem

set -euo pipefail

# ---------------------------------------------------------------------------
# Configurações
# ---------------------------------------------------------------------------
ORG="will-bank"
OUTPUT_DIR="reports"
REPORT_FILE="$OUTPUT_DIR/backend-detector-report.txt"
RATE_LIMIT_THRESHOLD=50   # requisições restantes antes de aguardar reset

# Data de corte: 2 anos atrás — compatível com Linux e macOS
CUTOFF_DATE=$(python3 -c "from datetime import date, timedelta; print((date.today() - timedelta(days=730)).isoformat())")

LANGUAGES="${1:-javascript go typescript rust java python}"

mkdir -p "$OUTPUT_DIR"
> "$REPORT_FILE"   # limpa o relatório anterior

# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------

print_report() {
  for msg in "$@"; do
    echo -e "$msg" | tee -a "$REPORT_FILE"
  done
}

# Verifica o rate limit da API do GitHub e aguarda se necessário
check_rate_limit() {
  local REMAINING
  local RESET
  local SLEEP_SEC

  REMAINING=$(gh api rate_limit --jq '.rate.remaining' 2>/dev/null || echo "999")

  if [[ "$REMAINING" -lt "$RATE_LIMIT_THRESHOLD" ]]; then
    RESET=$(gh api rate_limit --jq '.rate.reset' 2>/dev/null || echo "0")
    SLEEP_SEC=$(( RESET - $(date +%s) + 5 ))
    if [[ "$SLEEP_SEC" -gt 0 ]]; then
      print_report "⏳ Rate limit baixo (${REMAINING} req restantes). Aguardando ${SLEEP_SEC}s..."
      sleep "$SLEEP_SEC"
    fi
  fi
}

# Retorna: "<arquivo(s)_manifesto separados por |> <dep1> <dep2> ..."
# O primeiro token (antes do espaço) contém o(s) arquivo(s); o resto são deps.
get_criteria() {
  case "$1" in
    "javascript")
      echo "package.json express fastify @nestjs/core koa @hapi/hapi @will-bank/willauth-sdk"
      ;;
    "go")
      echo "go.mod gin gorm github.com/labstack/echo github.com/gofiber/fiber"
      ;;
    "typescript")
      echo "package.json express fastify @nestjs/core nestjs @hapi/hapi @will-bank/willauth-sdk"
      ;;
    "rust")
      echo "Cargo.toml actix-web rocket warp axum willauth-sdk"
      ;;
    "java")
      echo "pom.xml|build.gradle spring-boot jakarta-ee quarkus-arc"
      ;;
    "python")
      echo "requirements.txt|pyproject.toml flask django fastapi"
      ;;
    *)
      echo ""
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Cabeçalho do relatório
# ---------------------------------------------------------------------------
RUN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
print_report "REPORT: BACKEND REPOS CLASSIFICATION"
print_report "====================================="
print_report "Timestamp : $RUN_TIMESTAMP"
print_report "Org       : $ORG"
print_report "Cutoff    : $CUTOFF_DATE"
print_report "Linguagens: $LANGUAGES"
print_report "Run ID    : ${GITHUB_RUN_ID:-local}"
print_report "====================================="

# ---------------------------------------------------------------------------
# Loop principal por linguagem
# ---------------------------------------------------------------------------
for LANG in $LANGUAGES; do
  print_report "\n🔍 Analisando repositórios de $LANG..."

  BACKEND_FILE="$OUTPUT_DIR/${LANG}_backend.txt"
  NON_BACKEND_FILE="$OUTPUT_DIR/${LANG}_non_backend.txt"

  echo "# Backends $LANG | gerado em $RUN_TIMESTAMP" > "$BACKEND_FILE"
  echo "# Não Backends $LANG | gerado em $RUN_TIMESTAMP" > "$NON_BACKEND_FILE"

  # --- Busca repos da linguagem com data de corte ---
  check_rate_limit
  set +e
  REPOS=$(gh repo list "$ORG" --no-archived --source -l "$LANG" --limit 2000 \
    --json "name,pushedAt" \
    -q ".[] | select(.pushedAt >= \"$CUTOFF_DATE\") | .name" 2>&1)
  GH_STATUS=$?
  set -e

  if [[ $GH_STATUS -ne 0 ]]; then
    echo "ERROR ao listar repos de $LANG: $REPOS" | tee -a workflow_errors.log
    exit $GH_STATUS
  fi

  if [[ -z "$REPOS" ]]; then
    print_report "  ⚠️  Nenhum repositório $LANG encontrado após o cutoff $CUTOFF_DATE. Pulando."
    continue
  fi

  # --- Fix: parsing correto de CRITERIA ---
  # get_criteria retorna: "arquivo(s)|separados|por|pipe dep1 dep2 dep3 ..."
  # Primeiro campo = manifesto(s), restante = dependências
  CRITERIA_STR=$(get_criteria "$LANG")
  read -ra CRITERIA_PARTS <<< "$CRITERIA_STR"
  MANIFEST_FIELD="${CRITERIA_PARTS[0]}"
  IFS='|' read -ra FILES <<< "$MANIFEST_FIELD"
  DEPS=("${CRITERIA_PARTS[@]:1}")

  TOTAL=0
  BACKENDS=0
  REPOS_SIZE=$(echo "$REPOS" | wc -l)

  for REPO in $REPOS; do
    TOTAL=$(( TOTAL + 1 ))
    echo "> $TOTAL / $REPOS_SIZE — $REPO"

    IS_BACKEND=0
    MATCHED_DEP=""
    MATCHED_FILE=""

    for FILE in "${FILES[@]}"; do
      check_rate_limit

      set +e
      CONTENT=$(gh api -X GET \
        -H "Accept: application/vnd.github.v3.raw" \
        "/repos/$ORG/$REPO/contents/$FILE" 2>&1)
      GH_STATUS=$?
      set -e

      if [[ $GH_STATUS -eq 0 ]]; then
        for DEP in "${DEPS[@]}"; do
          # Busca exata (quoted) e parcial (unquoted) para cobrir diferentes formatos de manifesto
          if grep -q -i "\"$DEP\"" <<< "$CONTENT" || grep -q -i "$DEP" <<< "$CONTENT"; then
            IS_BACKEND=1
            MATCHED_DEP="$DEP"
            MATCHED_FILE="$FILE"
            break 2
          fi
        done
      elif [[ "$CONTENT" != *"404"* && "$CONTENT" != *"Not Found"* ]]; then
        echo "ERROR: $CONTENT" | tee -a workflow_errors.log
        exit $GH_STATUS
      fi
    done

    if [[ $IS_BACKEND -eq 1 ]]; then
      echo "$REPO" >> "$BACKEND_FILE"
      BACKENDS=$(( BACKENDS + 1 ))
      print_report "  ✅ BACKEND: $REPO (dep: $MATCHED_DEP em $MATCHED_FILE)"
    else
      echo "$REPO" >> "$NON_BACKEND_FILE"
    fi
  done

  print_report "  📊 Total repos $LANG : $TOTAL"
  print_report "  📊 Backends         : $BACKENDS"
  print_report "  📊 Não backends     : $(( TOTAL - BACKENDS ))"
  print_report "  💾 Backend list     : $BACKEND_FILE"
  print_report "  💾 Non-backend list : $NON_BACKEND_FILE"
done

print_report "\n🏁 Classificação concluída. Arquivos em $OUTPUT_DIR/"
