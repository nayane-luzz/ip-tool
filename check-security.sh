#!/bin/bash
# check-security.sh
# Verifica implementações de autenticação/segurança em repositórios backend
# previamente classificados pelo backend-detector.sh.
#
# Melhorias aplicadas:
#   - Fix: parsing de DEPS e PATTERNS (bug de array em string)
#   - Fix: guard contra divisão por zero na cobertura
#   - Fix: code search reativado com PATTERNS correto
#   - Add: detecção ampliada — OAuth2, sessions, API keys, SDK interno
#   - Add: rate limit handling com backoff automático
#   - Add: detecção de versões vulneráveis conhecidas (jsonwebtoken < 9.0.0)
#   - Add: threshold de cobertura com alerta no stdout
#   - Add: timestamp e Run ID no relatório CSV
#   - Add: saída JSON estruturada para ingestão em dashboards

set -euo pipefail

# ---------------------------------------------------------------------------
# Configurações
# ---------------------------------------------------------------------------
ORG="will-bank"
OUTPUT_DIR="reports"
SECURITY_REPORT="$OUTPUT_DIR/security_report.csv"
COVERAGE_JSON="$OUTPUT_DIR/security_coverage.json"
RATE_LIMIT_THRESHOLD=50
COVERAGE_ALERT_THRESHOLD=80    # % mínima esperada; abaixo disso emite alerta

LANGUAGES="${1:-javascript go typescript rust java python}"

RUN_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RUN_ID="${GITHUB_RUN_ID:-local}"

TOTAL_REPOS=0
TOTAL_HAS_SECURITY=0

# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------

check_rate_limit() {
  local REMAINING
  local RESET
  local SLEEP_SEC

  REMAINING=$(gh api rate_limit --jq '.rate.remaining' 2>/dev/null || echo "999")

  if [[ "$REMAINING" -lt "$RATE_LIMIT_THRESHOLD" ]]; then
    RESET=$(gh api rate_limit --jq '.rate.reset' 2>/dev/null || echo "0")
    SLEEP_SEC=$(( RESET - $(date +%s) + 5 ))
    if [[ "$SLEEP_SEC" -gt 0 ]]; then
      echo "⏳ Rate limit baixo (${REMAINING} req restantes). Aguardando ${SLEEP_SEC}s..."
      sleep "$SLEEP_SEC"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Critérios de segurança por linguagem
#
# Formato: get_security_deps → "dep1 dep2 dep3 ..."
#          get_code_patterns → "pattern1 pattern2 ..."  (para GitHub code search)
#          get_vuln_versions → "lib:versao_maxima_insegura ..."
# ---------------------------------------------------------------------------

get_security_deps() {
  case "$1" in
    "javascript"|"typescript")
      # JWT + OAuth2 + Sessions + API Keys + SDK interno
      echo "jsonwebtoken passport-jwt @auth0/auth0-spa-js \
            express-oauth2-jwt-bearer passport-oauth2 \
            express-session connect-redis \
            @will-bank/willauth-sdk \
            helmet cors"
      ;;
    "go")
      echo "golang-jwt/jwt dgrijalva/jwt-go lestrrat-go/jwx \
            go-oauth2/oauth2 coreos/go-oidc"
      ;;
    "rust")
      echo "jsonwebtoken jwt-simple biscuit-auth \
            oxide-auth actix-web-httpauth"
      ;;
    "java")
      echo "jjwt spring-security nimbus-jose-jwt \
            spring-security-oauth2 keycloak-spring-boot"
      ;;
    "python")
      echo "pyjwt python-jose fastapi-security \
            authlib oauthlib social-auth-core \
            django-allauth flask-login"
      ;;
    *)
      echo ""
      ;;
  esac
}

get_code_patterns() {
  case "$1" in
    "javascript"|"typescript")
      echo "jwt.verify jwt.sign passport.authenticate \
            Authorization Bearer"
      ;;
    "go")
      echo "jwt.Parse ValidateToken VerifyToken \
            oauth2.Config"
      ;;
    "rust")
      echo "decode_header jwk::JwkSet \
            validate Claims"
      ;;
    "java")
      echo "JwtParser parseClaimsJws \
            SecurityConfig WebSecurityConfigurerAdapter \
            @PreAuthorize"
      ;;
    "python")
      echo "jwt.decode jwt.encode \
            Depends HTTPBearer login_required"
      ;;
    *)
      echo ""
      ;;
  esac
}

# Retorna pares "lib:versao_limite" — versões <= limite são vulneráveis
get_vuln_versions() {
  case "$1" in
    "javascript"|"typescript")
      # CVE-2022-23529: jsonwebtoken < 9.0.0 permite bypass de verificação de assinatura
      echo "jsonwebtoken:9.0.0"
      ;;
    "python")
      # CVE-2022-29217: pyjwt < 2.4.0
      echo "pyjwt:2.4.0"
      ;;
    "java")
      # CVE-2021-46877: jjwt < 0.12.0
      echo "jjwt:0.12.0"
      ;;
    *)
      echo ""
      ;;
  esac
}

get_manifest() {
  case "$1" in
    "javascript"|"typescript") echo "package.json" ;;
    "go")                       echo "go.mod" ;;
    "rust")                     echo "Cargo.toml" ;;
    "java")                     echo "pom.xml build.gradle" ;;
    "python")                   echo "requirements.txt pyproject.toml" ;;
    *)                          echo "" ;;
  esac
}

# ---------------------------------------------------------------------------
# Verifica se uma versão encontrada no manifest é vulnerável
# check_vuln_version "package.json_content" "jsonwebtoken:9.0.0"
# Retorna "jsonwebtoken@X.Y.Z (VULN)" ou ""
# ---------------------------------------------------------------------------
check_vuln_version() {
  local CONTENT="$1"
  local PAIR="$2"
  local LIB="${PAIR%%:*}"
  local SAFE_VERSION="${PAIR##*:}"

  # Extrai versão do manifesto (suporta package.json, requirements.txt, go.mod)
  local FOUND_VERSION
  FOUND_VERSION=$(echo "$CONTENT" | grep -i "\"$LIB\"" | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || true)
  if [[ -z "$FOUND_VERSION" ]]; then
    FOUND_VERSION=$(echo "$CONTENT" | grep -i "^$LIB" | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || true)
  fi

  if [[ -n "$FOUND_VERSION" ]]; then
    # Compara versões usando sort -V
    LOWER=$(printf '%s\n%s' "$FOUND_VERSION" "$SAFE_VERSION" | sort -V | head -1)
    if [[ "$LOWER" == "$FOUND_VERSION" && "$FOUND_VERSION" != "$SAFE_VERSION" ]]; then
      echo "${LIB}@${FOUND_VERSION}(VULN-CVE)"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Cabeçalho do CSV
# ---------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
echo "# Security Report | Timestamp: $RUN_TIMESTAMP | Run: $RUN_ID" > "$SECURITY_REPORT"
echo "Repository,Language,Dependencies Found,Code Patterns Found,Vulnerable Versions,Has Security" >> "$SECURITY_REPORT"

# ---------------------------------------------------------------------------
# Processamento por linguagem
# ---------------------------------------------------------------------------
process_language() {
  local LANG="$1"
  local BACKEND_FILE="$OUTPUT_DIR/${LANG}_backend.txt"

  if [[ ! -f "$BACKEND_FILE" ]]; then
    echo "⚠️  Arquivo não encontrado: $BACKEND_FILE — rode backend-detector.sh primeiro."
    return
  fi

  echo ""
  echo "🔍 Processando backends $LANG..."

  # Fix: parsing correto via read -ra (sem slicing de string como array)
  read -ra DEPS    <<< "$(get_security_deps "$LANG")"
  read -ra PATTERNS <<< "$(get_code_patterns "$LANG")"
  read -ra MANIFESTS <<< "$(get_manifest "$LANG")"
  VULN_PAIRS="$(get_vuln_versions "$LANG")"

  while IFS= read -r REPO; do
    DEPS_FOUND=""
    CODE_PATTERNS_FOUND=""
    VULN_FOUND=""

    # --- 1. Verificação de dependências nos arquivos de manifesto ---
    for MANIFEST in "${MANIFESTS[@]}"; do
      check_rate_limit

      set +e
      CONTENT=$(gh api -X GET \
        -H "Accept: application/vnd.github.v3.raw" \
        "/repos/$ORG/$REPO/contents/$MANIFEST" 2>&1)
      GH_STATUS=$?
      set -e

      if [[ $GH_STATUS -eq 0 ]]; then
        for DEP in "${DEPS[@]}"; do
          if grep -q -i "$DEP" <<< "$CONTENT"; then
            DEPS_FOUND+="${DEP};"
          fi
        done

        # --- 2. Verificação de versões vulneráveis ---
        if [[ -n "$VULN_PAIRS" ]]; then
          for PAIR in $VULN_PAIRS; do
            VULN_RESULT=$(check_vuln_version "$CONTENT" "$PAIR")
            if [[ -n "$VULN_RESULT" ]]; then
              VULN_FOUND+="${VULN_RESULT};"
            fi
          done
        fi

      elif [[ "$CONTENT" != *"404"* && "$CONTENT" != *"Not Found"* ]]; then
        echo "ERROR: $CONTENT" | tee -a workflow_errors.log
        exit $GH_STATUS
      fi
    done

    # --- 3. Busca de padrões no código via GitHub Search API ---
    for PATTERN in "${PATTERNS[@]}"; do
      check_rate_limit

      set +e
      PATTERN_COUNT=$(gh api -X GET "search/code" \
        -f q="repo:$ORG/$REPO $PATTERN" \
        --jq '.total_count' 2>/dev/null || echo "0")
      set -e

      if [[ "$PATTERN_COUNT" =~ ^[1-9] ]]; then
        CODE_PATTERNS_FOUND+="${PATTERN};"
      fi
    done

    TOTAL_REPOS=$(( TOTAL_REPOS + 1 ))

    HAS_SECURITY="No"
    if [[ -n "$DEPS_FOUND" || -n "$CODE_PATTERNS_FOUND" ]]; then
      HAS_SECURITY="Yes"
      TOTAL_HAS_SECURITY=$(( TOTAL_HAS_SECURITY + 1 ))
    fi

    # Remove trailing semicolons
    echo "$REPO,$LANG,${DEPS_FOUND%;},${CODE_PATTERNS_FOUND%;},${VULN_FOUND%;},$HAS_SECURITY" \
      >> "$SECURITY_REPORT"

    # Log de versões vulneráveis encontradas
    if [[ -n "$VULN_FOUND" ]]; then
      echo "  ⚠️  VULN em $REPO: $VULN_FOUND"
    fi

  done < <(grep -v '^#' "$BACKEND_FILE")
}

# ---------------------------------------------------------------------------
# Execução
# ---------------------------------------------------------------------------
for LANG in $LANGUAGES; do
  process_language "$LANG"
done

# ---------------------------------------------------------------------------
# Fix: guard contra divisão por zero
# ---------------------------------------------------------------------------
if [[ $TOTAL_REPOS -eq 0 ]]; then
  echo ""
  echo "⚠️  Nenhum repositório backend encontrado. Verifique se backend-detector.sh foi executado."
  COVERAGE_PERC="0"
else
  COVERAGE_PERC=$(echo "scale=2; ($TOTAL_HAS_SECURITY / $TOTAL_REPOS) * 100" | bc)
fi

COVERAGE_LABEL="${COVERAGE_PERC}% (${TOTAL_HAS_SECURITY}/${TOTAL_REPOS})"

# ---------------------------------------------------------------------------
# Saída JSON estruturada para dashboards (Grafana, DataDog, etc.)
# ---------------------------------------------------------------------------
cat > "$COVERAGE_JSON" <<EOF
{
  "timestamp": "$RUN_TIMESTAMP",
  "run_id": "$RUN_ID",
  "total_repos": $TOTAL_REPOS,
  "repos_with_security": $TOTAL_HAS_SECURITY,
  "coverage_percentage": $COVERAGE_PERC
}
EOF

# ---------------------------------------------------------------------------
# Threshold de alerta
# ---------------------------------------------------------------------------
echo ""
echo "✅ Cobertura de segurança: $COVERAGE_LABEL"

if [[ $TOTAL_REPOS -gt 0 ]]; then
  COVERAGE_INT=${COVERAGE_PERC%.*}
  if [[ "$COVERAGE_INT" -lt "$COVERAGE_ALERT_THRESHOLD" ]]; then
    echo ""
    echo "🚨 ALERTA: Cobertura abaixo do threshold mínimo de ${COVERAGE_ALERT_THRESHOLD}%!"
    echo "   Considere verificar os repositórios sem autenticação detectada."
    # Sinaliza saída diferenciada para o workflow capturar
    echo "COVERAGE_BELOW_THRESHOLD=true" >> "$OUTPUT_DIR/run_metadata.env"
  else
    echo "COVERAGE_BELOW_THRESHOLD=false" >> "$OUTPUT_DIR/run_metadata.env"
  fi
fi

echo "COVERAGE_PERCENTAGE=$COVERAGE_PERC"  >> "$OUTPUT_DIR/run_metadata.env"
echo "TOTAL_REPOS=$TOTAL_REPOS"            >> "$OUTPUT_DIR/run_metadata.env"
echo "TOTAL_HAS_SECURITY=$TOTAL_HAS_SECURITY" >> "$OUTPUT_DIR/run_metadata.env"

echo ""
echo "✅ Relatório gerado em : $SECURITY_REPORT"
echo "✅ JSON de cobertura   : $COVERAGE_JSON"
