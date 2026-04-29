# Backend Auth Checker

O **Backend Auth Checker** é uma ferramenta automatizada para identificar repositórios backend e verificar a presença de dependências e padrões de autenticação/segurança em projetos de diferentes linguagens de programação. Ele utiliza a API do GitHub para analisar repositórios e gerar relatórios detalhados.

## O que ele detecta?

- **Classificação de Repositórios**: Identifica se um repositório é backend com base em arquivos de manifesto e dependências de frameworks.
- **Verificação de Segurança**: Detecta dependências de autenticação (JWT, OAuth2, sessions, API keys, SDK interno) e padrões de código.
- **Versões Vulneráveis**: Sinaliza versões conhecidamente vulneráveis de bibliotecas de autenticação (ex: `jsonwebtoken < 9.0.0` — CVE-2022-23529).
- **Cobertura com Threshold**: Alerta quando a cobertura de segurança fica abaixo do mínimo configurado.

## Metodologia

### 1. Classificação de Repositórios (`backend-detector.sh`)
- Analisa arquivos de manifesto (`package.json`, `go.mod`, `Cargo.toml`, etc.)
- Verifica dependências de frameworks backend por linguagem
- Registra qual dependência classificou o repositório e em qual arquivo
- Filtra repositórios com atividade nos últimos 2 anos

### 2. Verificação de Segurança (`check-security.sh`)
- Busca dependências de autenticação nos manifestos (JWT, OAuth2, sessions, SDK interno)
- Realiza code search na API do GitHub para padrões de implementação (ex: `jwt.verify`, `Authorization Bearer`)
- Verifica versões vulneráveis de bibliotecas críticas
- Calcula cobertura e emite alerta se abaixo do threshold configurado (`COVERAGE_ALERT_THRESHOLD`)

### 3. Geração de Relatórios
- `reports/security_report.csv` — repositórios com dependências, padrões e versões vulneráveis
- `reports/security_coverage.json` — JSON estruturado para ingestão em dashboards
- `reports/run_metadata.env` — variáveis de ambiente com métricas do run
- `reports/<lang>_backend.txt` / `<lang>_non_backend.txt` — listas por linguagem

## Requisitos

- Bash (Linux ou macOS) — compatibilidade de data via `python3`
- GitHub CLI (`gh`) configurado com um token de acesso
- `python3` (para cálculo de data portável entre Linux e macOS)
- `bc` (para cálculo de porcentagem)
- `jq` (para serialização de erros)

## Como executar

### Localmente

```bash
git clone https://github.com/will-bank/backend-detector.git
cd backend-detector

chmod +x backend-detector.sh check-security.sh

# Executa a classificação
./backend-detector.sh

# Executa a verificação de segurança
./check-security.sh

# Ou para linguagens específicas
./backend-detector.sh "javascript typescript"
./check-security.sh "javascript typescript"
```

Os relatórios serão gerados na pasta `reports/`.

### Via GitHub Actions

1. Configure os seguintes segredos no repositório:
   - `GH_TOKEN` — Token de acesso ao GitHub (veja abaixo como gerar)
   - `SLACK_WEBHOOK_URL` — URL do webhook do Slack para notificações

2. Acesse **Actions → Backend Auth Checker → Run workflow**

3. Informe as linguagens desejadas (ou deixe o padrão: `javascript go typescript rust java python`)

4. Após a execução, os relatórios estarão disponíveis como artefatos (retidos por 30 dias)

#### Como gerar o GH_TOKEN

1. Acesse: https://github.com/settings/personal-access-tokens/new
2. Defina o `Resource owner` como a org `will-bank`
3. Conceda acesso a `All repositories` com as seguintes permissões `Read-only`:
   - Commit statuses
   - Contents
   - Metadata

## Configurações Ajustáveis

| Variável | Arquivo | Padrão | Descrição |
|---|---|---|---|
| `RATE_LIMIT_THRESHOLD` | ambos os scripts | `50` | Requisições restantes antes de aguardar reset da API |
| `COVERAGE_ALERT_THRESHOLD` | `check-security.sh` | `80` | % mínima de cobertura antes de emitir alerta |
| `CUTOFF_DATE` | `backend-detector.sh` | 2 anos atrás | Repositórios sem atividade antes desta data são ignorados |

## Estrutura do Projeto

```
.
├── backend-detector.sh          # Classifica repos como backend
├── check-security.sh            # Verifica auth/segurança nos backends
├── reports/                     # Relatórios gerados (gitignored exceto .gitkeep)
│   ├── security_report.csv
│   ├── security_coverage.json
│   └── run_metadata.env
└── .github/
    └── workflows/
        ├── backend-auth-checker.yaml
        └── resources/
            ├── slack_payload_template.json           # Notificação de sucesso
            ├── slack_payload_error_template.json     # Notificação de falha
            └── slack_payload_coverage_alert_template.json  # Alerta de cobertura baixa
```

## Notificações Slack

| Evento | Template | Condição |
|---|---|---|
| Sucesso | `slack_payload_template.json` | Workflow completo sem erros |
| Falha | `slack_payload_error_template.json` | Qualquer step com erro |
| Alerta de cobertura | `slack_payload_coverage_alert_template.json` | Sucesso + cobertura < threshold |

## Contribuição

1. Faça um fork do repositório
2. Crie uma branch: `git checkout -b minha-feature`
3. Envie um pull request

## Licença

MIT — consulte o arquivo `LICENSE` para mais detalhes.
