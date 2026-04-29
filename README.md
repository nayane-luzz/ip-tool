# GENGAR 👻 — IP Threat Intelligence Tool

> by Nayane Luz · CSIRT

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Sources](https://img.shields.io/badge/Sources-AbuseIPDB%20·%20VirusTotal%20·%20ipinfo.io-purple)

Script de Threat Intelligence para enriquecimento de IOCs do tipo endereço IP, com veredicto automatizado e exportação para SIEM.

---

## Funcionalidades

- **AbuseIPDB** — score de abuso, ISP, domínio, total de reports, último report, detecção de nó Tor
- **VirusTotal v3** — contagem de engines maliciosas, suspeitas e inofensivas + percentual de detecção
- **ipinfo.io (HTTPS)** — geolocalização, ASN/Org, timezone, coordenadas
- **Veredicto automático** — `ALTO RISCO` / `SUSPEITO` / `LIMPO`
- **Rate limiting** — proteção automática contra rate limit do VirusTotal (free tier)
- **Exportação** — JSON e CSV prontos para ingestão no Splunk ou Elastic

---

## Instalação

```bash
pip install requests
```

## Configuração

Crie um arquivo `config.ini` no mesmo diretório:

```ini
[api_keys]
abuseipdb_key  = SUA_CHAVE_ABUSEIPDB
virustotal_key = SUA_CHAVE_VIRUSTOTAL
```

- **AbuseIPDB:** https://www.abuseipdb.com/api/
- **VirusTotal:** https://developers.virustotal.com/v3/reference

---

## Uso

```bash
# IP único
python gengar.py -i 1.2.3.4

# Múltiplos IPs
python gengar.py -i 1.2.3.4 8.8.8.8 45.33.32.156

# A partir de arquivo (um IP por linha)
python gengar.py -f lista_iocs.txt

# Exportar resultados
python gengar.py -f lista_iocs.txt --json resultado.json --csv resultado.csv

# Sem delay de rate limit (conta VT paga)
python gengar.py -f lista_iocs.txt --no-delay
```

---

## Veredicto

| Label | Critério |
|---|---|
| 🔴 ALTO RISCO | Abuse ≥ 75% **ou** VT ≥ 5 maliciosos **ou** nó Tor |
| 🟡 SUSPEITO | Abuse ≥ 25% **ou** VT ≥ 1 malicioso |
| 🟢 LIMPO | Sem detecções |

---

## CSV para SIEM

O CSV exportado contém as colunas:

`ip · timestamp · verdict · abuse_score · abuse_country · abuse_isp · abuse_domain · abuse_reports · abuse_last_seen · is_tor · vt_malicious · vt_suspicious · vt_harmless · vt_total · geo_country · geo_city · geo_region · geo_org · geo_timezone · geo_coordinates`

