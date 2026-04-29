#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  GENGAR — IP Threat Intelligence Tool                        ║
║  by Nayane Luz · CSIRT                                      ║
║  AbuseIPDB · VirusTotal · Geolocation · ASN Lookup          ║
╚══════════════════════════════════════════════════════════════╝
"""

import requests
import json
import sys
import time
import csv
import argparse
import configparser
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────
#  Cores
# ──────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'

# ──────────────────────────────────────────────
#  Configurações
# ──────────────────────────────────────────────
VT_FREE_DELAY   = 16   # segundos entre requests no VirusTotal (free tier: 4 req/min)
REQUEST_TIMEOUT = 12   # segundos de timeout por request

# ──────────────────────────────────────────────
#  Banner
# ──────────────────────────────────────────────
def banner():
    ghost = f"""{C.CYAN}{C.BOLD}
   _____________   ___________    ____
  / ____/ ____/ | / / ____/   |  / __ \\
 / / __/ __/ /  |/ / / __/ /| | / /_/ /
/ /_/ / /___/ /|  / /_/ / ___ / _, _/
\\____/_____/_/ |_/\\____/_/  |_/_/ |_|
{C.RESET}"""

    ghost_art = f"""{C.DIM}
          ░░░░░░░░░░░
        ░░▒▒▒▒▒▒▒▒▒▒▒░░
      ░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░
     ░▒▒▒░░░░▒▒▒░░░░▒▒▒▒▒░
     ░▒▒▒░██░▒▒▒░██░▒▒▒▒▒░
     ░▒▒▒░░░░▒▒▒░░░░▒▒▒▒▒░
     ░▒▒▒▒░░░░░░░░░▒▒▒▒▒▒░
      ░▒▒▒▒▒▒░░░░▒▒▒▒▒▒░░
       ░░▒░░▒░░░░▒░░▒░░░
         ░░   ░░░░   ░░
{C.RESET}"""

    print(ghost)
    print(ghost_art)
    print(f"{C.DIM}  IP Threat Intelligence Tool  ·  by Nayane Luz  ·  CSIRT")
    print(f"  Sources: AbuseIPDB · VirusTotal · ipinfo.io")
    print(f"  ─────────────────────────────────────────────────────────────{C.RESET}\n")

# ──────────────────────────────────────────────
#  Carrega config.ini
# ──────────────────────────────────────────────
def load_config():
    config = configparser.ConfigParser()
    config_path = Path('config.ini')

    if not config_path.exists():
        print(f"\n{C.RED}[ERRO] Arquivo config.ini não encontrado no diretório atual.{C.RESET}")
        print(f"{C.DIM}  Crie um arquivo config.ini com o seguinte conteúdo:\n")
        print("  [api_keys]")
        print("  abuseipdb_key = SUA_CHAVE")
        print(f"  virustotal_key = SUA_CHAVE{C.RESET}\n")
        sys.exit(1)

    config.read(config_path)

    try:
        return {
            'abuseipdb':  config['api_keys']['abuseipdb_key'],
            'virustotal': config['api_keys']['virustotal_key'],
        }
    except KeyError as e:
        print(f"\n{C.RED}[ERRO] Chave ausente no config.ini: {e}{C.RESET}\n")
        sys.exit(1)

# ──────────────────────────────────────────────
#  Consultas às APIs
# ──────────────────────────────────────────────
def check_abuseipdb(ip: str, api_key: str) -> dict:
    """Consulta AbuseIPDB — retorna dados de reputação do IP."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json().get('data', {})
    except requests.exceptions.HTTPError:
        return {"_error": f"HTTP {r.status_code}: {r.text[:120]}"}
    except Exception as e:
        return {"_error": str(e)}


def check_virustotal(ip: str, api_key: str) -> dict:
    """Consulta VirusTotal v3 — retorna análise de engines de segurança."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"Accept": "application/json", "x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json().get('data', {})
    except requests.exceptions.HTTPError:
        return {"_error": f"HTTP {r.status_code}: {r.text[:120]}"}
    except Exception as e:
        return {"_error": str(e)}


def check_geo(ip: str) -> dict:
    """Consulta ipinfo.io (HTTPS) — retorna geolocalização e ASN."""
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            headers={"Accept": "application/json"},
            timeout=REQUEST_TIMEOUT
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"_error": str(e)}

# ──────────────────────────────────────────────
#  Lógica de veredicto
# ──────────────────────────────────────────────
def get_verdict(abuse_score: int, vt_malicious: int, is_tor: bool) -> tuple:
    """Retorna (label, cor) do veredicto consolidado."""
    if abuse_score >= 75 or vt_malicious >= 5 or is_tor:
        return "ALTO RISCO", C.RED
    elif abuse_score >= 25 or vt_malicious >= 1:
        return "SUSPEITO", C.YELLOW
    else:
        return "LIMPO", C.GREEN

def score_color(score: int) -> str:
    if score >= 75: return C.RED
    if score >= 25: return C.YELLOW
    return C.GREEN

# ──────────────────────────────────────────────
#  Análise completa de um IP
# ──────────────────────────────────────────────
def analyze_ip(ip: str, keys: dict, apply_delay: bool = False) -> dict:
    """Executa todas as consultas para um IP e consolida o resultado."""
    if apply_delay:
        print(f"  {C.DIM}[rate limit] aguardando {VT_FREE_DELAY}s para o VirusTotal...{C.RESET}")
        time.sleep(VT_FREE_DELAY)

    abuse = check_abuseipdb(ip, keys['abuseipdb'])
    vt    = check_virustotal(ip, keys['virustotal'])
    geo   = check_geo(ip)

    return {
        'ip':        ip,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'abuseipdb': abuse,
        'virustotal': vt,
        'geo':       geo,
    }

# ──────────────────────────────────────────────
#  Exibição no terminal
# ──────────────────────────────────────────────
def print_result(result: dict):
    ip    = result['ip']
    abuse = result['abuseipdb']
    vt    = result['virustotal']
    geo   = result['geo']

    # Extrai métricas
    abuse_score  = abuse.get('abuseConfidenceScore', 0) if not abuse.get('_error') else 0
    is_tor       = bool(abuse.get('isTor', False))
    vt_attrs     = vt.get('attributes', {}) if not vt.get('_error') else {}
    vt_stats     = vt_attrs.get('last_analysis_stats', {})
    vt_malicious = vt_stats.get('malicious', 0)
    vt_suspicious= vt_stats.get('suspicious', 0)
    vt_harmless  = vt_stats.get('harmless', 0)
    vt_undetected= vt_stats.get('undetected', 0)
    vt_total     = vt_malicious + vt_suspicious + vt_harmless + vt_undetected

    verdict_label, verdict_col = get_verdict(abuse_score, vt_malicious, is_tor)

    # ── Cabeçalho ──
    print(f"\n{C.BOLD}{'─'*60}{C.RESET}")
    print(f"  {C.BOLD}IP:{C.RESET} {C.CYAN}{ip:<20}{C.RESET}  "
          f"Veredicto: {verdict_col}{C.BOLD}● {verdict_label}{C.RESET}")
    print(f"  {C.DIM}Analisado em: {result['timestamp']}{C.RESET}")
    print(f"{'─'*60}")

    # ── AbuseIPDB ──
    if abuse.get('_error'):
        print(f"\n  {C.BOLD}[AbuseIPDB]{C.RESET}  {C.RED}Erro: {abuse['_error']}{C.RESET}")
    else:
        sc = score_color(abuse_score)
        print(f"\n  {C.BOLD}[AbuseIPDB]{C.RESET}")
        print(f"    Score de Abuso  : {sc}{C.BOLD}{abuse_score}%{C.RESET}")
        print(f"    País            : {abuse.get('countryCode', 'N/A')} — {abuse.get('countryName', '')}")
        print(f"    ISP / Operadora : {abuse.get('isp', 'N/A')}")
        print(f"    Domínio         : {abuse.get('domain', 'N/A')}")
        print(f"    Total de Reports: {abuse.get('totalReports', 'N/A')}")
        last = abuse.get('lastReportedAt', None)
        print(f"    Último Report   : {last if last else 'nunca reportado'}")
        print(f"    Nó Tor?         : {C.RED+'Sim'+C.RESET if is_tor else C.GREEN+'Não'+C.RESET}")

    # ── VirusTotal ──
    if vt.get('_error'):
        print(f"\n  {C.BOLD}[VirusTotal]{C.RESET}  {C.RED}Erro: {vt['_error']}{C.RESET}")
    else:
        mal_c = C.RED if vt_malicious > 0 else C.GREEN
        sus_c = C.YELLOW if vt_suspicious > 0 else C.GREEN
        print(f"\n  {C.BOLD}[VirusTotal]{C.RESET}  {C.DIM}({vt_total} engines consultadas){C.RESET}")
        print(f"    Maliciosos  : {mal_c}{C.BOLD}{vt_malicious}{C.RESET}")
        print(f"    Suspeitos   : {sus_c}{vt_suspicious}{C.RESET}")
        print(f"    Inofensivos : {C.GREEN}{vt_harmless}{C.RESET}")
        print(f"    Não detect. : {vt_undetected}")
        if vt_total > 0:
            pct = (vt_malicious / vt_total) * 100
            print(f"    Detecção    : {mal_c}{pct:.1f}% das engines{C.RESET}")

    # ── Geolocalização ──
    if geo.get('_error'):
        print(f"\n  {C.BOLD}[Geolocalização]{C.RESET}  {C.RED}Erro: {geo['_error']}{C.RESET}")
    else:
        print(f"\n  {C.BOLD}[Geolocalização & ASN]{C.RESET}")
        print(f"    País        : {geo.get('country', 'N/A')}")
        print(f"    Cidade      : {geo.get('city', 'N/A')} / {geo.get('region', 'N/A')}")
        print(f"    ASN / Org   : {geo.get('org', 'N/A')}")
        print(f"    Timezone    : {geo.get('timezone', 'N/A')}")
        loc = geo.get('loc', '')
        if loc:
            print(f"    Coordenadas : {loc}")

# ──────────────────────────────────────────────
#  Tabela de resumo
# ──────────────────────────────────────────────
def print_summary(results: list):
    print(f"\n\n{C.BOLD}{'═'*60}")
    print(f"  RESUMO DA ANÁLISE  ·  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'═'*60}{C.RESET}")
    print(f"  {'IP':<22} {'Abuse':>7}  {'VT Mal':>7}  {'Tor':>5}  Veredicto")
    print(f"  {'─'*57}")

    for r in results:
        abuse = r['abuseipdb']
        vt    = r['virustotal']
        score = abuse.get('abuseConfidenceScore', 0) if not abuse.get('_error') else 0
        is_tor= bool(abuse.get('isTor', False))
        vt_stats = vt.get('attributes', {}).get('last_analysis_stats', {}) if not vt.get('_error') else {}
        mal   = vt_stats.get('malicious', 0)
        label, col = get_verdict(score, mal, is_tor)
        sc    = score_color(score)
        tor_s = f"{C.RED}sim{C.RESET}" if is_tor else "não"
        print(f"  {r['ip']:<22} {sc}{score:>6}%{C.RESET}  {mal:>7}  {tor_s:>5}  {col}{label}{C.RESET}")

    print(f"\n  Total analisado: {C.BOLD}{len(results)} IP(s){C.RESET}")

# ──────────────────────────────────────────────
#  Exportações
# ──────────────────────────────────────────────
def export_json(results: list, path: str):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n{C.GREEN}[✓] JSON exportado → {path}{C.RESET}")


def export_csv(results: list, path: str):
    rows = []
    for r in results:
        abuse = r['abuseipdb']
        vt    = r['virustotal']
        geo   = r['geo']
        vt_stats = vt.get('attributes', {}).get('last_analysis_stats', {}) if not vt.get('_error') else {}
        rows.append({
            'ip':              r['ip'],
            'timestamp':       r['timestamp'],
            'verdict':         get_verdict(
                                   abuse.get('abuseConfidenceScore', 0),
                                   vt_stats.get('malicious', 0),
                                   bool(abuse.get('isTor', False))
                               )[0],
            'abuse_score':     abuse.get('abuseConfidenceScore', ''),
            'abuse_country':   abuse.get('countryCode', ''),
            'abuse_isp':       abuse.get('isp', ''),
            'abuse_domain':    abuse.get('domain', ''),
            'abuse_reports':   abuse.get('totalReports', ''),
            'abuse_last_seen': abuse.get('lastReportedAt', ''),
            'is_tor':          abuse.get('isTor', ''),
            'vt_malicious':    vt_stats.get('malicious', ''),
            'vt_suspicious':   vt_stats.get('suspicious', ''),
            'vt_harmless':     vt_stats.get('harmless', ''),
            'vt_total':        sum(vt_stats.values()) if vt_stats else '',
            'geo_country':     geo.get('country', ''),
            'geo_city':        geo.get('city', ''),
            'geo_region':      geo.get('region', ''),
            'geo_org':         geo.get('org', ''),
            'geo_timezone':    geo.get('timezone', ''),
            'geo_coordinates': geo.get('loc', ''),
        })

    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"{C.GREEN}[✓] CSV exportado  → {path}{C.RESET}")

# ──────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="GENGAR — IP Threat Intelligence Tool | by Nayane Luz | CSIRT",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-i", "--ip",
        nargs='+', metavar='IP',
        help="Um ou mais endereços IP para analisar"
    )
    group.add_argument(
        "-f", "--file",
        metavar='FILE',
        help="Arquivo .txt com lista de IPs (um por linha)"
    )
    parser.add_argument(
        "--json",
        metavar='OUTPUT.json',
        help="Exporta todos os resultados em JSON"
    )
    parser.add_argument(
        "--csv",
        metavar='OUTPUT.csv',
        help="Exporta todos os resultados em CSV (pronto para Splunk/Elastic)"
    )
    parser.add_argument(
        "--no-delay",
        action='store_true',
        help="Remove o delay entre requests do VirusTotal (risco de rate limit no free tier)"
    )

    args = parser.parse_args()
    keys = load_config()

    # Monta lista de IPs
    ips = []
    if args.ip:
        ips = [ip.strip() for ip in args.ip if ip.strip()]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{C.RED}[ERRO] Arquivo '{args.file}' não encontrado.{C.RESET}\n")
            sys.exit(1)

    if not ips:
        print(f"{C.YELLOW}[AVISO] Nenhum IP válido para verificar.{C.RESET}\n")
        sys.exit(0)

    # Info de execução
    print(f"  {C.BOLD}IPs na fila:{C.RESET} {len(ips)}")
    if len(ips) > 1 and not args.no_delay:
        est = (len(ips) - 1) * VT_FREE_DELAY
        print(f"  {C.DIM}Rate limit VirusTotal ativo → tempo estimado: ~{est}s{C.RESET}")

    # Loop de análise
    results = []
    for i, ip in enumerate(ips):
        print(f"\n  {C.DIM}[{i+1}/{len(ips)}] Consultando {ip}...{C.RESET}")
        r = analyze_ip(ip, keys, apply_delay=(i > 0 and not args.no_delay))
        print_result(r)
        results.append(r)

    # Resumo final
    print_summary(results)

    # Exportações opcionais
    if args.json:
        export_json(results, args.json)
    if args.csv:
        export_csv(results, args.csv)

    print(f"\n  {C.DIM}Análise concluída · GENGAR · by Nayane Luz · CSIRT{C.RESET}\n")


if __name__ == "__main__":
    main()
