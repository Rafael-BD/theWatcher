import argparse
import json
from datetime import datetime
from dateutil.parser import parse
from summarizer import summarize_vulnerabilities
import os
from scrapers.sources import get_full_disclosure_latest, get_exploitdb_rss
from scrapers.nist import get_nist_cves
from scrapers.nist import Severity

def parse_args():
    parser = argparse.ArgumentParser(description='Security Vulnerability Collection and Analysis Tool')
    
    # Tipo de dados
    parser.add_argument('--type', choices=['sources', 'nist'], default='sources',
                        help='Type of vulnerability data to collect (default: sources)')
    
    # Ações principais
    parser.add_argument('--collect', action='store_true', help='Collect vulnerabilities from sources')
    parser.add_argument('--summarize', action='store_true', help='Generate summary report')
    
    # Configuração de fontes
    parser.add_argument('--sources', nargs='+', 
                        choices=['fulldisclosure', 'exploitdb', 'nist'], 
                        default=['fulldisclosure', 'exploitdb'],
                        help='Sources to collect from (default: fulldisclosure,exploitdb)')
    
    # Configuração de datas
    parser.add_argument('--start-date', type=str, help='Start date (YYYY-MM-DD)',
                        default=(datetime.now().replace(day=1)).strftime('%Y-%m-%d'))
    parser.add_argument('--end-date', type=str, help='End date (YYYY-MM-DD)',
                        default=datetime.now().strftime('%Y-%m-%d'))
    
    # Configuração de IA
    parser.add_argument('--no-ai', action='store_true', help='Disable AI classification and summarization')
    
    # Configuração de output
    parser.add_argument('--output-dir', type=str, default='./output',
                        help='Output directory for results (default: ./output)')
    
    # NIST specific arguments
    parser.add_argument('--include-unclassified', action='store_true',
                        help='Include CVEs without CVSS classification')
    parser.add_argument('--max-cves', type=int,
                        default=100,
                        help='Maximum number of CVEs to retrieve')
    parser.add_argument('--min-severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                        help='Minimum severity level for CVEs')
    
    return parser.parse_args()


def save_to_json(data, filename="./output/all_vulnerabilities.json"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    with open(filename, 'w', encoding='utf-8') as json_file:
        json.dump(data, json_file, indent=4, ensure_ascii=False)

def collect_vulnerabilities(args):
    vulns = []
    start_date = parse(args.start_date)
    end_date = parse(args.end_date)
    
    if args.type == 'sources':
        print(f"Collecting itens from full disclosure and exploitdb from {args.start_date} to {args.end_date}...")
        if 'fulldisclosure' in args.sources:
            fd_vulns = get_full_disclosure_latest(start_date, end_date, use_ai=not args.no_ai)
            vulns.extend(fd_vulns)
            print(f"Full Disclosure results: {len(fd_vulns)}")
        
        if 'exploitdb' in args.sources:
            edb_vulns = get_exploitdb_rss(start_date, end_date)
            vulns.extend(edb_vulns)
            print(f"Exploit-DB results: {len(edb_vulns)}")
    
    elif args.type == 'nist':
        print(f"Collecting NIST CVEs from {args.start_date} to {args.end_date}...")
        nist_vulns = get_nist_cves(
            start_date=parse(args.start_date),
            end_date=parse(args.end_date),
            classified_only=not args.include_unclassified,
            max_cves=args.max_cves,
            min_severity=args.min_severity
        )
        vulns.extend(nist_vulns)
        print(f"NIST CVE results: {len(nist_vulns)}")
    
    output_file = f"{args.output_dir}/{'nist' if args.type == 'nist' else 'sources'}_vulnerabilities.json"
    save_to_json(vulns, output_file)
    print(f"Data saved to {output_file}")
    return vulns

def main():
    args = parse_args()
    
    if not args.collect and not args.summarize:
        args.collect = True
        args.summarize = True
    
    vulns = []
    if args.collect:
        vulns = collect_vulnerabilities(args)
    
    if args.summarize:
        if not args.no_ai:
            try:
                input_file = f"{args.output_dir}/{'nist' if args.type == 'nist' else 'sources'}_vulnerabilities.json"
                output_file = f"{args.output_dir}/{'nist' if args.type == 'nist' else 'sources'}_report.md"
                summarize_vulnerabilities(input_file, output_file)
            except Exception as e:
                print(f"Summarization error: {e}")
        else:
            print("Summarization skipped (AI disabled)")

if __name__ == "__main__":
    main()
