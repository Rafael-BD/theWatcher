import argparse
import json
from datetime import datetime, timedelta
from dateutil.parser import parse
from summarizer import summarize_vulnerabilities
import os
from scrapers.sources import get_full_disclosure_latest, get_exploitdb_rss
from scrapers.nist import get_nist_cves
from scrapers.nist import Severity

def parse_args():
    parser = argparse.ArgumentParser(
        description='Security Vulnerability Collection and Analysis Tool',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Template actions
    template_group = parser.add_argument_group('Templates')
    template_group.add_argument('--full-scan', '-F', action='store_true',
                              help='Run complete scan on all sources including NIST')
    template_group.add_argument('--quick-scan', '-Q', action='store_true',
                              help='Quick scan of recent vulnerabilities (last 7 days)')
    
    # Action options
    action_group = parser.add_argument_group('Actions')
    action_group.add_argument('--collect', '-c', action='store_true',
                            help='Collect vulnerabilities from sources')
    action_group.add_argument('--summarize', '-s', action='store_true',
                            help='Generate summary report')
    
    # Source options
    source_group = parser.add_argument_group('Sources')
    source_group.add_argument('--type', '-t', 
                          choices=['sources', 'nist', 'all'],
                          default='sources',
                          help='Type of vulnerability data to collect')
    source_group.add_argument('--sources', '-S', nargs='+',
                          choices=['fulldisclosure', 'exploitdb', 'nist'],
                          default=['fulldisclosure', 'exploitdb'],
                          help='Specific sources to collect from')
    
    # Date options with relative date support
    date_group = parser.add_argument_group('Date Range')
    date_group.add_argument('--days', '-d', type=int, default=30,
                         help='Number of days to look back')
    date_group.add_argument('--start-date', type=str,
                         help='Start date (YYYY-MM-DD) or relative days (e.g. -30)')
    date_group.add_argument('--end-date', type=str,
                         help='End date (YYYY-MM-DD) or relative days (e.g. -1)')
    
    # Limit options
    limit_group = parser.add_argument_group('Limits')
    limit_group.add_argument('--max-items', '-m', type=int,
                         help='Maximum number of vulnerabilities to retrieve')
    limit_group.add_argument('--min-severity', '-M',
                         choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                         help='Minimum severity level for vulnerabilities')
    
    # Other options
    other_group = parser.add_argument_group('Other Options')
    other_group.add_argument('--no-ai', '-N', action='store_true',
                         help='Disable AI classification and summarization')
    other_group.add_argument('--output-dir', '-o', type=str,
                         default='./output',
                         help='Output directory for results')
    other_group.add_argument('--include-unclassified', '-U',
                         action='store_true',
                         help='Include items without CVSS classification')
    
    args = parser.parse_args()
    
    # Process template options
    if args.full_scan:
        args.type = 'all'
        args.collect = True
        args.summarize = True
        args.days = 30
        # Somente sobrescrever max_items se o usuário não tiver definido -m
        if not args.max_items:
            args.max_items = None
        args.include_unclassified = True
    
    if args.quick_scan:
        args.type = 'sources'
        args.collect = True
        args.summarize = True
        args.days = 7
        args.max_items = 50
    
    # Set default actions if none specified
    if not (args.collect or args.summarize):
        args.collect = True
        args.summarize = True
    
    # Process date ranges
    now = datetime.now()
    if args.start_date:
        try:
            args.start_date = parse(args.start_date)
        except:
            days = int(args.start_date)
            args.start_date = now + timedelta(days=days)
    else:
        args.start_date = now - timedelta(days=args.days)
    
    if args.end_date:
        try:
            args.end_date = parse(args.end_date)
        except:
            days = int(args.end_date)
            args.end_date = now + timedelta(days=days)
    else:
        args.end_date = now
    
    return args

def save_to_json(data, filename="./output/all_vulnerabilities.json"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    with open(filename, 'w', encoding='utf-8') as json_file:
        json.dump(data, json_file, indent=4, ensure_ascii=False)

def collect_vulnerabilities(args):
    vulns = []
    max_items = args.max_items
    source_type = 'all' if args.type == 'all' else ('nist' if args.type == 'nist' else 'sources')
    
    # Calculate max items per source
    if args.type == 'all' and max_items:
        active_sources = len(args.sources) if 'nist' not in args.sources else len(args.sources) + 1
        max_per_source = max_items // active_sources
    else:
        max_per_source = max_items
    
    print(f"Total limit: {max_items}, Per source limit: {max_per_source}")
    
    if args.type in ['sources', 'all']:
        print(f"Collecting items from sources between {args.start_date.strftime('%Y-%m-%d')} and {args.end_date.strftime('%Y-%m-%d')}...")
        
        if 'fulldisclosure' in args.sources:
            fd_vulns = get_full_disclosure_latest(args.start_date, args.end_date, use_ai=not args.no_ai)
            fd_vulns = fd_vulns[:max_per_source] if max_per_source else fd_vulns
            vulns.extend(fd_vulns)
            print(f"Full Disclosure results: {len(fd_vulns)}")
        
        if 'exploitdb' in args.sources:
            remaining = max_items - len(vulns) if max_items else None
            edb_vulns = get_exploitdb_rss(args.start_date, args.end_date)
            edb_vulns = edb_vulns[:max_per_source] if max_per_source else edb_vulns
            vulns.extend(edb_vulns)
            print(f"Exploit-DB results: {len(edb_vulns)}")
            
    if args.type in ['nist', 'all']:
        print(f"Collecting NIST CVEs between {args.start_date.strftime('%Y-%m-%d')} and {args.end_date.strftime('%Y-%m-%d')}...")
        
        nist_vulns = get_nist_cves(
            start_date=args.start_date,
            end_date=args.end_date,
            classified_only=not args.include_unclassified,
            max_cves=max_per_source,  # Usa o mesmo limite por fonte
            min_severity=args.min_severity
        )
        vulns.extend(nist_vulns)
        print(f"NIST CVE results: {len(nist_vulns)}")
    
    # Aplica limite final ao total
    if max_items and len(vulns) > max_items:
        vulns = vulns[:max_items]
        print(f"Applied final limit: {len(vulns)}/{max_items} vulnerabilities")
    
    output_file = f"{args.output_dir}/{source_type}_vulnerabilities.json"
    save_to_json(vulns, output_file)
    print(f"Data saved to {output_file}")
    return vulns, source_type

def main():
    args = parse_args()
    
    if not args.collect and not args.summarize:
        args.collect = True
        args.summarize = True
    
    vulns = []
    source_type = 'sources'  # default
    
    if args.collect:
        vulns, source_type = collect_vulnerabilities(args)
    
    if args.summarize:
        if not args.no_ai:
            try:
                input_file = f"{args.output_dir}/{source_type}_vulnerabilities.json"
                output_file = f"{args.output_dir}/{source_type}_report.md"
                summarize_vulnerabilities(input_file, output_file)
            except Exception as e:
                print(f"Summarization error: {e}")
                print(f"Expected input file: {input_file}")
        else:
            print("Summarization skipped (AI disabled)")

if __name__ == "__main__":
    main()
