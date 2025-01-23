import requests
from bs4 import BeautifulSoup
from datetime import datetime
import time
from typing import List, Dict, Optional
from enum import Enum

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
}

class CVSSVersion(Enum):
    V2 = "2.0"
    V3 = "3.x"
    V4 = "4.0"

class Severity(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

def format_date(date: datetime) -> str:
    return date.strftime('%m/%d/%Y')

def get_cvss_severity(row: BeautifulSoup) -> Optional[str]:
    """Extract highest CVSS severity from vulnerability row"""
    for version in ["3", "4", "2"]:  # Check in order of priority
        severity_link = row.select_one(f'a[data-testid^="vuln-cvss{version}-link-"]')
        if severity_link and "CRITICAL" in severity_link.text:
            return "CRITICAL"
        elif severity_link and "HIGH" in severity_link.text:
            return "HIGH"
        elif severity_link and "MEDIUM" in severity_link.text:
            return "MEDIUM"
        elif severity_link and "LOW" in severity_link.text:
            return "LOW"
    return None

def has_cvss_score(row: BeautifulSoup) -> bool:
    """Check if vulnerability has any CVSS score"""
    return any(row.select(f'a[data-testid^="vuln-cvss{v}-link-"]') 
                for v in ["2", "3", "4"])

def get_nist_cves(
    start_date: datetime, 
    end_date: datetime,
    classified_only: bool = True,
    max_cves: Optional[int] = None,
    min_severity: Optional[str] = None
) -> List[Dict]:
    vulns = []
    start_index = 0
    
    print(f"Starting CVE scraping from {format_date(start_date)} to {format_date(end_date)}")
    
    while True:
        if max_cves and len(vulns) >= max_cves:
            break
            
        params = {
            'isCpeNameSearch': 'false',
            'pub_start_date': start_date.strftime('%m/%d/%Y'),
            'pub_end_date': end_date.strftime('%m/%d/%Y'),
            'results_type': 'overview',
            'form_type': 'Advanced',
            'search_type': 'all',
            'startIndex': start_index
        }
        
        response = requests.get("https://nvd.nist.gov/vuln/search/results", 
                                params=params, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        rows = soup.select('table tbody tr')
        if not rows:
            print("No more CVE rows found, ending scraping.")
            break
            
        for row in rows:
            if max_cves and len(vulns) >= max_cves:
                print(f"Reached maximum number of CVEs: {max_cves}")
                break
                
            # Skip if requires classification and has none
            if classified_only and not has_cvss_score(row):
                continue
                
            severity = get_cvss_severity(row)
            if min_severity and (not severity or 
                Severity[severity].value < Severity[min_severity].value):
                continue
                
            cve_link = row.select_one('a[data-testid^="vuln-detail-link-"]')
            if not cve_link:
                continue
                
            cve_id = cve_link.text.strip()
            summary = row.select_one('p[data-testid^="vuln-summary-"]').text.strip()
            published = row.select_one('span[data-testid^="vuln-published-on-"]').text.strip()
            
            vulns.append({
                "title": f"{cve_id}: {summary}",
                "link": f"https://nvd.nist.gov{cve_link['href']}",
                "date": published,
                "content": summary,
                "source": "NIST",
                "severity": severity
            })
        
        start_index += len(rows)
        print(f"Processed {len(vulns)} CVEs so far")
        time.sleep(1)
        
    return vulns
