import google.generativeai as genai
import json
import time
import re
from typing import List, TypedDict
from datetime import datetime
from dateutil.parser import parse
from dotenv import load_dotenv
import os
from ai_prompts import summarization_prompt
import math
from colorama import Fore, Style

load_dotenv()
api_key = os.getenv('GEMINI_API_KEY')

genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-2.0-flash-exp")

class VulnSummary(TypedDict):
    period: str
    vulnerabilities_by_technology: List[dict]
    trends: List[str]

def clean_content(content: str) -> str:
    """Clean up content for summarization"""
    content = re.sub(r'-----BEGIN PGP SIGNED MESSAGE-----.*?-----END PGP SIGNATURE-----', '', content, flags=re.DOTALL)
    content = re.sub(r'http\S+|www\.\S+|\S+@\S+', '', content)
    content = re.sub(r'\n\s*\n', '\n', content)
    return content.strip()

def batch_vulnerabilities(vulns: List[dict], batch_size: int = 35) -> List[List[dict]]:
    return [vulns[i:i + batch_size] for i in range(0, len(vulns), batch_size)]

def format_vulnerability_entry(vuln: dict, tech_item: dict) -> str:
    """Format a vulnerability entry with indented description"""
    source = vuln.get('source', '').lower()
    desc = tech_item.get('description', '')
    
    if source == 'nist':
        # Extract only CVE ID from title
        title = vuln['title'].split(':')[0].strip()
        # Format date to show only date part
        date = parse(vuln['date']).strftime('%B %d, %Y')
        return f"- [{title}]({vuln['link']}) ({date}) [NIST]\n    - {desc}"
    elif source == 'full disclosure':
        date = vuln['date'].split('via')[-1].strip()
        # Remove "Fulldisclosure" from date if present
        date = date.replace('Fulldisclosure', '').replace('()', '').strip()
        return f"- [{vuln['title']}]({vuln['link']}) ({date}) [Full Disclosure]\n    - {desc}"
    else:
        return f"- [{vuln['title']}]({vuln['link']}) ({vuln['date']}) [{vuln['source']}]\n    - {desc}"

def generate_markdown_report(vulns: List[dict], all_classifications: List[dict], report_type: str) -> str:
    report = f"""# Vulnerability Analysis Report - {report_type.upper()}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Vulnerabilities Analyzed: {len(vulns)}

## Vulnerabilities by Technology

"""
    # Add vulnerabilities grouped by technology
    all_trends = []
    for classification in all_classifications:
        # Add vulnerabilities
        tech_sections = classification.get('technologies', [])
        for tech in tech_sections:
            tech_name = tech['name']
            report += f"### {tech_name}\n\n"
            for item in tech['items']:
                vuln = vulns[item['index']]
                entry = format_vulnerability_entry(vuln, item)
                report += f"{entry}\n\n"
        
        # Collect trends
        all_trends.extend(classification.get('trends', []))
    
    # Add trends section
    if all_trends:
        report += "\n## Security Trends Analysis\n\n"
        for trend in all_trends:
            report += f"### {trend['trend']}\n"
            report += f"**Impact**: {trend['impact']}\n\n"
    
    return report

def summarize_vulnerabilities(input_file: str = "./output/all_vulnerabilities.json", output_file: str = "./output/vulnerability_report.md"):
    print(Fore.BLUE + f"[theWatcher] Loading vulnerabilities from {input_file}" + Style.RESET_ALL)
    if not api_key:
        print(Fore.YELLOW + "[theWatcher] No API key found. Skipping summarization." + Style.RESET_ALL)
        return

    with open(input_file, 'r', encoding='utf-8') as f:
        all_vulns = json.load(f)

    batches = batch_vulnerabilities(all_vulns)
    total_batches = len(batches)
    all_classifications = []
    requests_count = 0
    current_batch = 0

    # Process all batches first
    for i, batch in enumerate(batches):
        print(Fore.BLUE + f"[theWatcher] Summarizing items in batch {i+1}/{total_batches}" + Style.RESET_ALL)
        if current_batch != i + 1:
            current_batch = i + 1
        
        if requests_count > 0 and requests_count % 5 == 0:
            print("Waiting 20s to avoid rate limiting...")
            time.sleep(20)

        cleaned_batch = [{
            "title": vuln["title"],
            "date": vuln["date"],
            "content": clean_content(vuln["content"])[:2000],
            "source_link": vuln["link"],
            "source": vuln["source"]
        } for vuln in batch]

        tries = 0
        while tries < 3:
            tries += 1
            prompt_text = summarization_prompt.replace("BATCH_SIZE", str(len(batch)))\
                                            .replace("THIS_JSON", json.dumps(cleaned_batch, ensure_ascii=False))
            try:
                response = model.generate_content(
                    prompt_text,
                    generation_config=genai.GenerationConfig(
                        response_mime_type="application/json",
                    )
                )
                if response:
                    classification = json.loads(response.text)
                    if isinstance(classification, dict) and 'technologies' in classification:
                        all_classifications.append({
                            'technologies': classification['technologies'],
                            'trends': classification.get('trends', [])
                        })
                        break
                print(Fore.YELLOW + f"[theWatcher] Retrying batch {i+1}/{total_batches}..." + Style.RESET_ALL)
            except Exception as e:
                print(Fore.YELLOW + f"[theWatcher] Retrying batch {i+1}/{total_batches}..." + Style.RESET_ALL)
            time.sleep(5)

        requests_count += 1

    # Generate final report only once
    report = generate_markdown_report(all_vulns, all_classifications, 
                                   'nist' if 'nist' in input_file else 'sources')
    
    # Write complete report
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)

    print(Fore.GREEN + f"[theWatcher] Report saved in {output_file}" + Style.RESET_ALL)

def validate_summary_format(summary: dict) -> bool:
    """Validate if summary follows the required format"""
    try:
        if not all(k in summary for k in ['period', 'vulnerabilities_by_technology', 'trends']):
            return False
            
        for tech in summary['vulnerabilities_by_technology']:
            if not all(k in tech for k in ['technology', 'vulnerabilities']):
                return False
                
            for vuln in tech['vulnerabilities']:
                if not all(k in vuln for k in ['title', 'link', 'date', 'source']):
                    return False
                    
                # Validate title format (should be short)
                if len(vuln['title'].split(':')[0]) > 50:
                    vuln['title'] = vuln['title'].split(':')[0]
                    
        return True
    except:
        return False

if __name__ == "__main__":
    summarize_vulnerabilities()