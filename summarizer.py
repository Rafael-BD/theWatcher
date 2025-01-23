import google.generativeai as genai
import json
import time
import re
from typing import List, TypedDict
from datetime import datetime
from dotenv import load_dotenv
import os
from ai_prompts import summarization_prompt
import math

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
    """Format a vulnerability entry with description and versions"""
    source = vuln.get('source', '').lower()
    desc = tech_item.get('description', '')
    versions = tech_item.get('affected_versions', '')
    vuln_type = tech_item.get('type', '')
    
    # Base entry with title and link
    if source == 'nist':
        base = f"- [{vuln['title'].split(':')[0]}]({vuln['link']})"
    else:
        base = f"- [{vuln['title']}]({vuln['link']})"
    
    # Add metadata
    meta = []
    if vuln_type:
        meta.append(f"Type: {vuln_type}")
    if versions and versions.lower() != "unknown":
        meta.append(f"Affects: {versions}")
    if desc:
        meta.append(desc)
    
    # Add date and source
    if source == 'nist':
        date_src = f"({vuln['date']}) [NIST]"
    elif source == 'full disclosure':
        date_parts = vuln['date'].split('via')
        author = date_parts[0].strip() if len(date_parts) > 1 else ''
        date = date_parts[-1].strip()
        date_src = f"({author} via Full Disclosure ({date})) [Full Disclosure]"
    else:
        date_src = f"({vuln['date']}) [{vuln['source']}]"
    
    # Combine all parts
    return f"{base} [{' | '.join(meta)}] {date_src}"

def generate_markdown_report(vulns: List[dict], tech_classifications: List[dict], report_type: str) -> str:
    """Generate markdown report with consistent formatting"""
    report = f"""# Vulnerability Analysis Report - {report_type.upper()}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Vulnerabilities Analyzed: {len(vulns)}

## Vulnerabilities by Technology

"""
    # Group vulnerabilities by technology using AI classifications
    for tech in tech_classifications:
        tech_name = tech['name']
        report += f"### {tech_name}\n\n"
        
        for item in tech['items']:
            vuln = vulns[item['index']]
            entry = format_vulnerability_entry(vuln, item)
            report += f"{entry}\n"
        
        report += "\n"
    
    return report

def summarize_vulnerabilities(input_file: str = "./output/all_vulnerabilities.json", output_file: str = "./output/vulnerability_report.md"):
    if not api_key:
        print("No API key found. Skipping summarization.")
        return

    with open(input_file, 'r', encoding='utf-8') as f:
        all_vulns = json.load(f)

    batches = batch_vulnerabilities(all_vulns)
    total_batches = len(batches)
    summaries = []
    requests_count = 0
    current_batch = 0

    for i, batch in enumerate(batches):
        if current_batch != i + 1:
            current_batch = i + 1
            print(f"Processing batch {current_batch} of {total_batches}")
        
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
                        markdown_report = generate_markdown_report(
                            batch, 
                            classification['technologies'],
                            'nist' if 'nist' in input_file else 'sources'
                        )
                        # Write report chunk
                        with open(output_file, 'a', encoding='utf-8') as f:
                            f.write(markdown_report)
                        break
                print(f"Retrying batch {current_batch}/{total_batches}...")
            except Exception as e:
                print(f"Retrying batch {current_batch}/{total_batches}...")
            time.sleep(5)

        requests_count += 1

    print(f"Report saved in {output_file}")

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