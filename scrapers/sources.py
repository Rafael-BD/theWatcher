import requests
from bs4 import BeautifulSoup
from datetime import datetime
import feedparser
from classification import classify_fd_titles
from dateutil.parser import parse

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

def is_date_in_range(date_str, start_date, end_date):
    date = parse(date_str)
    if date.tzinfo:
        date = date.replace(tzinfo=None)
    return start_date <= date <= end_date

def get_full_disclosure_latest(start_date, end_date, use_ai=True):
    vulns = []
    current_date = start_date
    month_names = {
        1: 'Jan', 2: 'Feb', 3: 'Mar', 4: 'Apr', 5: 'May', 6: 'Jun',
        7: 'Jul', 8: 'Aug', 9: 'Sep', 10: 'Oct', 11: 'Nov', 12: 'Dec'
    }

    while current_date <= end_date:
        month_str = month_names[current_date.month]
        base_url = f"https://seclists.org/fulldisclosure/{current_date.strftime('%Y')}/{month_str}"

        response = requests.get(base_url, headers=HEADERS, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        items = soup.select('ul.thread li')
        titles = []

        for index, item in enumerate(items):
            title = item.select_one('a').get_text(strip=True)
            titles.append(title)

        if use_ai:
            classified_items = classify_fd_titles(titles, batch_size=100)
            vuln_indices = [item["index"] for item in classified_items if item.get("is_vulnerability")]
        else:
            vuln_indices = range(len(titles))

        for index in vuln_indices:
            item = items[index]
            vuln_url = f"{base_url}/{index}"
            vuln_response = requests.get(vuln_url, headers=HEADERS, timeout=10)
            vuln_response.raise_for_status()

            vuln_soup = BeautifulSoup(vuln_response.text, 'html.parser')
            pre_content = vuln_soup.find('pre')
            if pre_content:
                date_text = f"{item.select_one('em').get_text(strip=True)}"
                vulns.append({
                    "title": titles[index],
                    "link": vuln_url,
                    "date": date_text,
                    "content": pre_content.get_text(),
                    "source": "Full Disclosure"
                })

        if current_date.month == 12:
            current_date = datetime(current_date.year + 1, 1, 1)
        else:
            current_date = datetime(current_date.year, current_date.month + 1, 1)

    return vulns

def get_exploitdb_rss(start_date, end_date):
    feed_url = "https://www.exploit-db.com/rss.xml"
    feed = feedparser.parse(feed_url)
    vulns = []
    requests_count = 0
    
    for entry in feed.entries:
        if is_date_in_range(entry.published, start_date, end_date):              
            content = get_exploitdb_content(entry.link)
            vulns.append({
                "title": entry.title.strip(),
                "link": entry.link,
                "date": entry.published,
                "description": entry.description,
                "content": content,
                "source": "Exploit-DB"
            })
            requests_count += 1
                
    return vulns

def get_exploitdb_content(vuln_link):
    response = requests.get(vuln_link, headers=HEADERS, timeout=10)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')
    
    content = soup.find('div', {'id': 'exploit-code'})
    return content.get_text().strip() if content else "No content available"

def get_vuln_content(vuln_link):
    response = requests.get(vuln_link, headers=HEADERS, timeout=10)
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup.find("pre").get_text() if soup.find("pre") else "No content available"
