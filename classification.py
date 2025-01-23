import os
from dotenv import load_dotenv
import google.generativeai as genai
from pydantic import BaseModel
import json
import time
from typing import List
from ai_prompts import classification_prompt
import math
from colorama import Fore, Style

load_dotenv()
api_key = os.getenv('GEMINI_API_KEY')
use_ai = True

if not api_key:
    print(Fore.YELLOW + "[theWatcher] GEMINI_API_KEY not found in .env file. AI classification disabled." + Style.RESET_ALL)
    use_ai = False
else:
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.0-flash-exp")
    except Exception as e:
        print(Fore.YELLOW + f"[theWatcher] Error configuring AI model: {e}. AI classification disabled." + Style.RESET_ALL)
        use_ai = False

def classify_fd_titles(titles: List[str], month: str, batch_size: int = 20) -> List[dict]:
    if not use_ai:
        print(Fore.YELLOW + "[theWatcher] AI classification disabled. Skipping filtering." + Style.RESET_ALL)
        return [{"index": i, "title": t, "is_vulnerability": True} for i, t in enumerate(titles)]

    results = []
    total_batches = math.ceil(len(titles) / batch_size)
    requests_count = 0
    current_batch = 0
    
    for i in range(0, len(titles), batch_size):
        batch_num = i // batch_size + 1
        if current_batch != batch_num:
            current_batch = batch_num
            print(Fore.BLUE + f"[theWatcher] Filtering items with AI (batch {batch_num}/{total_batches}) - month: {month}" + Style.RESET_ALL)
        
        batch = [{"index": j, "title": titles[j]} for j in range(i, min(i+batch_size, len(titles)))]

        tries = 0
        while tries < 3:
            tries += 1
            prompt_text = classification_prompt.replace("THIS_JSON", json.dumps(batch, ensure_ascii=False))
            try:
                resp = model.generate_content(
                    prompt_text,
                    generation_config=genai.GenerationConfig(
                        response_mime_type="application/json",
                    ),
                )
                if resp:
                    parsed = json.loads(resp.text)
                    if isinstance(parsed, list):
                        results.extend(parsed)
                        break
                print(f"Invalid response format (batch {batch_num}/{total_batches}, attempt {tries}). Retrying in 5s...")
            except Exception as e:
                print(f"Error in batch {batch_num}/{total_batches}, attempt {tries}: {e}. Retrying in 5s...")
            time.sleep(5)
        requests_count += 1

    return results