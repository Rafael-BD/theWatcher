import os
from dotenv import load_dotenv
import google.generativeai as genai
from pydantic import BaseModel
import json
import time
from typing import List
from ai_prompts import classification_prompt
import math

load_dotenv()
api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    raise ValueError("GEMINI_API_KEY não encontrada no arquivo .env")

genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-2.0-flash-exp")

def classify_fd_titles(titles: List[str], batch_size: int = 20, use_ai: bool = True) -> List[dict]:
    if not use_ai or not api_key:
        print("AI classification disabled. Including all titles.")
        return [{"index": i, "title": t, "is_vulnerability": True} for i, t in enumerate(titles)]

    results = []
    total_batches = math.ceil(len(titles) / batch_size)
    requests_count = 0
    current_batch = 0
    
    for i in range(0, len(titles), batch_size):
        batch_num = i // batch_size + 1
        if current_batch != batch_num:
            current_batch = batch_num
            print(f"[Classification] Processing batch {batch_num}/{total_batches}")
        
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