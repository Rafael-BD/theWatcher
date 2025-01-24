classification_prompt = """Decide if each title directly describes a security vulnerability or not.
Exclude titles that are about other topics such as software updates, security releases, general news, etc.
Replace THIS_JSON with the following data:

THIS_JSON

Use this JSON schema:
Post: {'index': int, 'title': str, 'is_vulnerability': bool}
Return: list[Post]
"""

summarization_prompt = """Analyze the vulnerabilities in this batch and group them by their affected technology/product.
For each vulnerability:
1) Provide a concise technical description (max 200 chars).
2) Indicate the index of the item no JSON references needed beyond that.

Also, produce a short summary of observed trends or relevant security notes in free text. (call it "trendSummary")

Input data:
THIS_JSON

Expected response format (JSON):
{
    "technologies": [
        {
            "name": str,
            "items": [
                {
                    "index": int,
                    "description": str
                }
            ]
        }
    ],
    "trendSummary": str
}
"""