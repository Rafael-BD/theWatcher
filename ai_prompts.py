classification_prompt = """Decide if each title directly describes a security vulnerability or not.
Exclude titles that are about other topics such as software updates, security releases, general news, etc.
Replace THIS_JSON with the following data:

THIS_JSON

Use this JSON schema:
Post: {'index': int, 'title': str, 'is_vulnerability': bool}
Return: list[Post]
"""

summarization_prompt = """Analyze the vulnerabilities in this batch and group them by their affected technology/product.
Do not modify or add information, just organize them into their respective categories.

Input data:
THIS_JSON

Required format:
{
    "technologies": [
        {
            "name": str,       # Name of the technology/product
            "items": [         # List of vulnerability indices from the input batch
                {
                    "index": int,      # Index in the input batch
                    "type": str,       # Type of vulnerability (e.g. "RCE", "XSS", "Buffer Overflow")
                }
            ]
        }
    ]
}
"""