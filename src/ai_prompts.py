classification_prompt = """Decide if each title directly describes a security vulnerability or not.
Exclude titles that are about other topics such as software updates, security releases, general news, etc.
Replace THIS_JSON with the following data:

THIS_JSON

Use this JSON schema:
Post: {'index': int, 'title': str, 'is_vulnerability': bool}
Return: list[Post]
"""

summarization_prompt = """Analyze the vulnerabilities in this batch and group them by their affected technology/product.
For each vulnerability, provide a concise technical description.

Input data:
THIS_JSON

Required format:
{
    "technologies": [
        {
            "name": str,          # Name of the technology/product
            "items": [
                {
                    "index": int,           # Index in the input batch
                    "description": str      # Technical description (max 200 chars)
                }
            ]
        }
    ],
    "trends": [                  # List of observed security trends
        {
            "trend": str,        # Description of the trend
            "impact": str        # Potential security impact
        }
    ]
}

Example response:
{
    "technologies": [
        {
            "name": "Apache Server",
            "items": [
                {
                    "index": 0,
                    "description": "Memory corruption vulnerability in mod_proxy allows remote attackers to execute arbitrary code via crafted HTTP requests"
                }
            ]
        }
    ],
    "trends": [
        {
            "trend": "Increase in HTTP request smuggling vulnerabilities",
            "impact": "Allows bypass of security controls and potential RCE"
        }
    ]
}
"""