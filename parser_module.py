import re

PHISHING_KEYWORDS = [
    "verify", "urgent", "bank", "password", "click here", "suspended",
    "account", "login", "update", "confirm", "security", "alert",
    "immediately", "expire", "limited", "access", "validate", "credit",
    "debit", "ssn", "social security", "pin", "otp", "wire transfer",
    "prize", "winner", "lottery", "free", "claim", "reward", "gift",
    "paypal", "bitcoin", "crypto", "wallet", "refund", "invoice",
    "unauthorized", "suspicious activity", "blocked", "locked"
]

def parse_email_content(content):
    if not content:
        return {
            'urls': [],
            'email_addresses': [],
            'keywords_found': [],
            'raw_text': ''
        }

    # Extract URLs
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, content, re.IGNORECASE)

    # Also detect URLs without protocol
    bare_url_pattern = r'(?<!\S)(?:www\.[^\s<>"{}|\\^`\[\]]+)'
    bare_urls = re.findall(bare_url_pattern, content, re.IGNORECASE)
    urls += ['http://' + u for u in bare_urls]

    # Clean URLs
    urls = list(set([u.rstrip('.,;)>') for u in urls]))

    # Extract email addresses
    email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    email_addresses = re.findall(email_pattern, content)

    # Find phishing keywords
    content_lower = content.lower()
    keywords_found = []
    for keyword in PHISHING_KEYWORDS:
        if keyword in content_lower:
            keywords_found.append(keyword)

    return {
        'urls': urls,
        'email_addresses': email_addresses,
        'keywords_found': keywords_found,
        'raw_text': content
    }
