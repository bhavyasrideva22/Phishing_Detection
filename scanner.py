import re
try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.link']
URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly']
SUSPICIOUS_KEYWORDS_IN_URL = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'bank', 'paypal', 'signin', 'password', 'auth']
LEGIT_DOMAINS = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com', 'linkedin.com']

def analyze_single_url(url):
    issues = []
    score = 0

    # Check HTTP vs HTTPS
    if url.startswith('http://'):
        issues.append('Insecure HTTP protocol')
        score += 20

    # Check for @ symbol
    if '@' in url:
        issues.append('URL contains @ symbol (phishing trick)')
        score += 30

    # Long URL
    if len(url) > 75:
        issues.append('Unusually long URL')
        score += 15

    # Multiple subdomains
    subdomain_count = url.split('/')[2].count('.')
    if subdomain_count > 3:
        issues.append('Multiple subdomains detected')
        score += 20

    # IP address instead of domain
    ip_pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'
    if re.match(ip_pattern, url):
        issues.append('IP address used instead of domain')
        score += 35

    # URL shorteners
    for shortener in URL_SHORTENERS:
        if shortener in url.lower():
            issues.append(f'URL shortener detected ({shortener})')
            score += 25
            break

    # Suspicious keywords in URL
    url_lower = url.lower()
    for kw in SUSPICIOUS_KEYWORDS_IN_URL:
        if kw in url_lower:
            issues.append(f'Suspicious keyword in URL: "{kw}"')
            score += 15
            break

    # Suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld) or tld + '/' in url_lower:
            issues.append(f'Suspicious top-level domain: {tld}')
            score += 25
            break

    # Hyphen abuse
    domain_part = url.split('/')[2] if '/' in url else url
    if domain_part.count('-') > 2:
        issues.append('Excessive hyphens in domain')
        score += 10

    # Extract domain info
    domain_info = {}
    if HAS_TLDEXTRACT:
        try:
            extracted = tldextract.extract(url)
            domain_info = {
                'subdomain': extracted.subdomain,
                'domain': extracted.domain,
                'suffix': extracted.suffix
            }
        except:
            domain_info = {}

    # Check for typosquatting patterns
    typo_patterns = ['paypa1', 'g00gle', 'micros0ft', 'arnazon', 'facebok', 'bankofamerica-', 'wellsfarg0']
    for typo in typo_patterns:
        if typo in url_lower:
            issues.append('Possible typosquatting detected')
            score += 40
            break

    status = 'safe'
    if score >= 61:
        status = 'malicious'
    elif score >= 31:
        status = 'suspicious'

    return {
        'url': url,
        'status': status,
        'score': min(score, 100),
        'issues': issues,
        'domain_info': domain_info
    }

def analyze_urls(urls):
    return [analyze_single_url(url) for url in urls]

def calculate_risk_score(parsed, url_results, ml_result):
    score = 0
    indicators = []

    # URL-based scoring
    for url_result in url_results:
        if url_result['status'] == 'malicious':
            score += 30
            indicators.append(f"Malicious URL detected: {url_result['url'][:50]}")
        elif url_result['status'] == 'suspicious':
            score += 15
            indicators.append(f"Suspicious URL: {url_result['url'][:50]}")
        for issue in url_result['issues']:
            if 'HTTP' in issue:
                score += 5
            elif '@' in issue:
                score += 10

    # Keyword scoring
    keywords = parsed.get('keywords_found', [])
    if len(keywords) >= 5:
        score += 25
        indicators.append(f"High density of phishing keywords ({len(keywords)} found)")
    elif len(keywords) >= 3:
        score += 15
        indicators.append(f"Multiple phishing keywords found: {', '.join(keywords[:3])}")
    elif len(keywords) >= 1:
        score += 8
        indicators.append(f"Phishing keyword detected: {keywords[0]}")

    # ML scoring
    if ml_result['prediction'] == 'phishing':
        conf = ml_result['confidence']
        if conf > 0.8:
            score += 30
            indicators.append(f"ML model: HIGH confidence phishing ({conf:.0%})")
        elif conf > 0.6:
            score += 20
            indicators.append(f"ML model: Likely phishing ({conf:.0%})")
        else:
            score += 10
            indicators.append(f"ML model: Possible phishing ({conf:.0%})")

    # Multiple URLs
    if len(parsed.get('urls', [])) > 3:
        score += 10
        indicators.append(f"Multiple URLs detected ({len(parsed['urls'])})")

    # Suspicious sender email
    for email_addr in parsed.get('email_addresses', []):
        domain = email_addr.split('@')[-1] if '@' in email_addr else ''
        for sus_tld in ['.tk', '.ml', '.ga', '.cf', '.gq']:
            if domain.endswith(sus_tld):
                score += 15
                indicators.append(f"Suspicious sender email domain: {domain}")

    # Cap at 100
    score = min(score, 100)

    if not indicators:
        indicators.append("No significant threats detected")

    return {
        'score': score,
        'indicators': indicators
    }
