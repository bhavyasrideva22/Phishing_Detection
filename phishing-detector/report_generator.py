import os
from datetime import datetime

REPORTS_DIR = 'reports'

def generate_report(scan, username):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    result_data = scan.get('result_data', {})
    scan_id = scan.get('id', 'N/A')
    timestamp = scan.get('scanned_at', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    threat_level = scan.get('threat_level', 'UNKNOWN')
    risk_score = scan.get('risk_score', 0)

    report_path = os.path.join(REPORTS_DIR, f'report_{scan_id}.txt')

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("       PHISHING DETECTION SECURITY REPORT\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Analyst: {username}\n")
        f.write(f"Scan ID: #{scan_id}\n")
        f.write(f"Scan Date: {timestamp}\n\n")

        f.write("-" * 60 + "\n")
        f.write("THREAT SUMMARY\n")
        f.write("-" * 60 + "\n")
        f.write(f"Threat Level:    {threat_level}\n")
        f.write(f"Risk Score:      {risk_score}/100\n")
        f.write(f"ML Prediction:   {result_data.get('ml_prediction', 'N/A').upper()}\n")
        f.write(f"ML Confidence:   {result_data.get('ml_confidence', 0):.1%}\n\n")

        f.write("-" * 60 + "\n")
        f.write("THREAT INDICATORS\n")
        f.write("-" * 60 + "\n")
        indicators = result_data.get('indicators', [])
        if indicators:
            for i, indicator in enumerate(indicators, 1):
                f.write(f"  {i}. {indicator}\n")
        else:
            f.write("  No significant threats detected.\n")
        f.write("\n")

        f.write("-" * 60 + "\n")
        f.write("DETECTED URLS\n")
        f.write("-" * 60 + "\n")
        urls = result_data.get('urls', [])
        if urls:
            for url_info in urls:
                f.write(f"  URL: {url_info.get('url', '')}\n")
                f.write(f"  Status: {url_info.get('status', '').upper()}\n")
                f.write(f"  Score: {url_info.get('score', 0)}\n")
                issues = url_info.get('issues', [])
                if issues:
                    f.write("  Issues:\n")
                    for issue in issues:
                        f.write(f"    - {issue}\n")
                f.write("\n")
        else:
            f.write("  No URLs detected.\n\n")

        f.write("-" * 60 + "\n")
        f.write("KEYWORDS DETECTED\n")
        f.write("-" * 60 + "\n")
        keywords = result_data.get('keywords_found', [])
        if keywords:
            f.write("  " + ", ".join(keywords) + "\n")
        else:
            f.write("  No suspicious keywords detected.\n")
        f.write("\n")

        f.write("-" * 60 + "\n")
        f.write("EMAIL CONTENT PREVIEW\n")
        f.write("-" * 60 + "\n")
        content = scan.get('content', '')[:500]
        f.write(content + "\n\n")

        f.write("=" * 60 + "\n")
        f.write("SOC RECOMMENDATION\n")
        f.write("=" * 60 + "\n")
        if threat_level == "PHISHING":
            f.write("⚠  ACTION REQUIRED: This email is highly likely to be a\n")
            f.write("   phishing attempt. DO NOT click any links or provide\n")
            f.write("   any personal information. Report to security team.\n")
        elif threat_level == "SUSPICIOUS":
            f.write("⚡ CAUTION: This email shows suspicious characteristics.\n")
            f.write("   Verify sender identity before taking any action.\n")
            f.write("   Exercise caution with any links or attachments.\n")
        else:
            f.write("✓  SAFE: This email appears to be legitimate based on\n")
            f.write("   current analysis. Continue with normal precautions.\n")
        f.write("\n")
        f.write("=" * 60 + "\n")
        f.write("     END OF REPORT — PhishDetect AI Security System\n")
        f.write("=" * 60 + "\n")

    return report_path
