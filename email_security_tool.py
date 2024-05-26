# Email Security Tool
# Created by Nurlan Isazade

import email
import re
import requests
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from virus_total_apis import PublicApi as VirusTotalPublicApi

# Initialize VirusTotal API
API_KEY = 'your_virustotal_api_key'
vt = VirusTotalPublicApi(API_KEY)


# Function to extract URLs from email body
def extract_urls(text):
    url_regex = re.compile(r'(https?://\S+)')
    return url_regex.findall(text)


# Function to check if a URL is malicious using VirusTotal
def check_url_safety(url):
    response = vt.get_url_report(url)
    if response['response_code'] == 200:
        results = response.get('results', {})
        positives = results.get('positives', 0)
        if positives > 0:
            return True  # URL is flagged as malicious
        else:
            return False  # URL is not flagged as malicious
    else:
        print(f"Error in API response: {response}")
        return False  # Default to not malicious if API call fails


# Function to analyze email headers for common phishing indicators
def analyze_headers(msg):
    indicators = []
    from_address = msg.get('From')
    if not re.match(r".+@.+\..+", from_address):
        indicators.append("Suspicious From address: " + from_address)

    subject = msg.get('Subject')
    if "urgent" in subject.lower() or "immediate" in subject.lower():
        indicators.append("Suspicious subject line: " + subject)

    return indicators


# Function to analyze the email body for phishing attempts and malicious links
def analyze_email_body(msg):
    indicators = []
    body = ""
    if msg.is_multipart():
        for part in msg.iter_parts():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(part.get_content_charset())
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset())

    urls = extract_urls(body)
    for url in urls:
        if check_url_safety(url):
            indicators.append("Malicious URL found: " + url)

    if "login" in body.lower() or "password" in body.lower():
        indicators.append("Sensitive keywords found in the email body.")

    return indicators


# Main function to analyze the email
def analyze_email(email_file):
    with open(email_file, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    header_indicators = analyze_headers(msg)
    body_indicators = analyze_email_body(msg)

    indicators = header_indicators + body_indicators
    if not indicators:
        print("No suspicious indicators found in the email.")
    else:
        print("Suspicious indicators found:")
        for indicator in indicators:
            print(indicator)


# Example usage
email_file = 'path_to_your_email_file.eml'
analyze_email(email_file)
