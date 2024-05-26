Email Security Tool
Project Overview
The Email Security Tool is designed to analyze email headers and body content for phishing attempts, malicious links, and other potential security threats. The tool is implemented in Python and utilizes the VirusTotal API to check the safety of URLs found in the email content.

Features
Header Analysis:

Checks the "From" address for suspicious patterns.
Scans the subject line for common phishing keywords such as "urgent" or "immediate".
Body Analysis:

Extracts URLs from the email body.
Uses the VirusTotal API to determine if URLs are malicious.
Searches for sensitive keywords like "login" and "password" in the email body.
Requirements
Python 3.x
requests library
virus_total_apis library
A VirusTotal API key
