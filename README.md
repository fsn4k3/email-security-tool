
# Email Security Tool

## Project Overview

The Email Security Tool is designed to analyze email headers and body content for phishing attempts, malicious links, and other potential security threats. The tool is implemented in Python and utilizes the VirusTotal API to check the safety of URLs found in the email content.

## Features

1. **Header Analysis**:
   - Checks the "From" address for suspicious patterns.
   - Scans the subject line for common phishing keywords such as "urgent" or "immediate".

2. **Body Analysis**:
   - Extracts URLs from the email body.
   - Uses the VirusTotal API to determine if URLs are malicious.
   - Searches for sensitive keywords like "login" and "password" in the email body.

## Requirements

- Python 3.x
- `requests` library
- `virus_total_apis` library
- A VirusTotal API key

## Installation

1. **Clone the repository** (if applicable):
   ```bash
   git clone https://github.com/yourusername/email-security-tool.git
   cd email-security-tool
   ```

2. **Install the required libraries**:
   ```bash
   pip install requests
   pip install virus_total_apis
   ```

3. **Obtain a VirusTotal API key**:
   - Sign up at [VirusTotal](https://www.virustotal.com) to get a free API key.

## Configuration

- Replace `'your_virustotal_api_key'` in the script with your actual VirusTotal API key.
- Replace `'path_to_your_email_file.eml'` with the path to the email file you want to analyze.

## Usage

1. **Save the script**:
   Save the provided script to a file, for example `email_security_tool.py`.

2. **Run the script**:
   ```bash
   python email_security_tool.py
   ```


## How It Works

1. **Email Parsing**:
   - The email is parsed using the `email` library, which handles different parts of the email, including headers and body content.

2. **URL Extraction**:
   - The `extract_urls` function uses a regular expression to find all URLs in the email body.

3. **URL Safety Check**:
   - The `check_url_safety` function uses the VirusTotal API to check the safety of each extracted URL. If VirusTotal reports any positive detections, the URL is flagged as malicious.

4. **Header Analysis**:
   - The `analyze_headers` function checks the "From" address and subject line for common phishing indicators.

5. **Body Analysis**:
   - The `analyze_email_body` function scans the email body for sensitive keywords and checks each URL using the VirusTotal API.

6. **Main Function**:
   - The `analyze_email` function reads the email file, parses it, and runs header and body analysis. It then prints out any suspicious indicators found.

## Limitations

- The VirusTotal API has usage limitations, and the free tier may not support high-frequency queries.
- This tool provides basic phishing detection and URL safety checks. More advanced threat detection mechanisms can be integrated for improved accuracy.

## Future Enhancements

- Integrate additional reputation services for more robust URL safety checks.
- Implement machine learning models to detect phishing emails based on content analysis.
- Add support for analyzing attachments for malware.

## Conclusion

The Email Security Tool provides a basic yet effective way to analyze emails for phishing attempts and malicious links. By leveraging Python and the VirusTotal API, it demonstrates key skills in email parsing, regex, and security analysis.

## Note

Replace 'your_virustotal_api_key' with your actual VirusTotal API key and 'path_to_your_email_file.eml' with the path to your email file. This script provides a foundational tool for email security analysis that can be further enhanced with more advanced techniques and integrations.
