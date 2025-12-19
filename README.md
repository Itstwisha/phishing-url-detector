# Phishing URL Detector

A Python-based tool that analyzes URLs using common phishing heuristics such as suspicious keywords, domain impersonation, IP-based addressing, and hyphenated domains.

---

## Features

- Detects phishing indicators:
  - Fake login pages
  - Suspicious keywords (login, secure, verify)
  - IP address URLs
  - Impersonated domains (google → login-google-secure.com)
  - Hyphenated phishing-style URLs
- Scores each URL as:
  - **SAFE**
  - **SUSPICIOUS**
  - **PHISHING**

---

## Project Structure

```

phishing-url-detector/
│── src/
│     └── detector.py
│── data/
│     └── whitelist_domains.txt
│── samples/
│     └── test_urls.txt
│── README.md

````

---

## How to Run

```bash
python3 src/detector.py
````

Enter a URL:

```
http://login-google.com-security-check.com
```

---

## Sample Output

```
Result: PHISHING
Reasons:
- Suspicious keywords found: login
- Domain mimics trusted site: google.com
- Domain contains hyphens (common in phishing)
```

---

## Future Enhancements

* Add Levenshtein distance for advanced domain similarity
* Add HaveIBeenPwned or VirusTotal integration
* Build REST API version
* Build Chrome extension
* Machine learning classifier 

---

## Author

**Twisha**
Cybersecurity Analyst | Threat Intelligence | MS Cybersecurity
GitHub: @Itstwisha

---

## License

MIT License

```
