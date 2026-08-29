# 🛡️ Phishing URL Detector

A **Streamlit-based rule-driven web application** that analyzes URLs for common phishing indicators and produces a risk score, risk level, security warnings, positive security signals, technical URL details, and session-based analysis history.

> ⚠️ **Disclaimer:** This is a rule-based security assessment tool. A "Likely Safe" result does not guarantee that a website is safe.

## ✨ Features

- 🔍 Analyze any URL through a simple Streamlit interface
- 🛡️ Calculate a phishing risk score from **0–100**
- 🚦 Classify URLs as:
  - **Likely Safe** — score below 30
  - **Suspicious** — score 30–59
  - **High Risk** — score 60–100
- 🔐 Check for HTTPS usage
- ⚠️ Detect the `@` symbol commonly used to obscure destinations
- 🌐 Detect IP-address-based URLs
- 🏠 Identify unusually deep subdomains
- 🚨 Detect suspicious/phishing-related keywords
- 🔤 Detect possible typosquatting of trusted brands
- ✅ Recognize a predefined set of trusted domains
- 🔗 Detect common URL-shortening services
- 📏 Detect unusually long URLs
- ➖ Detect domains containing multiple hyphens
- 🔢 Detect excessive numbers in domains
- 🔐 Detect URL-encoded characters
- 📊 Display a visual risk-progress bar
- 🔎 Show technical URL parsing details
- 📜 Maintain analysis history during the Streamlit session
- 🗑️ Clear analysis history

## 🧠 How It Works

The detector parses and normalizes the submitted URL, extracts its hostname, and evaluates multiple rule-based indicators.

### Security Checks

| Indicator | Score Impact |
|---|---:|
| No HTTPS | +20 |
| `@` symbol | +25 |
| IP address as domain | +25 |
| Excessive subdomains | +15 |
| Suspicious keywords | +5 each, capped at +25 |
| Possible typosquatting | +30 |
| Known trusted domain | -30 |
| URL shortener | +15 |
| Very long URL (>150 characters) | +10 |
| Multiple hyphens in domain | +10 |
| Excessive digits (4+) | +5 |
| Encoded characters | +5 |

The final score is constrained to the **0–100** range.

### Risk Classification

```text
0–29   → Likely Safe
30–59  → Suspicious
60–100 → High Risk
```

## 🔤 Typosquatting Detection

The application compares the main domain portion of a URL against a predefined list of trusted brands using Python's `difflib.get_close_matches()`.

For example, a domain that closely resembles a trusted brand but is not an exact match can be flagged as a potential typosquatting attempt.

The similarity cutoff used by the detector is **0.75**.

## 🏷️ Trusted Domains

The current trusted-domain list includes:

- google.com
- paypal.com
- amazon.com
- facebook.com
- apple.com
- microsoft.com
- github.com
- linkedin.com
- instagram.com
- youtube.com
- twitter.com
- x.com

These are used only as predefined indicators in the rule-based analysis and should not be interpreted as a complete allowlist.

## 🚨 Suspicious Keywords

The detector checks URLs for terms commonly associated with phishing or social engineering, including:

`login`, `verify`, `verification`, `update`, `secure`, `security`, `free`, `bonus`, `bank`, `account`, `confirm`, `password`, `signin`, `authenticate`, `wallet`, `payment`, `credential`, `unlock`, `suspend`, `urgent`, `alert`, `recover`, `reset`, `claim`, and `reward`.

The keyword contribution is limited to **25 points**.

## 🔗 URL Shorteners

The detector identifies several common shortening services:

- bit.ly
- tinyurl.com
- t.co
- goo.gl
- ow.ly
- is.gd
- buff.ly
- cutt.ly
- shorturl.at

A URL shortener adds **15 risk points** because the final destination is not immediately visible.

## 🖥️ Application Interface

The Streamlit interface provides:

1. **URL input field** — Enter the URL to inspect.
2. **Analyze URL button** — Starts the analysis.
3. **Risk result** — Displays the overall risk classification.
4. **Metrics** — Shows risk score, risk level, and detected domain.
5. **Risk analysis bar** — Visualizes the score.
6. **Detected Indicators** — Lists triggered warning rules.
7. **Positive Security Indicators** — Lists favorable signals such as HTTPS or a known trusted domain.
8. **Recommendation** — Provides guidance based on the risk level.
9. **Technical Details** — Shows protocol, domain, path, query, fragment, normalized URL, and URL length.
10. **Analysis History** — Displays previously analyzed URLs in the current session.

## 🛠️ Tech Stack

- **Python**
- **Streamlit**
- `urllib.parse` — URL parsing and decoding
- `difflib` — Typosquatting similarity detection
- `ipaddress` — IP-address validation
- `re` — Regular-expression based URL normalization
- Python session state — Temporary analysis history

## 📁 Project Structure

A minimal project setup can be:

```text
phishing-url-detector/
│
├── app.py
└── README.md
```

The Python source contains the URL normalization/parsing utilities, security checks, scoring engine, and Streamlit UI.

## 🚀 Installation

### 1. Clone or download the project

```bash
git clone <your-repository-url>
cd phishing-url-detector
```

### 2. Install dependencies

```bash
pip install streamlit
```

The remaining modules used by the application are part of Python's standard library.

### 3. Run the application

```bash
streamlit run app.py
```

Streamlit will start a local web server and provide a browser URL for the application.

## 🧪 Example URLs

You can test the detector with examples such as:

```text
https://google.com
https://paypal.com
http://example.com/login
https://google.com@evil-example.com
https://192.168.1.10/login
https://paypa1-example.com/verify
```

These examples are intended to demonstrate different rule triggers; the detector's result depends on the complete set of indicators found in each URL.

## ⚙️ Scoring Philosophy

The application uses a **heuristic, rule-based scoring model** rather than machine learning.

Positive indicators can reduce the score, while suspicious URL characteristics increase it. Multiple indicators can accumulate, making URLs with several phishing-like characteristics more likely to reach the higher-risk categories.

This approach makes the detector:

- Easy to understand
- Easy to modify
- Lightweight
- Fast to execute
- Suitable for educational and prototype security analysis

## ⚠️ Limitations

This detector should **not** be treated as a complete phishing detection system.

Important limitations include:

- It does not visit or inspect the actual website.
- It does not analyze webpage HTML, JavaScript, certificates, DNS records, WHOIS data, or reputation feeds.
- The trusted-domain list is manually defined and limited.
- Legitimate URLs can contain suspicious-looking words.
- Sophisticated phishing URLs may avoid the implemented rules.
- A URL using HTTPS can still be malicious.
- A domain that is not flagged is not necessarily trustworthy.
- The scoring weights are heuristic and are not based on a trained statistical model.

## 🔮 Possible Future Enhancements

Potential improvements include:

- 🌐 Domain reputation and threat-intelligence APIs
- 🔐 SSL/TLS certificate analysis
- 🌍 DNS and WHOIS inspection
- 🧠 Machine-learning-based URL classification
- 🕵️ More advanced homograph/Unicode attack detection
- 🧩 HTML and webpage-content analysis
- 📡 Real-time blacklist integration
- 📈 Analytics and historical visualization
- 🗃️ Persistent database-backed scan history
- 🔌 Browser-extension integration
- 📱 Improved mobile UI
- 🧪 Automated test coverage for security rules

## 🔒 Security Note

Use this project as a **defensive and educational URL-analysis tool**. Do not enter passwords, OTPs, banking credentials, API keys, or other sensitive information into websites simply because this detector labels their URLs as "Likely Safe."

## 📄 License

Add your preferred open-source license here, such as **MIT License**, if you intend to publish the project publicly.
