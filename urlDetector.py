import streamlit as st
import difflib
from urllib.parse import urlparse

# List of suspicious keywords
suspicious_keywords = ["login", "verify", "update", "free", "bonus", "secure", "bank", "account", "confirm"]

# List of trusted domain keywords for typo checking
trusted_keywords = ["google", "paypal", "amazon", "facebook", "apple", "microsoft", "github", "linkedin"]

def extract_domain(url):
    try:
        netloc = urlparse(url).netloc
        if netloc.startswith("www."):
            netloc = netloc[4:]
        domain = netloc.split('.')[0]  # main domain part before TLD
        return domain.lower()
    except:
        return ""

def check_typo(domain):
    matches = difflib.get_close_matches(domain, trusted_keywords, n=1, cutoff=0.8)
    if matches and matches[0] != domain:
        return True, matches[0]  # typo detected, close to this trusted domain
    return False, None

def is_phishing(url):
    url_lower = url.lower()

    # Rule 1: '@' symbol
    if "@" in url_lower:
        return True, "Contains '@' symbol"

    # Rule 2: Too many dots (subdomains)
    if url_lower.count('.') > 3:
        return True, "Too many subdomains"

    # Rule 3: HTTPS missing
    if not url_lower.startswith("https://"):
        return True, "Missing HTTPS"

    # Rule 4: Suspicious keywords
    for word in suspicious_keywords:
        if word in url_lower:
            return True, f"Contains suspicious keyword: '{word}'"

    # Rule 5: Typo/misspelling in domain
    domain = extract_domain(url_lower)
    typo_found, close_match = check_typo(domain)
    if typo_found:
        return True, f"Domain '{domain}' looks like a typo of '{close_match}'"

    return False, "No suspicious patterns detected"

# Streamlit UI
st.set_page_config(page_title="Phishing URL Detector", page_icon="🔍")
st.title("🔍 Simple Phishing URL Detector")
st.write("Check if a URL is safe or suspicious.")

user_url = st.text_input("Enter a URL:")

if st.button("Check URL"):
    if user_url.strip() == "":
        st.warning("Please enter a URL first.")
    else:
        phishing, reason = is_phishing(user_url)
        if phishing:
            st.error(f"🚨 This URL is likely a phishing link!\nReason: {reason}")
        else:
            st.success("✅ This URL seems safe.")
