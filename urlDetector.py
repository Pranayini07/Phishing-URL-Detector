import streamlit as st
import difflib
import re
import ipaddress
from urllib.parse import urlparse, unquote

# ============================================================
# CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide"
)

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "update", "secure",
    "security", "free", "bonus", "bank", "account", "confirm",
    "password", "signin", "authenticate", "wallet", "payment",
    "credential", "unlock", "suspend", "urgent", "alert",
    "recover", "reset", "claim", "reward"
]

# Trusted domains
TRUSTED_DOMAINS = {
    "google.com",
    "paypal.com",
    "amazon.com",
    "facebook.com",
    "apple.com",
    "microsoft.com",
    "github.com",
    "linkedin.com",
    "instagram.com",
    "youtube.com",
    "twitter.com",
    "x.com"
}

# Trusted brand names for typo detection
TRUSTED_BRANDS = [
    "google",
    "paypal",
    "amazon",
    "facebook",
    "apple",
    "microsoft",
    "github",
    "linkedin",
    "instagram",
    "youtube",
    "twitter"
]

# Common URL shorteners
SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at"
]


# ============================================================
# URL FUNCTIONS
# ============================================================

def normalize_url(url):
    """
    Adds https:// if the user didn't provide a scheme.
    """
    url = url.strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url

    return url


def parse_url(url):
    """
    Safely parse the URL.
    """
    try:
        return urlparse(normalize_url(url))
    except Exception:
        return None


def extract_domain(url):
    """
    Extract the hostname/domain from a URL.
    """
    try:
        parsed = parse_url(url)

        if not parsed or not parsed.hostname:
            return ""

        hostname = parsed.hostname.lower()

        if hostname.startswith("www."):
            hostname = hostname[4:]

        return hostname

    except Exception:
        return ""


def get_main_domain(domain):
    """
    Get the primary domain portion.

    Example:
    login.paypal.com -> paypal
    """
    if not domain:
        return ""

    parts = domain.split(".")

    if len(parts) >= 2:
        return parts[-2]

    return parts[0]


def is_ip_address(domain):
    """
    Check whether the hostname is an IP address.
    """
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


# ============================================================
# SECURITY CHECKS
# ============================================================

def check_https(url):
    """
    Check whether HTTPS is used.
    """
    return url.lower().startswith("https://")


def check_at_symbol(url):
    """
    @ can hide the real destination.

    Example:
    https://google.com@evil.com
    """
    return "@" in url


def check_excessive_subdomains(domain):
    """
    Detect unusually deep subdomains.
    """
    if not domain:
        return False

    return len(domain.split(".")) > 3


def check_ip_domain(domain):
    """
    Detect URLs using an IP instead of a domain name.
    """
    return is_ip_address(domain)


def check_suspicious_keywords(url):
    """
    Find suspicious keywords in the URL.
    """
    url_lower = unquote(url.lower())

    found = []

    for word in SUSPICIOUS_KEYWORDS:
        if word in url_lower:
            found.append(word)

    return found


def check_url_shortener(domain):
    """
    Detect common URL shortening services.
    """
    return domain in SHORTENERS


def check_long_url(url):
    """
    Extremely long URLs can be suspicious.
    """
    return len(url) > 150


def check_multiple_hyphens(domain):
    """
    Detect domains with many hyphens.

    Example:
    paypal-account-security-verification.com
    """
    if not domain:
        return False

    return domain.count("-") >= 2


def check_numeric_domain(domain):
    """
    Detect excessive numbers in the domain.
    """
    if not domain:
        return False

    numbers = sum(char.isdigit() for char in domain)

    return numbers >= 4


def check_encoded_url(url):
    """
    Detect encoded characters that may hide URL content.
    """
    return "%" in url


# ============================================================
# TYPOSQUATTING DETECTION
# ============================================================

def check_typo(domain):
    """
    Detect domains that closely resemble trusted brands.
    """

    if not domain:
        return False, None

    main_domain = get_main_domain(domain)

    matches = difflib.get_close_matches(
        main_domain,
        TRUSTED_BRANDS,
        n=1,
        cutoff=0.75
    )

    if matches and matches[0] != main_domain:
        return True, matches[0]

    return False, None


def check_trusted_domain(domain):
    """
    Check if domain exactly matches a trusted domain.
    """
    return domain in TRUSTED_DOMAINS


# ============================================================
# MAIN ANALYSIS ENGINE
# ============================================================

def analyze_url(url):
    """
    Analyze the URL and calculate a risk score.
    """

    score = 0
    warnings = []
    positive_signs = []

    domain = extract_domain(url)
    parsed = parse_url(url)

    # --------------------------------------------------------
    # Invalid URL
    # --------------------------------------------------------

    if not domain or not parsed:
        return {
            "score": 100,
            "risk": "High Risk",
            "domain": domain,
            "warnings": ["Invalid or malformed URL"],
            "positive_signs": []
        }

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    if not check_https(url):
        score += 20
        warnings.append("🔓 URL does not use HTTPS")
    else:
        positive_signs.append("🔐 HTTPS connection detected")

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if check_at_symbol(url):
        score += 25
        warnings.append("⚠️ URL contains '@' symbol")

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    if check_ip_domain(domain):
        score += 25
        warnings.append("🌐 Domain is an IP address instead of a normal domain")

    # --------------------------------------------------------
    # SUBDOMAINS
    # --------------------------------------------------------

    if check_excessive_subdomains(domain):
        score += 15
        warnings.append("🏠 URL contains an unusually large number of subdomains")

    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    suspicious_words = check_suspicious_keywords(url)

    if suspicious_words:
        keyword_score = min(len(suspicious_words) * 5, 25)

        score += keyword_score

        warnings.append(
            "🚨 Suspicious keywords detected: "
            + ", ".join(suspicious_words)
        )

    # --------------------------------------------------------
    # TYPO DETECTION
    # --------------------------------------------------------

    typo_found, close_match = check_typo(domain)

    if typo_found:
        score += 30

        warnings.append(
            f"🔤 Domain '{get_main_domain(domain)}' "
            f"looks similar to trusted brand '{close_match}'"
        )

    # --------------------------------------------------------
    # TRUSTED DOMAIN
    # --------------------------------------------------------

    if check_trusted_domain(domain):
        score -= 30
        positive_signs.append("✅ Domain matches a known trusted domain")

    # --------------------------------------------------------
    # URL SHORTENER
    # --------------------------------------------------------

    if check_url_shortener(domain):
        score += 15
        warnings.append("🔗 URL uses a URL-shortening service")

    # --------------------------------------------------------
    # LONG URL
    # --------------------------------------------------------

    if check_long_url(url):
        score += 10
        warnings.append("📏 URL is unusually long")

    # --------------------------------------------------------
    # MULTIPLE HYPHENS
    # --------------------------------------------------------

    if check_multiple_hyphens(domain):
        score += 10
        warnings.append("➖ Domain contains multiple hyphens")

    # --------------------------------------------------------
    # EXCESSIVE NUMBERS
    # --------------------------------------------------------

    if check_numeric_domain(domain):
        score += 5
        warnings.append("🔢 Domain contains an unusual number of digits")

    # --------------------------------------------------------
    # ENCODED CHARACTERS
    # --------------------------------------------------------

    if check_encoded_url(url):
        score += 5
        warnings.append("🔐 URL contains encoded characters")

    # --------------------------------------------------------
    # LIMIT SCORE
    # --------------------------------------------------------

    score = max(0, min(score, 100))

    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if score >= 60:
        risk = "High Risk"
    elif score >= 30:
        risk = "Suspicious"
    else:
        risk = "Likely Safe"

    return {
        "score": score,
        "risk": risk,
        "domain": domain,
        "warnings": warnings,
        "positive_signs": positive_signs
    }


# ============================================================
# UI
# ============================================================

st.title("🛡️ Phishing URL Detector")

st.markdown(
    """
    ### 🔍 Analyze a URL for phishing indicators

    This tool uses multiple security rules to identify potentially
    malicious or suspicious URLs.
    """
)

st.divider()

# ============================================================
# INPUT
# ============================================================

user_url = st.text_input(
    "🌐 Enter URL",
    placeholder="https://example.com/login",
    help="Enter the complete URL you want to analyze."
)

check_button = st.button(
    "🔍 Analyze URL",
    type="primary",
    use_container_width=True
)

# ============================================================
# ANALYSIS
# ============================================================

if check_button:

    if not user_url.strip():

        st.warning("⚠️ Please enter a URL first.")

    else:

        result = analyze_url(user_url)

        score = result["score"]
        risk = result["risk"]
        domain = result["domain"]

        st.divider()

        # ----------------------------------------------------
        # RESULT HEADER
        # ----------------------------------------------------

        if risk == "High Risk":

            st.error(
                "🚨 HIGH RISK — This URL shows strong phishing indicators."
            )

        elif risk == "Suspicious":

            st.warning(
                "⚠️ SUSPICIOUS — This URL contains potentially risky patterns."
            )

        else:

            st.success(
                "✅ LIKELY SAFE — No major phishing indicators were detected."
            )

        # ----------------------------------------------------
        # METRICS
        # ----------------------------------------------------

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric(
                "Risk Score",
                f"{score}/100"
            )

        with col2:
            st.metric(
                "Risk Level",
                risk
            )

        with col3:
            st.metric(
                "Domain",
                domain if domain else "Unknown"
            )

        # ----------------------------------------------------
        # RISK BAR
        # ----------------------------------------------------

        st.subheader("📊 Risk Analysis")

        st.progress(score / 100)

        if score < 30:
            st.caption("🟢 Low risk")
        elif score < 60:
            st.caption("🟡 Moderate risk")
        else:
            st.caption("🔴 High risk")

        # ----------------------------------------------------
        # WARNINGS
        # ----------------------------------------------------

        if result["warnings"]:

            st.subheader("🚨 Detected Indicators")

            for warning in result["warnings"]:
                st.write(f"- {warning}")

        # ----------------------------------------------------
        # POSITIVE SIGNS
        # ----------------------------------------------------

        if result["positive_signs"]:

            st.subheader("✅ Positive Security Indicators")

            for sign in result["positive_signs"]:
                st.write(f"- {sign}")

        # ----------------------------------------------------
        # RECOMMENDATION
        # ----------------------------------------------------

        st.subheader("💡 Recommendation")

        if risk == "High Risk":

            st.error(
                """
                **Do not open this URL.**

                Avoid entering passwords, banking information,
                OTPs, or other personal information on this website.
                """
            )

        elif risk == "Suspicious":

            st.warning(
                """
                **Proceed with caution.**

                Verify the domain independently before entering
                any sensitive information.
                """
            )

        else:

            st.success(
                """
                The URL does not show major phishing patterns based
                on the rules used by this detector. However, no
                rule-based detector can guarantee that a website is safe.
                """
            )

        # ----------------------------------------------------
        # TECHNICAL DETAILS
        # ----------------------------------------------------

        with st.expander("🔎 View Technical Details"):

            parsed_url = parse_url(user_url)

            st.write("**Original URL:**", user_url)
            st.write("**Normalized URL:**", normalize_url(user_url))
            st.write("**Protocol:**", parsed_url.scheme)
            st.write("**Domain:**", domain)
            st.write("**Path:**", parsed_url.path)
            st.write("**Query:**", parsed_url.query)
            st.write("**Fragment:**", parsed_url.fragment)
            st.write("**URL Length:**", len(user_url))

        # ----------------------------------------------------
        # SESSION HISTORY
        # ----------------------------------------------------

        if "history" not in st.session_state:
            st.session_state.history = []

        st.session_state.history.append({
            "URL": user_url,
            "Domain": domain,
            "Risk Score": score,
            "Risk Level": risk
        })


# ============================================================
# HISTORY
# ============================================================

if "history" in st.session_state and st.session_state.history:

    st.divider()

    st.subheader("📜 Analysis History")

    st.dataframe(
        st.session_state.history,
        use_container_width=True,
        hide_index=True
    )

    if st.button("🗑️ Clear History"):
        st.session_state.history = []
        st.rerun()


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "🛡️ Phishing URL Detector | Rule-based security analysis"
)

st.caption(
    "⚠️ This tool provides an automated risk assessment and "
    "should not be treated as a definitive security guarantee."
)
