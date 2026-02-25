import streamlit as st
import joblib
import socket
import ssl
import math
import tldextract
import re
import whois
import dns.resolver
from datetime import datetime
import numpy as np

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="Multi-Agent Phishing Detector",
    page_icon="🛡️",
    layout="wide"
)

# =========================================================
# CUSTOM DARK CYBERSECURITY THEME
# =========================================================
st.markdown("""
<style>
.stApp {
    background-color: #0E1117;
    color: #FAFAFA;
}
h1 {
    color: #00C2FF;
    text-align: center;
}
h2, h3 {
    color: #00FFAA;
}
.stButton>button {
    background-color: #1F77B4;
    color: white;
    border-radius: 10px;
    padding: 0.5em 1em;
    font-weight: bold;
}
.stButton>button:hover {
    background-color: #00C2FF;
    color: black;
}
textarea, input {
    background-color: #1A1F2E !important;
    color: white !important;
}
.safe {
    color: #00FF88;
    font-weight: bold;
    font-size: 22px;
}
.phish {
    color: #FF4B4B;
    font-weight: bold;
    font-size: 22px;
}
</style>
""", unsafe_allow_html=True)

# =========================================================
# HEADER
# =========================================================
st.markdown("<h1>🛡️ Multi-Agent Phishing Detection System</h1>", unsafe_allow_html=True)
st.markdown("### AI-Driven Multi-Layer Security Framework for FinTech Platforms")
st.markdown("---")

# =========================================================
# SIDEBAR
# =========================================================
with st.sidebar:
    st.title("Detection Mode")
    mode = st.radio(
        "",
        ["URL Detection", "Email Detection", "Combined URL + Email"]
    )
    st.markdown("---")
    st.info("Multi-Agent Architecture\n\nURL Agent\nEmail Agent\nCoordinator Agent")

# =========================================================
# UTILITIES
# =========================================================
def shannon_entropy(s):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum([p * math.log2(p) for p in prob])

def to_naive(dt):
    if isinstance(dt, datetime):
        return dt.replace(tzinfo=None)
    return dt

# =========================================================
# DOMAIN RULE AGENT
# =========================================================
def extract_domain_info(domain):
    info = {}
    now = datetime.utcnow()

    ext = tldextract.extract(domain)
    registered = ext.registered_domain or domain

    try:
        w = whois.whois(registered)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        created = to_naive(created)
        info["domain_age_days"] = (now - created).days if created else None
    except:
        info["domain_age_days"] = None

    try:
        a = dns.resolver.resolve(registered, 'A', lifetime=5)
        info["resolved_ips"] = [r.to_text() for r in a]
    except:
        info["resolved_ips"] = []

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=registered) as s:
            s.settimeout(4)
            s.connect((registered, 443))
            info["cert_present"] = True
    except:
        info["cert_present"] = False

    label = registered.split(".")[0]
    info["entropy"] = shannon_entropy(label)

    return info

def rule_based_score(info):
    score = 0
    total = 4

    if info["domain_age_days"] and info["domain_age_days"] < 30:
        score += 1
    if not info["resolved_ips"]:
        score += 1
    if not info["cert_present"]:
        score += 1
    if info["entropy"] > 3.5:
        score += 1

    return score / total

# =========================================================
# EMAIL HEADER RULE AGENT
# =========================================================
def header_rule_report(header):
    report = {}
    spf = re.search(r"spf=(\w+)", header, re.I)
    dkim = re.search(r"dkim=(\w+)", header, re.I)
    dmarc = re.search(r"dmarc=(\w+)", header, re.I)
    received = re.findall(r"^Received:", header, re.I | re.M)

    report["SPF"] = "PASS" if spf and "pass" in spf.group(0).lower() else "FAIL"
    report["DKIM"] = "PASS" if dkim and "pass" in dkim.group(0).lower() else "FAIL"
    report["DMARC"] = "PASS" if dmarc and "pass" in dmarc.group(0).lower() else "FAIL"
    report["Received hops ≥ 2"] = "PASS" if len(received) >= 2 else "FAIL"

    return report

def header_risk_score(header):
    report = header_rule_report(header)
    fails = list(report.values()).count("FAIL")
    return fails / len(report), report

# =========================================================
# MODEL LOADER
# =========================================================
@st.cache_resource
def load_models():
    models = {}
    for n in [
        "url_agent",
        "email_agent",
        "coordinator_agent",
        "url_vectorizer",
        "email_vectorizer",
    ]:
        models[n] = joblib.load(f"{n}.pkl")
    return models

models = load_models()

# =========================================================
# MODE 1: URL
# =========================================================
if mode == "URL Detection":

    url = st.text_input("Enter URL")

    if st.button("Analyze URL") and url.strip():

        info = extract_domain_info(url)
        rule_score = rule_based_score(info)

        ml_prob = models["url_agent"].predict_proba(
            models["url_vectorizer"].transform([url])
        )[0][1]

        final_prob = 0.3 * ml_prob + 0.7 * rule_score
        pred = final_prob >= 0.5

        st.subheader("🔍 URL Analysis Result")
        st.progress(float(final_prob))

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Suspiciousness Score", f"{final_prob:.3f}")
        with col2:
            if pred:
                st.markdown('<p class="phish">🚨 PHISHING DETECTED</p>', unsafe_allow_html=True)
            else:
                st.markdown('<p class="safe">✅ SAFE URL</p>', unsafe_allow_html=True)

# =========================================================
# MODE 2: EMAIL
# =========================================================
elif mode == "Email Detection":

    content = st.text_area("Email Content")
    header = st.text_area("Email Header (Optional)")

    if st.button("Analyze Email") and content.strip():

        email_prob = models["email_agent"].predict_proba(
            models["email_vectorizer"].transform([content])
        )[0][1]

        header_prob, report = header_risk_score(header) if header else (0, {})
        combined = max(email_prob, header_prob)

        pred = combined >= 0.5

        st.subheader("📧 Email Analysis Result")
        st.progress(float(combined))

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Risk Score", f"{combined:.3f}")
        with col2:
            if pred:
                st.markdown('<p class="phish">🚨 PHISHING EMAIL</p>', unsafe_allow_html=True)
            else:
                st.markdown('<p class="safe">✅ SAFE EMAIL</p>', unsafe_allow_html=True)

        if report:
            with st.expander("🔎 Header Rule Report"):
                for k, v in report.items():
                    st.write(f"{k}: {v}")

# =========================================================
# MODE 3: COMBINED
# =========================================================
else:

    url = st.text_input("Enter URL")
    content = st.text_area("Email Content")

    if st.button("Analyze FULL ATTACK VECTOR"):

        if not url.strip() or not content.strip():
            st.warning("Both URL and Email content required.")
        else:

            url_prob = models["url_agent"].predict_proba(
                models["url_vectorizer"].transform([url])
            )[0][1]

            email_prob = models["email_agent"].predict_proba(
                models["email_vectorizer"].transform([content])
            )[0][1]

            X_meta = np.array([[url_prob, email_prob, 1, 1]])
            coord_prob = models["coordinator_agent"].predict_proba(X_meta)[0][1]
            coord_pred = coord_prob >= 0.5

            st.subheader("🤖 Coordinator Meta-Agent Decision")
            st.progress(float(coord_prob))

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Coordinator Confidence", f"{coord_prob:.3f}")
            with col2:
                if coord_pred:
                    st.markdown('<p class="phish">🚨 PHISHING ATTACK</p>', unsafe_allow_html=True)
                else:
                    st.markdown('<p class="safe">✅ LEGITIMATE COMMUNICATION</p>', unsafe_allow_html=True)

st.markdown("---")
st.markdown(
    "<center>© 2026 | Multi-Agent Phishing Detection Framework | MS Thesis Project</center>",
    unsafe_allow_html=True
)
