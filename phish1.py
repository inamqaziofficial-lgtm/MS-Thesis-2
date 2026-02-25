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
# DARK THEME (STABLE + FIXED LABELS)
# =========================================================
st.markdown("""
<style>

/* ================= Background ================= */
.stApp {
    background: linear-gradient(135deg, #0B1120, #1E293B);
}

/* ================= Sidebar ================= */
section[data-testid="stSidebar"] {
    background-color: #111827;
}
section[data-testid="stSidebar"] * {
    color: #F9FAFB !important;
}

/* ================= Headers ================= */
h1 {
    color: #38BDF8 !important;
    text-align: center;
}
h2, h3 {
    color: #34D399 !important;
}

/* ================= INPUT LABEL FIX ================= */
div[data-testid="stWidgetLabel"] {
    color: #F8FAFC !important;
    font-weight: 600 !important;
}
div[data-testid="stWidgetLabel"] label {
    color: #F8FAFC !important;
    font-weight: 600 !important;
}

/* ================= Inputs ================= */
textarea, input {
    background-color: #1E293B !important;
    color: #F8FAFC !important;
    border: 1px solid #475569 !important;
    border-radius: 8px !important;
    caret-color: #22D3EE !important;
}

/* ================= Buttons ================= */
.stButton>button {
    background: linear-gradient(90deg, #2563EB, #0EA5E9);
    color: white;
    border-radius: 10px;
    padding: 0.5em 1.2em;
    font-weight: bold;
    border: none;
}
.stButton>button:hover {
    background: linear-gradient(90deg, #0EA5E9, #38BDF8);
    color: black;
}

/* ================= Metrics ================= */
[data-testid="stMetricLabel"] {
    color: #CBD5E1 !important;
    font-weight: 600;
}
[data-testid="stMetricValue"] {
    color: #F8FAFC !important;
    font-size: 28px;
}

/* ================= Progress ================= */
div[data-testid="stProgressBar"] > div > div {
    background-color: #22D3EE !important;
}

/* ================= Result Colors ================= */
.safe {
    color: #22C55E;
    font-weight: bold;
    font-size: 22px;
}
.phish {
    color: #EF4444;
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
        ["Combined URL + Email"]  # Keeping main mode clean
    )
    st.markdown("---")
    st.info("Multi-Agent Architecture\n\nURL Agent\nEmail Agent\nRule Agents\nCoordinator Agent")

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
# LOAD MODELS
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
# MAIN INPUT
# =========================================================
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
        st.progress(coord_prob)

        col1, col2 = st.columns(2)
        with col1:
            st.metric("Coordinator Confidence", f"{coord_prob:.3f}")
        with col2:
            if coord_pred:
                st.markdown('<p class="phish">🚨 PHISHING ATTACK</p>', unsafe_allow_html=True)
            else:
                st.markdown('<p class="safe">✅ LEGITIMATE COMMUNICATION</p>', unsafe_allow_html=True)

        st.markdown("---")

        with st.expander("🔎 Detailed Agent Breakdown (Explainability)"):
            st.metric("URL ML Agent", f"{url_prob:.3f}")
            st.progress(url_prob)

            st.metric("Email ML Agent", f"{email_prob:.3f}")
            st.progress(email_prob)

            url_rule_score = rule_based_score(extract_domain_info(url))
            st.metric("URL Rule Agent", f"{url_rule_score:.3f}")
            st.progress(url_rule_score)

# =========================================================
# FOOTER
# =========================================================
st.markdown("---")
st.markdown(
    "<center>© 2026 | Multi-Agent Phishing Detection Framework | MS Thesis Project</center>",
    unsafe_allow_html=True
)
