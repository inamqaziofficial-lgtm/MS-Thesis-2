import streamlit as st
import joblib, socket, ssl, math, tldextract, re
import whois, dns.resolver, requests
from datetime import datetime

# =========================================================
# CONFIG
# =========================================================
URL_BLEND = 0.3   # fixed internally (no slider)

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
    info = {"domain": domain}
    now = datetime.utcnow()

    ext = tldextract.extract(domain)
    registered = ext.registered_domain or domain
    info["registered_domain"] = registered

    try:
        w = whois.whois(registered)
        created = w.creation_date
        if isinstance(created, list): created = created[0]
        created = to_naive(created)
        info["domain_age_days"] = (now - created).days if created else None
    except:
        info["domain_age_days"] = None

    resolver = dns.resolver.Resolver()
    try:
        a = resolver.resolve(registered, 'A', lifetime=5)
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

    if info["domain_age_days"] is not None and info["domain_age_days"] < 30:
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
def parse_header(header):
    return {
        "spf": re.search(r"spf=(\w+)", header, re.I),
        "dkim": re.search(r"dkim=(\w+)", header, re.I),
        "dmarc": re.search(r"dmarc=(\w+)", header, re.I),
        "received": re.findall(r"^Received:", header, re.I | re.M)
    }

def header_risk_score(text):
    h = parse_header(text)
    score = 0
    total = 4

    if not (h["spf"] and "pass" in h["spf"].group(0).lower()):
        score += 1
    if not (h["dkim"] and "pass" in h["dkim"].group(0).lower()):
        score += 1
    if not (h["dmarc"] and "pass" in h["dmarc"].group(0).lower()):
        score += 1
    if len(h["received"]) < 2:
        score += 1

    return score / total

def contains_header(text):
    markers = ["received:", "dkim", "spf=", "dmarc="]
    return any(m in text.lower() for m in markers)

# =========================================================
# MODEL LOADER
# =========================================================
@st.cache_resource
def load_models():
    models = {}
    for n in ["url_agent","email_agent","coordinator_agent","url_vectorizer","email_vectorizer"]:
        try:
            models[n] = joblib.load(f"{n}.pkl")
        except:
            models[n] = None
    return models

models = load_models()

# =========================================================
# UI
# =========================================================
st.set_page_config(page_title="Phishing Detector", layout="wide")
st.title("🛡️ Phishing Detection — Streamlit Interface")

# Sidebar model status
st.sidebar.header("Loaded Models")
for k,v in models.items():
    st.sidebar.write(f"{k}: {'✅' if v else '❌'}")

mode = st.radio("Choose input type:", ["URL","Email"], horizontal=True)

# =========================================================
# URL MODE
# =========================================================
if mode == "URL":
    url = st.text_input("Enter URL or domain")

    if st.button("Analyze URL"):
        info = extract_domain_info(url)
        rule_score = rule_based_score(info)

        ml_prob = 0
        if models["url_agent"]:
            v = models["url_vectorizer"].transform([url])
            ml_prob = models["url_agent"].predict_proba(v)[0][1]

        final_prob = URL_BLEND*ml_prob + (1-URL_BLEND)*rule_score
        meta = [[final_prob, 0, 1, 0]]

        pred = models["coordinator_agent"].predict(meta)[0]

        st.metric("Final suspiciousness", round(final_prob,3))
        st.write("Coordinator decision:", "PHISHING" if pred else "SAFE")

        with st.expander("Domain details"):
            st.json(info)

# =========================================================
# EMAIL MODE (CONTENT + HEADER AGENTS SEPARATE)
# =========================================================
else:
    text = st.text_area("Paste email content OR header")

    if st.button("Analyze Email"):

        # Email Content Agent
        email_prob = 0
        if models["email_agent"]:
            v = models["email_vectorizer"].transform([text])
            email_prob = models["email_agent"].predict_proba(v)[0][1]

        # Email Header Agent
        header_present = contains_header(text)
        header_prob = header_risk_score(text) if header_present else 0

        # Coordinator fusion
        combined_email_signal = max(email_prob, header_prob)
        meta = [[0, combined_email_signal, 0, 1]]

        pred = models["coordinator_agent"].predict(meta)[0]

        st.subheader("Agent Outputs")
        st.write("Email Content Agent probability:", round(email_prob,3))
        st.write("Header Agent probability:", round(header_prob,3))
        st.write("Header detected:", header_present)

        st.metric("Coordinator Email Signal", round(combined_email_signal,3))
        st.write("Coordinator decision:", "PHISHING" if pred else "SAFE")