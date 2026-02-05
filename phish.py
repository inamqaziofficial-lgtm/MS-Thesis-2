import streamlit as st
import joblib, socket, ssl, math, tldextract, re
import whois, dns.resolver
from datetime import datetime

URL_BLEND = 0.3

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
    if info["domain_age_days"] is not None and info["domain_age_days"] < 30: score += 1
    if not info["resolved_ips"]: score += 1
    if not info["cert_present"]: score += 1
    if info["entropy"] > 3.5: score += 1
    return score / total

# =========================================================
# EMAIL HEADER RULE AGENT
# =========================================================
def extract_email(header_text):
    f = re.findall(r"From:.*?([\w\.-]+@[\w\.-]+)", header_text, re.I)
    r = re.findall(r"Reply-To:.*?([\w\.-]+@[\w\.-]+)", header_text, re.I)
    return f[0] if f else None, r[0] if r else None

def header_rule_report(header):
    report = {}
    spf = re.search(r"spf=(\w+)", header, re.I)
    dkim = re.search(r"dkim=(\w+)", header, re.I)
    dmarc = re.search(r"dmarc=(\w+)", header, re.I)
    received = re.findall(r"^Received:", header, re.I | re.M)

    report["Rule 1 (SPF)"] = "PASS" if spf and "pass" in spf.group(0).lower() else "FAIL"
    report["Rule 2 (DKIM)"] = "PASS" if dkim and "pass" in dkim.group(0).lower() else "FAIL"
    report["Rule 3 (DMARC)"] = "PASS" if dmarc and "pass" in dmarc.group(0).lower() else "FAIL"

    from_addr, reply_addr = extract_email(header)
    if reply_addr is None:
        report["Rule 4 (From = Reply-To)"] = "PASS"
    elif from_addr and reply_addr:
        report["Rule 4 (From = Reply-To)"] = "PASS" if from_addr.split("@")[1] == reply_addr.split("@")[1] else "FAIL"
    else:
        report["Rule 4 (From = Reply-To)"] = "FAIL"

    report["Rule 5 (Received hops ≥ 2)"] = "PASS" if len(received) >= 2 else "FAIL"
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
st.set_page_config(page_title="Multi-Agent Phishing Detector", layout="wide")
st.title("🛡️ Multi-Agent Phishing Detector")

mode = st.radio(
    "Select Mode",
    ["URL Detection", "Email Detection", "Combined URL + Email"]
)

# =========================================================
# URL MODE (UNCHANGED)
# =========================================================
if mode == "URL Detection":
    url = st.text_input("Enter URL")

    if st.button("Analyze URL") and url:
        info = extract_domain_info(url)
        rule_score = rule_based_score(info)

        ml_prob = models["url_agent"].predict_proba(
            models["url_vectorizer"].transform([url])
        )[0][1]

        final_prob = URL_BLEND*ml_prob + (1-URL_BLEND)*rule_score
        meta = [[final_prob,0,1,0]]
        pred = models["coordinator_agent"].predict(meta)[0]

        st.metric("URL Suspiciousness", round(final_prob,3))
        st.write("Decision:", "PHISHING" if pred else "SAFE")

# =========================================================
# EMAIL MODE (RESTORED — EXACTLY AS ORIGINAL)
# =========================================================
elif mode == "Email Detection":
    content = st.text_area("Email Content")
    header = st.text_area("Email Header")

    if st.button("Analyze Email"):
        email_prob = models["email_agent"].predict_proba(
            models["email_vectorizer"].transform([content])
        )[0][1]

        header_prob, report = header_risk_score(header) if header else (0, {})

        combined = max(email_prob, header_prob)
        meta = [[0,combined,0,1]]
        pred = models["coordinator_agent"].predict(meta)[0]

        st.write("Email Content Agent:", round(email_prob,3))
        st.write("Header Agent:", round(header_prob,3))
        st.metric("Coordinator Signal", round(combined,3))
        st.write("Decision:", "PHISHING" if pred else "SAFE")

        if report:
            st.markdown("### RULE CHECK REPORT")
            for k,v in report.items():
                st.write(f"{k}: {v}")

# =========================================================
# COMBINED MODE (NEW — SAFE)
# =========================================================
else:
    url = st.text_input("Enter URL")
    content = st.text_area("Email Content")
    header = st.text_area("Email Header (optional)")

    if st.button("Analyze FULL ATTACK VECTOR"):
        url_score = 0
        if url:
            info = extract_domain_info(url)
            rule = rule_based_score(info)
            ml = models["url_agent"].predict_proba(
                models["url_vectorizer"].transform([url])
            )[0][1]
            url_score = URL_BLEND*ml + (1-URL_BLEND)*rule

        email_score = 0
        if content:
            email_ml = models["email_agent"].predict_proba(
                models["email_vectorizer"].transform([content])
            )[0][1]
            header_p, _ = header_risk_score(header) if header else (0,{})
            email_score = max(email_ml, header_p)

        meta = [[url_score, email_score, int(bool(url)), int(bool(content))]]
        pred = models["coordinator_agent"].predict(meta)[0]

        st.metric("FINAL DECISION", "PHISHING" if pred else "SAFE")
