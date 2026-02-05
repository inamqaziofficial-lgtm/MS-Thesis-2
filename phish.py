import streamlit as st
import joblib, socket, ssl, math, tldextract, re
import whois, dns.resolver
from datetime import datetime

URL_BLEND = 0.3
THRESHOLD = 0.5

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

def verdict(p):
    return "PHISHING" if p >= THRESHOLD else "SAFE"

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
    if mentioned:=info["domain_age_days"] is not None and info["domain_age_days"] < 30: score += 1
    if not info["resolved_ips"]: score += 1
    if not info["cert_present"]: score += 1
    if info["entropy"] > 3.5: score += 1
    return score / 4

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

    report["SPF"] = "PASS" if spf and "pass" in spf.group(0).lower() else "FAIL"
    report["DKIM"] = "PASS" if dkim and "pass" in dkim.group(0).lower() else "FAIL"
    report["DMARC"] = "PASS" if dmarc and "pass" in dmarc.group(0).lower() else "FAIL"

    from_addr, reply_addr = extract_email(header)
    report["From/Reply-To"] = "PASS" if (not reply_addr or from_addr.split("@")[1] == reply_addr.split("@")[1]) else "FAIL"
    report["Received hops"] = "PASS" if len(received) >= 2 else "FAIL"

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
# MODE 1: URL ONLY
# =========================================================
if mode == "URL Detection":
    url = st.text_input("Enter URL")

    if st.button("Analyze URL"):
        info = extract_domain_info(url)
        rule_p = rule_based_score(info)
        ml_p = models["url_agent"].predict_proba(models["url_vectorizer"].transform([url]))[0][1]

        final = URL_BLEND*ml_p + (1-URL_BLEND)*rule_p
        pred = models["coordinator_agent"].predict([[final,0,1,0]])[0]

        st.metric("Final URL Risk", round(final,3))
        st.write("Decision:", verdict(pred))

# =========================================================
# MODE 2: EMAIL ONLY
# =========================================================
elif mode == "Email Detection":
    content = st.text_area("Email Content")
    header = st.text_area("Email Header")

    if st.button("Analyze Email"):
        email_p = models["email_agent"].predict_proba(models["email_vectorizer"].transform([content]))[0][1]
        header_p, report = header_risk_score(header)

        combined = max(email_p, header_p)
        pred = models["coordinator_agent"].predict([[0,combined,0,1]])[0]

        st.metric("Final Email Risk", round(combined,3))
        st.write("Decision:", verdict(pred))

# =========================================================
# MODE 3: COMBINED (⭐ THIS IS THE NEW PART ⭐)
# =========================================================
else:
    st.subheader("🔗 URL Input")
    url = st.text_input("Enter URL")

    st.subheader("📧 Email Content")
    content = st.text_area("Email Content")

    st.subheader("📩 Email Header (optional)")
    header = st.text_area("Email Header")

    if st.button("Analyze FULL ATTACK VECTOR"):
        # URL agents
        info = extract_domain_info(url)
        url_rule_p = rule_based_score(info)
        url_ml_p = models["url_agent"].predict_proba(
            models["url_vectorizer"].transform([url])
        )[0][1]
        url_final = URL_BLEND*url_ml_p + (1-URL_BLEND)*url_rule_p

        # Email agents
        email_p = models["email_agent"].predict_proba(
            models["email_vectorizer"].transform([content])
        )[0][1]
        header_p, report = header_risk_score(header) if header else (0,{})
        email_final = max(email_p, header_p)

        # Coordinator sees EVERYTHING
        meta = [[url_final, email_final, 1, 1]]
        pred = models["coordinator_agent"].predict(meta)[0]

        st.subheader("🧠 Agent Scores")
        st.write(f"URL Agent → {round(url_final,3)} ({verdict(url_final)})")
        st.write(f"Email Agent → {round(email_final,3)} ({verdict(email_final)})")

        st.metric("🚨 FINAL COORDINATOR DECISION", verdict(pred))

        if report:
            st.subheader("📋 Header Rule Report")
            for k,v in report.items():
                st.write(f"{k}: {v}")
