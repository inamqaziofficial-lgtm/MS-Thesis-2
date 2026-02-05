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
    if reply_addr is None:
        report["From = Reply-To"] = "PASS"
    elif from_addr and reply_addr:
        report["From = Reply-To"] = (
            "PASS" if from_addr.split("@")[1] == reply_addr.split("@")[1] else "FAIL"
        )
    else:
        report["From = Reply-To"] = "FAIL"

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

st.sidebar.header("Loaded Models")
for k, v in models.items():
    st.sidebar.write(f"{k}: {'✅' if v else '❌'}")

mode = st.radio(
    "Select Mode",
    ["URL Detection", "Email Detection", "Combined URL + Email"],
)

# =========================================================
# MODE 1: URL ONLY
# =========================================================
if mode == "URL Detection":
    url = st.text_input("Enter URL")

    if st.button("Analyze URL") and url:
        info = extract_domain_info(url)
        rule_score = rule_based_score(info)

        ml_prob = 0
        if models["url_agent"]:
            v = models["url_vectorizer"].transform([url])
            ml_prob = models["url_agent"].predict_proba(v)[0][1]

        final_prob = URL_BLEND * ml_prob + (1 - URL_BLEND) * rule_score
        meta = [[final_prob, 0, 1, 0]]
        pred = models["coordinator_agent"].predict(meta)[0]

        st.metric("URL Suspiciousness", round(final_prob, 3))
        st.write("Coordinator decision:", "PHISHING" if pred == 1 else "SAFE")

# =========================================================
# MODE 2: EMAIL ONLY
# =========================================================
elif mode == "Email Detection":
    content = st.text_area("Email Content")
    header = st.text_area("Email Header")

    if st.button("Analyze Email") and content:
        email_prob = 0
        if models["email_agent"]:
            v = models["email_vectorizer"].transform([content])
            email_prob = models["email_agent"].predict_proba(v)[0][1]

        header_prob, report = header_risk_score(header) if header else (0, {})
        combined = max(email_prob, header_prob)

        meta = [[0, combined, 0, 1]]
        pred = models["coordinator_agent"].predict(meta)[0]

        st.metric("Email Suspiciousness", round(combined, 3))
        st.write("Coordinator decision:", "PHISHING" if pred == 1 else "SAFE")

        if report:
            st.markdown("### RULE CHECK REPORT")
            for k, v in report.items():
                st.write(f"{k}: {v}")

# =========================================================
# MODE 3: COMBINED URL + EMAIL (FIXED)
# =========================================================
else:
    st.subheader("🔗 URL Input")
    url = st.text_input("Enter URL")

    st.subheader("📧 Email Content")
    content = st.text_area("Email Content")

    st.subheader("📩 Email Header (optional)")
    header = st.text_area("Email Header")

    if st.button("Analyze FULL ATTACK VECTOR"):
        # ---------- URL AGENTS ----------
        url_final = 0
        if url:
            info = extract_domain_info(url)
            rule_p = rule_based_score(info)

            ml_p = 0
            if models["url_agent"]:
                v = models["url_vectorizer"].transform([url])
                ml_p = models["url_agent"].predict_proba(v)[0][1]

            url_final = URL_BLEND * ml_p + (1 - URL_BLEND) * rule_p

        # ---------- EMAIL AGENTS ----------
        email_final = 0
        report = {}
        if content:
            email_p = 0
            if models["email_agent"]:
                v = models["email_vectorizer"].transform([content])
                email_p = models["email_agent"].predict_proba(v)[0][1]

            header_p, report = header_risk_score(header) if header else (0, {})
            email_final = max(email_p, header_p)

        # ---------- COORDINATOR (FIXED FLAGS) ----------
        url_used = 1 if url else 0
        email_used = 1 if content else 0

        meta = [[url_final, email_final, url_used, email_used]]
        pred = models["coordinator_agent"].predict(meta)[0]

        # ---------- OUTPUT ----------
        st.subheader("🧠 Agent Scores")
        st.write(f"URL Risk Score: {round(url_final, 3)}")
        st.write(f"Email Risk Score: {round(email_final, 3)}")

        st.metric(
            "🚨 FINAL COORDINATOR DECISION",
            "PHISHING" if pred == 1 else "SAFE",
        )

        if report:
            st.subheader("📋 Header Rule Report")
            for k, v in report.items():
                st.write(f"{k}: {v}")
