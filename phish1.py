import streamlit as st
import joblib, socket, ssl, math, tldextract, re
import whois, dns.resolver
from datetime import datetime
import numpy as np

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

mode = st.radio(
    "Select Mode",
    ["URL Detection", "Email Detection", "Combined URL + Email"],
)

# =========================================================
# MODE 1: URL ONLY
# =========================================================
if mode == "URL Detection":
    url = st.text_input("Enter URL")

    if st.button("Analyze URL") and url.strip():
        info = extract_domain_info(url)
        rule_score = rule_based_score(info)

        ml_prob = models["url_agent"].predict_proba(
            models["url_vectorizer"].transform([url])
        )[0][1]

        final_prob = URL_BLEND * ml_prob + (1 - URL_BLEND) * rule_score
        meta = [[final_prob, 0, 1, 0]]
        pred = models["coordinator_agent"].predict(meta)[0]

        st.metric("URL Suspiciousness", round(final_prob, 3))
        st.write("Decision:", "PHISHING" if pred else "SAFE")

# =========================================================
# MODE 2: EMAIL ONLY (UNCHANGED)
# =========================================================
elif mode == "Email Detection":
    content = st.text_area("Email Content")
    header = st.text_area("Email Header")

    if st.button("Analyze Email") and content.strip():
        email_prob = models["email_agent"].predict_proba(
            models["email_vectorizer"].transform([content])
        )[0][1]

        header_prob, report = header_risk_score(header) if header else (0, {})
        combined = max(email_prob, header_prob)

        meta = [[0, combined, 0, 1]]
        pred = models["coordinator_agent"].predict(meta)[0]

        st.write("Email Content Agent:", round(email_prob, 3))
        st.write("Header Agent:", round(header_prob, 3))
        st.metric("Coordinator Signal", round(combined, 3))
        st.write("Decision:", "PHISHING" if pred else "SAFE")

        if report:
            st.markdown("### RULE CHECK REPORT")
            for k, v in report.items():
                st.write(f"{k}: {v}")

# =========================================================
# MODE 3: COMBINED URL + EMAIL (OLD LOGIC)
# =========================================================
else:
    url = st.text_input("Enter URL")
    content = st.text_area("Email Content")
    header = st.text_area("Email Header (optional)")

    if st.button("Analyze FULL ATTACK VECTOR"):
        if not url.strip() or not content.strip():
            st.warning("Both URL and Email content are required.")
        else:
            # ---- URL ML (PURE) ----
            url_ml_prob = models["url_agent"].predict_proba(
                models["url_vectorizer"].transform([url])
            )[0][1]

            # ---- EMAIL ML (PURE) ----
            email_ml_prob = models["email_agent"].predict_proba(
                models["email_vectorizer"].transform([content])
            )[0][1]

            # ---- COORDINATOR (EXACT OLD THESIS LOGIC) ----
            X_meta = np.array([[url_ml_prob, email_ml_prob, 1, 1]])
            coord_prob = models["coordinator_agent"].predict_proba(X_meta)[0][1]
            coord_pred = coord_prob >= 0.5

            st.subheader("🤖 Coordinator Meta-Agent Decision")
            st.metric(
                "FINAL DECISION",
                "PHISHING" if coord_pred else "SAFE"
            )
            st.write(f"Coordinator Confidence: {coord_prob:.3f}")

            # ---- SUPPORTING EXPLAINABILITY ----
            with st.expander("🔎 Agent Breakdown (Explainability)"):
                st.write(f"URL ML Agent: {url_ml_prob:.3f}")
                st.write(f"Email ML Agent: {email_ml_prob:.3f}")

                url_rule = rule_based_score(extract_domain_info(url))
                st.write(f"URL Rule Agent (supporting): {url_rule:.3f}")

                header_p, report = header_risk_score(header) if header else (0, {})
                st.write(f"Header Rule Agent (supporting): {header_p:.3f}")

                if report:
                    st.markdown("**Header Rule Report**")
                    for k, v in report.items():
                        st.write(f"{k}: {v}")
