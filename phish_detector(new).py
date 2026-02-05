# ================================
# Streamlit Phishing Detector (FIXED)
# Separate Email Content & Email Header
# Includes Header Rule-Check Report (SPF/DKIM/DMARC)
# ================================

import streamlit as st
import joblib, re

# ---------------- Load models ----------------
@st.cache_resource
def load_models():
    return {
        "email_agent": joblib.load("email_agent.pkl"),
        "email_vectorizer": joblib.load("email_vectorizer.pkl"),
        "coordinator_agent": joblib.load("coordinator_agent.pkl"),
    }

models = load_models()

# ---------------- Header Parsing ----------------
def parse_email_header(raw_header: str):
    header = raw_header.lower()
    parsed = {}

    parsed['spf'] = 'pass' if 'spf=pass' in header else 'fail'
    parsed['dkim'] = 'pass' if 'dkim=pass' in header else 'fail'
    parsed['dmarc'] = 'pass' if 'dmarc=pass' in header else 'fail'

    from_match = re.search(r"from:.*?<([^>]+)>", raw_header, re.IGNORECASE)
    reply_match = re.search(r"reply-to:.*?<([^>]+)>", raw_header, re.IGNORECASE)

    parsed['from_email'] = from_match.group(1) if from_match else None
    parsed['reply_to'] = reply_match.group(1) if reply_match else None

    return parsed

# ---------------- Header Rule Engine ----------------
def header_rule_check(parsed):
    rules = {}
    score = 0

    rules['SPF'] = 'PASS' if parsed['spf']=='pass' else 'FAIL'
    rules['DKIM'] = 'PASS' if parsed['dkim']=='pass' else 'FAIL'
    rules['DMARC'] = 'PASS' if parsed['dmarc']=='pass' else 'FAIL'

    if parsed['from_email'] and parsed['reply_to']:
        rules['From vs Reply-To'] = 'PASS' if parsed['from_email']==parsed['reply_to'] else 'FAIL'
    else:
        rules['From vs Reply-To'] = 'PASS'

    for v in rules.values():
        if v == 'FAIL': score += 1

    classification = 'Phishing' if score >= 2 else 'Safe Mail'
    return rules, classification

# ---------------- Email Content ML ----------------
def predict_email_content(text):
    vec = models['email_vectorizer'].transform([text])
    prob = models['email_agent'].predict_proba(vec)[:,1][0]
    return prob

# ---------------- Streamlit UI ----------------
st.set_page_config(page_title="Email Phishing Detector", layout="wide")
st.title("📧 Email Phishing Detection (Fixed Version)")

st.markdown("### 1️⃣ Email Content Analysis")
email_body = st.text_area("Paste EMAIL BODY here (no headers)", height=200)

st.markdown("### 2️⃣ Email Header Analysis")
email_header = st.text_area("Paste EMAIL HEADER here", height=200)

if st.button("Analyze Email"):
    st.markdown("---")

    # ---- Content ----
    if email_body.strip():
        content_prob = predict_email_content(email_body)
        st.subheader("📌 Email Content Result")
        st.write(f"Phishing Probability (ML): **{content_prob:.3f}**")
    else:
        content_prob = 0.0
        st.warning("Email body not provided")

    # ---- Header ----
    if email_header.strip():
        parsed = parse_email_header(email_header)
        rules, header_class = header_rule_check(parsed)

        st.subheader("📌 Parsed Header Fields")
        st.json(parsed)

        st.subheader("📌 Rule Check Report")
        for k,v in rules.items():
            st.write(f"{k}: {v}")

        st.subheader("📌 Header Decision")
        st.success(header_class)
    else:
        header_class = 'Safe Mail'
        st.warning("Email header not provided")

    # ---- Coordinator ----
    meta = [[0.0, content_prob, 0.0, 1.0]]
    final_pred = models['coordinator_agent'].predict(meta)[0]
    final_label = 'PHISHING' if final_pred==1 else 'SAFE'

    st.markdown("---")
    st.subheader("✅ FINAL DECISION")
    st.info(final_label)
