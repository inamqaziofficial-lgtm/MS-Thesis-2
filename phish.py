import streamlit as st
import joblib

# =========================================================
# CONFIG
# =========================================================
URL_BLEND = 0.6
THRESHOLD = 0.5

# =========================================================
# LOAD MODELS
# =========================================================
@st.cache_resource
def load_models():
    models = {}
    try:
        models["url_agent"] = joblib.load("url_agent.pkl")
        models["url_vectorizer"] = joblib.load("url_vectorizer.pkl")
        models["email_agent"] = joblib.load("email_agent.pkl")
        models["email_vectorizer"] = joblib.load("email_vectorizer.pkl")
        models["coordinator_agent"] = joblib.load("coordinator_agent.pkl")
    except:
        pass
    return models


models = load_models()

# =========================================================
# HELPER FUNCTIONS
# =========================================================
def agent_verdict(prob, threshold=THRESHOLD):
    return "PHISHING" if prob >= threshold else "SAFE"


def extract_domain_info(url):
    # Dummy placeholder – keep your real implementation
    return {"url": url, "length": len(url)}


def rule_based_score(info):
    # Dummy placeholder – keep your real implementation
    return 0.7 if info["length"] > 25 else 0.2


def header_risk_score(header):
    # Dummy placeholder – keep your real implementation
    report = {
        "SPF": "Fail" if "spf=fail" in header.lower() else "Pass",
        "DKIM": "Fail" if "dkim=fail" in header.lower() else "Pass",
        "DMARC": "Fail" if "dmarc=fail" in header.lower() else "Pass"
    }
    risk = 0.8 if "fail" in " ".join(report.values()).lower() else 0.1
    return risk, report


# =========================================================
# UI
# =========================================================
st.set_page_config(page_title="Multi-Agent Phishing Detector", layout="wide")
st.title("🛡️ Multi-Agent Phishing Detector")

st.sidebar.header("Loaded Models")
for k, v in models.items():
    st.sidebar.write(f"{k}: {'✅' if v else '❌'}")

mode = st.radio("Select Mode", ["URL Detection", "Email Detection"])

# =========================================================
# URL MODE
# =========================================================
if mode == "URL Detection":
    url = st.text_input("Enter URL")

    if st.button("Analyze URL") and url:
        info = extract_domain_info(url)
        rule_score = rule_based_score(info)

        ml_prob = 0
        if models.get("url_agent"):
            v = models["url_vectorizer"].transform([url])
            ml_prob = models["url_agent"].predict_proba(v)[0][1]

        final_prob = URL_BLEND * ml_prob + (1 - URL_BLEND) * rule_score
        meta = [[final_prob, 0, 1, 0]]
        pred = models["coordinator_agent"].predict(meta)[0]

        # ===============================
        # AGENT VERDICTS
        # ===============================
        url_verdict = agent_verdict(ml_prob)
        rule_verdict = agent_verdict(rule_score)
        coord_verdict = "PHISHING" if pred else "SAFE"

        agent_decisions = [url_verdict, rule_verdict]
        disagreement = len(set(agent_decisions)) > 1

        # ===============================
        # MAIN RESULT
        # ===============================
        st.metric("Final URL Risk Score", round(final_prob, 3))
        st.write("### Coordinator Decision:", coord_verdict)

        # ===============================
        # AGENT BREAKDOWN
        # ===============================
        st.subheader("🧠 Agent-Level Decisions")
        c1, c2 = st.columns(2)

        with c1:
            st.metric("URL ML Agent", round(ml_prob, 3), url_verdict)

        with c2:
            st.metric("URL Rule Agent", round(rule_score, 3), rule_verdict)

        if disagreement:
            st.warning("⚠ Agents Disagree — Coordinator resolved the conflict")
        else:
            st.success("✅ All Agents Agree")

        # ===============================
        # DECISION TRACE
        # ===============================
        st.subheader("🧾 Decision Trace")
        trace = [
            "Input URL received",
            f"URL ML Agent → {round(ml_prob,3)} → {url_verdict}",
            f"URL Rule Agent → {round(rule_score,3)} → {rule_verdict}",
            f"Coordinator fused results → {coord_verdict}"
        ]

        for step in trace:
            st.write("•", step)

        st.json(info)


# =========================================================
# EMAIL MODE
# =========================================================
else:
    content = st.text_area("Email Content")
    header = st.text_area("Email Header")

    if st.button("Analyze Email") and content:
        email_prob = 0
        if models.get("email_agent"):
            v = models["email_vectorizer"].transform([content])
            email_prob = models["email_agent"].predict_proba(v)[0][1]

        header_prob, report = header_risk_score(header) if header else (0, {})

        combined = max(email_prob, header_prob)
        meta = [[0, combined, 0, 1]]
        pred = models["coordinator_agent"].predict(meta)[0]

        # ===============================
        # AGENT VERDICTS
        # ===============================
        email_verdict = agent_verdict(email_prob)
        header_verdict = agent_verdict(header_prob)
        coord_verdict = "PHISHING" if pred else "SAFE"

        agent_decisions = [email_verdict, header_verdict]
        disagreement = len(set(agent_decisions)) > 1

        # ===============================
        # MAIN RESULT
        # ===============================
        st.metric("Final Email Risk Score", round(combined, 3))
        st.write("### Coordinator Decision:", coord_verdict)

        # ===============================
        # AGENT BREAKDOWN
        # ===============================
        st.subheader("🧠 Agent-Level Decisions")
        c1, c2 = st.columns(2)

        with c1:
            st.metric("Email Content Agent", round(email_prob, 3), email_verdict)

        with c2:
            st.metric("Header Rule Agent", round(header_prob, 3), header_verdict)

        if disagreement:
            st.warning("⚠ Agents Disagree — Coordinator resolved the conflict")
        else:
            st.success("✅ All Agents Agree")

        # ===============================
        # DECISION TRACE
        # ===============================
        st.subheader("🧾 Decision Trace")
        trace = [
            "Email input received",
            f"Email Content Agent → {round(email_prob,3)} → {email_verdict}",
            f"Header Rule Agent → {round(header_prob,3)} → {header_verdict}",
            f"Coordinator fused results → {coord_verdict}"
        ]

        for step in trace:
            st.write("•", step)

        if report:
            st.subheader("📋 Header Rule Check Report")
            for k, v in report.items():
                st.write(f"{k}: {v}")
