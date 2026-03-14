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
from difflib import SequenceMatcher

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="Multi-Agent Phishing Detector",
    page_icon="🛡️",
    layout="wide"
)

# =========================================================
# CLEAN PROFESSIONAL LIGHT THEME
# =========================================================
st.markdown("""
<style>
.stApp {background: linear-gradient(135deg, #F8FAFC, #E2E8F0);}
section[data-testid="stSidebar"] {background-color: #FFFFFF;border-right: 1px solid #E2E8F0;}
section[data-testid="stSidebar"] * {color: #0F172A !important;}
h1 {color: #1D4ED8 !important;text-align: center;}
h2, h3 {color: #0F766E !important;}
div[data-testid="stWidgetLabel"] {color: #0F172A !important;font-weight: 600 !important;}
textarea, input {background-color: #FFFFFF !important;color: #0F172A !important;border: 1px solid #CBD5E1 !important;border-radius: 8px !important;}
.stButton>button {background: linear-gradient(90deg,#2563EB,#3B82F6);color:white;border-radius:8px;font-weight:600;border:none;}
.stButton>button:hover {background: linear-gradient(90deg,#1D4ED8,#2563EB);}
.safe {color:#16A34A;font-weight:bold;font-size:20px;}
.phish {color:#DC2626;font-weight:bold;font-size:20px;}
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
    mode = st.radio("", ["URL Detection","Email Detection","Combined URL + Email"])
    st.markdown("---")
    st.info("Multi-Agent Architecture\n\nURL Agent\nEmail Agent\nSender Address Agent\nCoordinator Agent")

# =========================================================
# UTILITIES
# =========================================================
def shannon_entropy(s):
    if not s: return 0.0
    prob=[float(s.count(c))/len(s) for c in set(s)]
    return -sum([p*math.log2(p) for p in prob])

def to_naive(dt):
    if isinstance(dt,datetime): return dt.replace(tzinfo=None)
    return dt

# =========================================================
# DOMAIN RULE AGENT
# =========================================================
def extract_domain_info(domain):
    info={}
    now=datetime.utcnow()
    ext=tldextract.extract(domain)
    registered=ext.registered_domain or domain

    try:
        w=whois.whois(registered)
        created=w.creation_date
        if isinstance(created,list): created=created[0]
        created=to_naive(created)
        info["domain_age_days"]=(now-created).days if created else None
    except: info["domain_age_days"]=None

    try:
        a=dns.resolver.resolve(registered,'A',lifetime=5)
        info["resolved_ips"]=[r.to_text() for r in a]
    except: info["resolved_ips"]=[]

    try:
        ctx=ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(),server_hostname=registered) as s:
            s.settimeout(4)
            s.connect((registered,443))
            info["cert_present"]=True
    except: info["cert_present"]=False

    label=registered.split(".")[0]
    info["entropy"]=shannon_entropy(label)

    return info

def rule_based_score(info):
    score=0
    total=4
    if info["domain_age_days"] and info["domain_age_days"]<30: score+=1
    if not info["resolved_ips"]: score+=1
    if not info["cert_present"]: score+=1
    if info["entropy"]>3.5: score+=1
    return score/total

# =========================================================
# SENDER ADDRESS AGENT (NEW)
# =========================================================
legitimate_domains=["paypal.com","amazon.com","google.com","microsoft.com","apple.com","facebook.com"]
free_providers=["gmail.com","yahoo.com","outlook.com","hotmail.com"]
keywords=["secure","verify","update","alert","login","account","billing","support"]

def similarity(a,b):
    return SequenceMatcher(None,a,b).ratio()

def digit_ratio(text):
    digits=sum(c.isdigit() for c in text)
    return digits/len(text) if len(text)>0 else 0

def sender_email_score(email):
    try:
        local,domain=email.lower().split("@")
    except:
        return 0

    score=0
    total=6

    # brand with free provider
    if domain in free_providers:
        for b in legitimate_domains:
            if b.split(".")[0] in local:
                return 1

    # keywords
    if any(k in local or k in domain for k in keywords):
        score+=1

    # digits
    if digit_ratio(local)>0.4:
        score+=1

    # typosquatting
    for legit in legitimate_domains:
        if similarity(domain,legit)>0.85 and domain!=legit:
            score+=2

    # special characters
    if len(re.findall(r"[._\-]",local))>3:
        score+=1

    # long domain
    if len(domain)>25:
        score+=1

    return score/total

# =========================================================
# LOAD MODELS
# =========================================================
@st.cache_resource
def load_models():
    models={}
    for n in ["url_agent","email_agent","coordinator_agent","url_vectorizer","email_vectorizer"]:
        models[n]=joblib.load(f"{n}.pkl")
    return models

models=load_models()

# =========================================================
# URL MODE
# =========================================================
if mode=="URL Detection":
    url=st.text_input("Enter URL")

    if st.button("Analyze URL") and url.strip():
        info=extract_domain_info(url)
        rule_score=rule_based_score(info)

        ml_prob=models["url_agent"].predict_proba(
            models["url_vectorizer"].transform([url])
        )[0][1]

        final_prob=0.3*ml_prob+0.7*rule_score
        pred=final_prob>=0.5

        st.subheader("🔍 URL Analysis Result")
        st.progress(final_prob)

        col1,col2=st.columns(2)
        with col1:
            st.metric("Suspiciousness Score",f"{final_prob:.3f}")
        with col2:
            st.markdown('<p class="phish">🚨 PHISHING DETECTED</p>' if pred
                        else '<p class="safe">✅ SAFE URL</p>',unsafe_allow_html=True)

# =========================================================
# EMAIL MODE
# =========================================================
elif mode=="Email Detection":

    sender_email=st.text_input("Sender Email Address")
    content=st.text_area("Email Content")

    if st.button("Analyze Email") and content.strip():

        email_prob=models["email_agent"].predict_proba(
            models["email_vectorizer"].transform([content])
        )[0][1]

        sender_prob=sender_email_score(sender_email) if sender_email else 0

        combined=max(email_prob,sender_prob)
        pred=combined>=0.5

        st.subheader("📧 Email Analysis Result")
        st.progress(combined)

        col1,col2=st.columns(2)
        with col1:
            st.metric("Risk Score",f"{combined:.3f}")
        with col2:
            st.markdown('<p class="phish">🚨 PHISHING EMAIL</p>' if pred
                        else '<p class="safe">✅ SAFE EMAIL</p>',unsafe_allow_html=True)

# =========================================================
# COMBINED MODE
# =========================================================
else:

    url=st.text_input("Enter URL")
    sender_email=st.text_input("Sender Email Address")
    content=st.text_area("Email Content")

    if st.button("Analyze FULL ATTACK VECTOR"):

        if not url.strip() or not content.strip():
            st.warning("URL and Email content required.")
        else:

            url_prob=models["url_agent"].predict_proba(
                models["url_vectorizer"].transform([url])
            )[0][1]

            email_prob=models["email_agent"].predict_proba(
                models["email_vectorizer"].transform([content])
            )[0][1]

            sender_prob=sender_email_score(sender_email) if sender_email else 0

            X_meta=np.array([[url_prob,email_prob,sender_prob,1]])

            coord_prob=models["coordinator_agent"].predict_proba(X_meta)[0][1]
            coord_pred=coord_prob>=0.5

            st.subheader("🤖 Coordinator Meta-Agent Decision")
            st.progress(coord_prob)

            col1,col2=st.columns(2)
            with col1:
                st.metric("Coordinator Confidence",f"{coord_prob:.3f}")
            with col2:
                st.markdown('<p class="phish">🚨 PHISHING ATTACK</p>' if coord_pred
                            else '<p class="safe">✅ LEGITIMATE COMMUNICATION</p>',unsafe_allow_html=True)

            st.markdown("---")
            with st.expander("🔎 Detailed Agent Breakdown (Explainability)"):

                st.metric("URL ML Agent",f"{url_prob:.3f}")
                st.progress(url_prob)

                st.metric("Email ML Agent",f"{email_prob:.3f}")
                st.progress(email_prob)

                st.metric("Sender Address Agent",f"{sender_prob:.3f}")
                st.progress(sender_prob)

# =========================================================
# FOOTER
# =========================================================
st.markdown("---")
st.markdown(
    "<center>© 2026 | Multi-Agent Phishing Detection Framework | MS Thesis Project</center>",
    unsafe_allow_html=True
)
