# app.py
import streamlit as st
import pandas as pd
import os, uuid, joblib, hashlib
from datetime import datetime
from PIL import Image

# ----------------------------
# Config
# ----------------------------
APP_TITLE = "Civic Issues Reporter"
APP_SUB = "Report. Track. Resolve."
LOGO_URL = "https://images.unsplash.com/photo-1526406915892-582c6d4d19f6?w=1200&q=80&auto=format&fit=crop&crop=entropy"

# Files/folders
MODELS_DIR = "."   # changed: models are in repo root
UPLOAD_DIR = "uploads"
USERS_FILE = "users.csv"
ISSUES_FILE = "issues.csv"

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ----------------------------
# Load ML artifacts
# ----------------------------
def load_artifacts():
    artifacts = {}
    try:
        artifacts["tfidf"] = joblib.load(os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl"))
        artifacts["svd"] = joblib.load(os.path.join(MODELS_DIR, "svd_transformer.pkl"))
        artifacts["clf"] = joblib.load(os.path.join(MODELS_DIR, "clf.pkl"))
        artifacts["label_encoder"] = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
    except Exception as e:
        st.error(f"Error loading ML artifacts: {e}")
        artifacts = None
    return artifacts

artifacts = load_artifacts()

# ----------------------------
# Utils
# ----------------------------
def sha256_hash(txt): 
    return hashlib.sha256(txt.encode()).hexdigest()

def ensure_csv(file, cols):
    if not os.path.exists(file):
        pd.DataFrame(columns=cols).to_csv(file, index=False)

def load_df(file, cols): 
    ensure_csv(file, cols)
    return pd.read_csv(file)

def save_df(df, file): 
    df.to_csv(file, index=False)

def predict_issue(desc):
    if artifacts:
        try:
            tfidf = artifacts["tfidf"]
            svd = artifacts["svd"]
            clf = artifacts["clf"]
            le = artifacts["label_encoder"]
            vec = tfidf.transform([desc])
            feat = svd.transform(vec)
            pred = clf.predict(feat)[0]
            label = le.inverse_transform([pred])[0]
            conf = max(clf.predict_proba(feat)[0])
            return label, conf
        except Exception as e:
            st.error(f"Prediction error: {e}")
            return "Other", 0.0
    # fallback rules
    d = desc.lower()
    if "pothole" in d: return "Pothole", 0.0
    if "garbage" in d or "trash" in d: return "Garbage", 0.0
    if "water" in d or "leak" in d: return "Water Leakage", 0.0
    if "light" in d: return "Streetlight", 0.0
    return "Other", 0.0

# ----------------------------
# Session
# ----------------------------
if "user" not in st.session_state: 
    st.session_state.user = None

def login_required():
    if st.session_state.user is None:
        st.warning("Please log in first.")
        st.stop()

# ----------------------------
# Pages
# ----------------------------
st.set_page_config(page_title=APP_TITLE, page_icon="🚨", layout="wide")

with st.sidebar:
    st.image(LOGO_URL, use_column_width=True)
    st.markdown(f"## {APP_TITLE}")
    st.markdown(APP_SUB)
    st.markdown("---")
    page = st.radio("Navigation", ["Home","Sign Up","Login","Report Issue","My Reports","Gallery","Admin","About","Logout"])

# ----------------------------
# Home
# ----------------------------
if page == "Home":
    st.title(APP_TITLE)
    st.write(APP_SUB)
    df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
    c1,c2,c3 = st.columns(3)
    c1.metric("Total Reports", len(df))
    c2.metric("Pending", (df["status"]=="Pending").sum())
    c3.metric("Resolved", (df["status"]=="Resolved").sum())

# ----------------------------
# Sign Up
# ----------------------------
elif page == "Sign Up":
    st.title("Sign Up")
    with st.form("signup"):
        u = st.text_input("Username")
        e = st.text_input("Email")
        p = st.text_input("Password", type="password")
        s = st.form_submit_button("Create Account")
        if s:
            df = load_df(USERS_FILE, ["id","username","email","pw","is_admin"])
            if u in df["username"].values: 
                st.error("Username exists")
            else:
                row = {
                    "id":str(uuid.uuid4())[:8],
                    "username":u,
                    "email":e,
                    "pw":sha256_hash(p),
                    "is_admin":False
                }
                df = pd.concat([df,pd.DataFrame([row])], ignore_index=True)
                save_df(df, USERS_FILE)
                st.success("Account created!")

# ----------------------------
# Login
# ----------------------------
elif page == "Login":
    st.title("Login")
    with st.form("login"):
        ue = st.text_input("Username or Email")
        p = st.text_input("Password", type="password")
        s = st.form_submit_button("Login")
        if s:
            df = load_df(USERS_FILE, ["id","username","email","pw","is_admin"])
            user = df[(df["username"]==ue)|(df["email"]==ue)]
            if user.empty: 
                st.error("User not found")
            else:
                row = user.iloc[0]
                if sha256_hash(p)==row["pw"]:
                    st.session_state.user = {
                        "id":row["id"],
                        "username":row["username"],
                        "is_admin":row["is_admin"]
                    }
                    st.success("Logged in!")
                else: 
                    st.error("Wrong password")

# ----------------------------
# Report Issue
# ----------------------------
elif page == "Report Issue":
    login_required()
    st.title("Report an Issue")
    with st.form("report"):
        t = st.text_input("Title")
        d = st.text_area("Description")
        f = st.file_uploader("Upload Image", type=["jpg","png","jpeg"])
        s = st.form_submit_button("Submit")
        if s:
            pred,conf = predict_issue(d)
            img_path = ""
            if f:
                fn = f"{uuid.uuid4().hex}.jpg"
                img_path = os.path.join(UPLOAD_DIR, fn)
                try:
                    image = Image.open(f)
                    image.save(img_path)
                except Exception as e:
                    st.error(f"Error saving image: {e}")
                    img_path = ""
            df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
            row = {
                "id":str(uuid.uuid4())[:8],
                "user":st.session_state.user["username"],
                "title":t,
                "desc":d,
                "pred":pred,
                "conf":conf,
                "status":"Pending",
                "created_at":datetime.now().isoformat(),
                "image":img_path
            }
            df = pd.concat([df,pd.DataFrame([row])], ignore_index=True)
            save_df(df, ISSUES_FILE)
            st.success(f"Issue reported! Predicted type: {pred} ({conf:.2f})")

# ----------------------------
# My Reports
# ----------------------------
elif page == "My Reports":
    login_required()
    st.title("My Reports")
    df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
    my = df[df["user"]==st.session_state.user["username"]]
    if my.empty: 
        st.info("No reports yet.")
    else: 
        st.dataframe(my[["id","title","pred","status","created_at"]])

# ----------------------------
# Gallery
# ----------------------------
elif page == "Gallery":
    st.title("Gallery")
    df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
    imgs = df["image"].dropna().tolist()
    for i in imgs:
        if i and os.path.exists(i): 
            st.image(i, width=300)

# ----------------------------
# Admin
# ----------------------------
elif page == "Admin":
    login_required()
    if not st.session_state.user["is_admin"]:
        st.error("Admin only!")
    else:
        st.title("Admin Dashboard")
        df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
        st.dataframe(df)
        # update
        ids = df["id"].tolist()
        if ids:
            sel = st.selectbox("Select issue to update", ids)
            new_status = st.selectbox("New status", ["Pending","In Progress","Resolved"])
            if st.button("Update"):
                df.loc[df["id"]==sel,"status"]=new_status
                save_df(df, ISSUES_FILE)
                st.success("Updated!")

# ----------------------------
# About
# ----------------------------
elif page == "About":
    st.title("About")
    st.write("This is a civic issue reporting system built with Streamlit. Users can report issues, admins can track them. ML model auto-classifies issue type.")

# ----------------------------
# Logout
# ----------------------------
elif page == "Logout":
    st.session_state.user=None
    st.success("Logged out")
