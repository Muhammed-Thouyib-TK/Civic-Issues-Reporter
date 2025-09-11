import streamlit as st
import pandas as pd
import joblib
import os
from datetime import datetime
import hashlib
import matplotlib.pyplot as plt

# ----------------------------
# Config
# ----------------------------
APP_TITLE = "Civic Issues Reporter"
APP_SUB = "Report. Track. Resolve."
APP_LOGO = "https://cdn-icons-png.flaticon.com/512/6193/6193947.png"

# ----------------------------
# Helper Functions
# ----------------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def load_model(filename):
    return joblib.load(filename)

# ----------------------------
# Load Models (directly from root, not models/)
# ----------------------------
clf = load_model("clf.pkl")
tfidf = load_model("tfidf_vectorizer.pkl")
svd = load_model("svd_transformer.pkl")
img_scaler = load_model("img_scaler.pkl")
pca = load_model("pca_transformer.pkl")
label_encoder = load_model("label_encoder.pkl")
severity_mapping = load_model("severity_mapping.pkl")

# ----------------------------
# File Paths
# ----------------------------
USERS_FILE = "users.csv"
REPORTS_FILE = "reports.csv"

# Ensure files exist
if not os.path.exists(USERS_FILE):
    pd.DataFrame(columns=["username", "email", "password", "role"]).to_csv(USERS_FILE, index=False)

if not os.path.exists(REPORTS_FILE):
    pd.DataFrame(columns=["username", "issue_type", "description", "location", "severity", "timestamp"]).to_csv(REPORTS_FILE, index=False)

# ----------------------------
# App Header
# ----------------------------
st.set_page_config(page_title=APP_TITLE, page_icon="🛠️", layout="wide")
st.image(APP_LOGO, width=80)
st.title(APP_TITLE)
st.caption(APP_SUB)

# ----------------------------
# Authentication
# ----------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
    st.session_state.role = None
    st.session_state.username = None

menu = ["Login", "Sign Up", "Report Issue", "Dashboard", "Admin Panel"]
choice = st.sidebar.radio("Navigation", menu)

# ----------------------------
# Sign Up
# ----------------------------
if choice == "Sign Up":
    st.subheader("Create a New Account")
    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    role = st.selectbox("Role", ["User", "Admin"])
    admin_code = None
    if role == "Admin":
        admin_code = st.text_input("Enter Admin Code", type="password")

    if st.button("Sign Up"):
        users = pd.read_csv(USERS_FILE)

        if role == "Admin" and admin_code != "admincode":
            st.error("❌ Invalid admin code. You cannot sign up as Admin.")
        elif username in users["username"].values:
            st.error("❌ Username already exists")
        else:
            new_user = pd.DataFrame([[username, email, hash_password(password), role]], 
                                     columns=["username", "email", "password", "role"])
            users = pd.concat([users, new_user], ignore_index=True)
            users.to_csv(USERS_FILE, index=False)
            st.success("✅ Account created successfully!")
            st.info("Redirecting you to login page...")
            st.session_state.authenticated = False
            st.session_state.username = None
            st.experimental_rerun()

# ----------------------------
# Login
# ----------------------------
elif choice == "Login":
    st.subheader("Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        users = pd.read_csv(USERS_FILE)
        hashed_pw = hash_password(password)

        user_row = users[(users["username"] == username) & (users["password"] == hashed_pw)]
        if not user_row.empty:
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.role = user_row.iloc[0]["role"]
            st.success(f"✅ Welcome {username}!")
        else:
            st.error("❌ Invalid credentials")

# ----------------------------
# Report Issue
# ----------------------------
elif choice == "Report Issue":
    if not st.session_state.authenticated:
        st.warning("⚠️ Please log in first.")
    else:
        st.subheader("Report a Civic Issue")
        description = st.text_area("Describe the issue")
        location = st.text_input("Enter the location of the problem")
        issue_type = st.selectbox("Issue Type", ["Pothole", "Garbage", "Streetlight", "WaterLeak", "Noise"])

        if st.button("Submit Report"):
            # Check duplicate reports
            reports = pd.read_csv(REPORTS_FILE)
            if ((reports["issue_type"] == issue_type) & (reports["location"] == location)).any():
                st.warning("⚠️ This issue was already reported by another user. Your report is still recorded.")

            severity = severity_mapping.get(issue_type, "Medium")

            new_report = pd.DataFrame([[
                st.session_state.username, issue_type, description, location, severity, datetime.now()
            ]], columns=["username", "issue_type", "description", "location", "severity", "timestamp"])

            reports = pd.concat([reports, new_report], ignore_index=True)
            reports.to_csv(REPORTS_FILE, index=False)
            st.success("✅ Report submitted successfully!")

# ----------------------------
# Dashboard
# ----------------------------
elif choice == "Dashboard":
    if not st.session_state.authenticated:
        st.warning("⚠️ Please log in first.")
    else:
        st.subheader("📊 Your Reports")
        reports = pd.read_csv(REPORTS_FILE)
        user_reports = reports[reports["username"] == st.session_state.username]

        if user_reports.empty:
            st.info("You have not reported any issues yet.")
        else:
            st.dataframe(user_reports)

# ----------------------------
# Admin Panel
# ----------------------------
elif choice == "Admin Panel":
    if st.session_state.role != "Admin":
        st.error("❌ Access denied. Admins only.")
    else:
        st.subheader("🛠️ Admin Dashboard")

        tab1, tab2, tab3 = st.tabs(["Users", "Reports", "Analytics"])

        with tab1:
            st.write("👥 Registered Users")
            users = pd.read_csv(USERS_FILE)
            st.dataframe(users)
            st.download_button("Download Users CSV", users.to_csv(index=False), "users.csv", "text/csv")

        with tab2:
            st.write("📑 All Reports")
            reports = pd.read_csv(REPORTS_FILE)
            sort_by = st.selectbox("Sort Reports By", ["timestamp", "severity", "issue_type"])
            reports = reports.sort_values(by=sort_by, ascending=False)
            st.dataframe(reports)
            st.download_button("Download Reports CSV", reports.to_csv(index=False), "reports.csv", "text/csv")

        with tab3:
            st.write("📊 Analysis & Insights")
            reports = pd.read_csv(REPORTS_FILE)

            if reports.empty:
                st.info("No reports yet.")
            else:
                # Issues by type
                fig1, ax1 = plt.subplots()
                reports["issue_type"].value_counts().plot(kind="bar", ax=ax1, title="Issues by Type")
                st.pyplot(fig1)

                # Severity distribution
                fig2, ax2 = plt.subplots()
                reports["severity"].value_counts().plot(kind="pie", autopct='%1.1f%%', ax=ax2, title="Severity Distribution")
                st.pyplot(fig2)

                # Reports over time
                reports["timestamp"] = pd.to_datetime(reports["timestamp"])
                fig3, ax3 = plt.subplots()
                reports.groupby(reports["timestamp"].dt.date).size().plot(kind="line", ax=ax3, title="Reports Over Time")
                st.pyplot(fig3)
