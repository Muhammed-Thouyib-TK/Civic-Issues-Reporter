import streamlit as st
import pandas as pd
import os, uuid, hashlib
from datetime import datetime
from PIL import Image
import plotly.express as px

# ---------------- CONFIG ----------------
APP_TITLE = "Civic Issues Reporter Pro"
APP_SUB = "Report. Track. Resolve. Analyze."
DATA_FILE = "reports.csv"
USERS_FILE = "users.csv"
NOTIFICATION_FILE = "notifications.csv"
FEEDBACK_FILE = "feedback.csv"
SUPPORT_FILE = "support.csv"
IMAGE_DIR = "uploaded_images"
ADMIN_EMAIL = "admin@civicreporter.com"

st.set_page_config(page_title=APP_TITLE, page_icon="📍", layout="wide")

if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR)

# ---------------- STATIC SEVERITY ----------------
SEVERITY_MAPPING = {
    "Pothole": "High",
    "Garbage": "Medium",
    "Streetlight": "Low",
    "Water Leakage": "High",
    "Noise": "Medium",
    "Medical Facilities Lack": "High",
    "Drought": "High",
    "Drinking Water Issue": "High",
    "Other": "Medium"
}

# ---------------- UTILITIES ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if os.path.exists(USERS_FILE):
        return pd.read_csv(USERS_FILE)
    return pd.DataFrame(columns=["username", "email", "password", "role", "phone", "profile_image"])

def save_users(df):
    df.to_csv(USERS_FILE, index=False)

def load_data():
    if os.path.exists(DATA_FILE):
        df = pd.read_csv(DATA_FILE)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
        return df
    return pd.DataFrame(columns=[
        "id", "title", "description", "category", "status",
        "image", "timestamp", "user", "location", "severity", "phone",
        "likes", "dislikes"
    ])

def save_data(df):
    df.to_csv(DATA_FILE, index=False)

def load_notifications():
    if os.path.exists(NOTIFICATION_FILE):
        return pd.read_csv(NOTIFICATION_FILE)
    return pd.DataFrame(columns=["user", "message", "timestamp"])

def save_notifications(df):
    df.to_csv(NOTIFICATION_FILE, index=False)

def load_feedback():
    if os.path.exists(FEEDBACK_FILE):
        return pd.read_csv(FEEDBACK_FILE)
    return pd.DataFrame(columns=["user", "message", "timestamp"])

def save_feedback(df):
    df.to_csv(FEEDBACK_FILE, index=False)

def load_support():
    if os.path.exists(SUPPORT_FILE):
        return pd.read_csv(SUPPORT_FILE)
    return pd.DataFrame(columns=["user", "message", "timestamp"])

def save_support(df):
    df.to_csv(SUPPORT_FILE, index=False)

def save_image(uploaded_file):
    if uploaded_file is None:
        return ""
    ext = os.path.splitext(uploaded_file.name)[1].lower()
    if ext not in [".png", ".jpg", ".jpeg"]:
        return None
    filename = f"{uuid.uuid4()}{ext}"
    filepath = os.path.join(IMAGE_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filepath

# ---------------- SESSION STATE ----------------
if "user" not in st.session_state:
    st.session_state.user = None
if "intro" not in st.session_state:
    st.session_state.intro = True

# ---------------- INTRO PAGE ----------------
def intro_page():
    st.markdown(
        """
        <div style="text-align:center;">
        <h1>📌 Welcome to Civic Issues Reporter Pro</h1>
        <p><b>Guide & Features:</b></p>
        <p>1. Report civic issues with photos and details.<br>
        2. Track your reports and their progress.<br>
        3. Like/Dislike, feedback, and report other users’ issues.<br>
        4. Admin analytics and full dashboard.<br>
        5. Contact support for any help.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    st.markdown(
        '<div style="text-align:center;">'
        '<button onclick="window.parent.location.reload();">➡️ Next</button>'
        '</div>',
        unsafe_allow_html=True
    )
    if st.button("➡️ Next"):
        st.session_state.intro = False
        st.experimental_rerun()

# ---------------- LOGIN / SIGNUP ----------------
def login_signup():
    st.markdown("## 🔑 Login or Signup")
    option = st.radio("Choose an option", ["Login", "Signup"], horizontal=True)

    users = load_users()

    if option == "Signup":
        st.subheader("🆕 Create Account")
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        role = st.selectbox("Role", ["User", "Admin"])
        phone = st.text_input("Phone Number")
        profile_image = st.file_uploader("Profile Image", type=["png","jpg","jpeg"])
        admin_code = None
        if role == "Admin":
            admin_code = st.text_input("Enter Admin Code", type="password")

        if st.button("Signup"):
            if username and email and password:
                if username in users["username"].values:
                    st.error("⚠️ Username already exists!")
                elif role == "Admin" and admin_code != "admincode":
                    st.error("❌ Invalid Admin Code.")
                else:
                    img_path = save_image(profile_image) if profile_image else ""
                    new_user = pd.DataFrame([{
                        "username": username,
                        "email": email,
                        "password": hash_password(password),
                        "role": role,
                        "phone": phone,
                        "profile_image": img_path
                    }])
                    users = pd.concat([users, new_user], ignore_index=True)
                    save_users(users)
                    st.session_state.user = {
                        "username": username,
                        "email": email,
                        "role": role,
                        "phone": phone,
                        "profile_image": img_path
                    }
                    st.success("✅ Account created & logged in successfully!")
                    st.experimental_rerun()
            else:
                st.warning("Please fill all fields!")

    else:  # Login
        st.subheader("🔐 Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if username in users["username"].values:
                user_row = users[users["username"] == username].iloc[0]
                if user_row["password"] == hash_password(password):
                    st.session_state.user = {
                        "username": user_row["username"],
                        "email": user_row["email"],
                        "role": user_row["role"],
                        "phone": user_row.get("phone",""),
                        "profile_image": user_row.get("profile_image","")
                    }
                    st.success(f"✅ Welcome {username}!")
                    st.experimental_rerun()
                else:
                    st.error("❌ Incorrect password.")
            else:
                st.error("❌ User not found.")

# ---------------- ADMIN DASHBOARD ----------------
def admin_dashboard(df, users):
    st.subheader("📊 Admin Dashboard")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Reports", len(df))
    with col2:
        st.metric("Users Reported", df["user"].nunique())
    with col3:
        st.metric("Locations Covered", df["location"].nunique())

    if not df.empty:
        severity_count = df["severity"].value_counts().reset_index()
        severity_count.columns = ["Severity", "Count"]
        fig1 = px.pie(severity_count, names="Severity", values="Count", title="Severity Distribution")
        st.plotly_chart(fig1, use_container_width=True)

        fig2 = px.histogram(df, x="category", color="status", barmode="group", title="Category vs Status")
        st.plotly_chart(fig2, use_container_width=True)

        df_time = df.dropna(subset=["timestamp"])
        if not df_time.empty:
            time_group = df_time.groupby(df_time["timestamp"].dt.date).size().reset_index(name="Reports")
            fig3 = px.line(time_group, x="timestamp", y="Reports", title="Reports Over Time")
            st.plotly_chart(fig3, use_container_width=True)

        loc_counts = df["location"].value_counts().reset_index()
        loc_counts.columns = ["Location", "Reports"]
        fig4 = px.bar(loc_counts, x="Location", y="Reports", title="Reports by Location")
        st.plotly_chart(fig4, use_container_width=True)

        top_users = df["user"].value_counts().reset_index()
        top_users.columns = ["User", "Reports"]
        fig5 = px.bar(top_users, x="User", y="Reports", title="Top Reporters")
        st.plotly_chart(fig5, use_container_width=True)
    else:
        st.info("No report data available to analyze.")

    st.markdown("### 🔹 Download Data")
    st.download_button("📥 Download Reports CSV", data=df.to_csv(index=False).encode('utf-8'), file_name="reports.csv", mime="text/csv")
    st.download_button("📥 Download Users CSV", data=users.to_csv(index=False).encode('utf-8'), file_name="users.csv", mime="text/csv")

# ---------------- MAIN APP ----------------
def main_app():
    user = st.session_state.user
    df = load_data()
    users = load_users()

    # Sidebar
    with st.sidebar:
        st.markdown(f"### 👋 Welcome {user['username']}")
        st.caption(user["email"])
        if user.get("profile_image") and os.path.exists(user["profile_image"]):
            st.image(user["profile_image"], width=80)
        if st.button("🚪 Logout"):
            st.session_state.user = None
            st.experimental_rerun()

        st.markdown("---")
        if user["role"] == "Admin":
            pages = ["Dashboard", "Reports", "Users Management", "Analytics", "Notifications", "Profile", "Feedback & Support"]
        else:
            pages = ["Home", "Report Issue", "My Reports", "Notifications", "Profile", "Contact Support", "Feedback"]
        nav = st.radio("Navigation", pages)

    # ===================== USER PAGES =====================
    if user["role"] != "Admin":
        # ... Implement all user pages here (Home, Report Issue, My Reports, Notifications, Profile, Contact Support, Feedback)
        pass

    # ===================== ADMIN PAGES =====================
    else:
        # ... Implement all admin pages here (Dashboard, Reports, Users Management, Analytics, Notifications, Profile, Feedback & Support)
        pass

# ---------------- ROUTER ----------------
if st.session_state.intro:
    intro_page()
else:
    if st.session_state.user:
        main_app()
    else:
        login_signup()
