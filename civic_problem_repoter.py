# civic_issues_reporter.py
import streamlit as st
import pandas as pd
import os, uuid, hashlib
from datetime import datetime
from PIL import Image
import plotly.express as px

# ---------------- CONFIG ----------------
APP_TITLE = "Civic Issues Reporter"
APP_SUB = "Report. Track. Resolve."
DATA_FILE = "reports.csv"
USERS_FILE = "users.csv"
IMAGE_DIR = "uploaded_images"

st.set_page_config(page_title=APP_TITLE, page_icon="📍", layout="wide")

if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR)

# ---------------- UTILITIES ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if os.path.exists(USERS_FILE):
        return pd.read_csv(USERS_FILE)
    return pd.DataFrame(columns=["username", "email", "password", "role"])

def save_users(df):
    df.to_csv(USERS_FILE, index=False)

def load_data():
    if os.path.exists(DATA_FILE):
        return pd.read_csv(DATA_FILE)
    return pd.DataFrame(columns=["id", "title", "description", "category", "status", "image", "timestamp", "user"])

def save_data(df):
    df.to_csv(DATA_FILE, index=False)

def save_image(uploaded_file):
    if uploaded_file is None:
        return ""
    ext = os.path.splitext(uploaded_file.name)[1]
    filename = f"{uuid.uuid4()}{ext}"
    filepath = os.path.join(IMAGE_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filepath

# ---------------- SESSION STATE ----------------
if "user" not in st.session_state:
    st.session_state.user = None

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
        if st.button("Signup"):
            if username and email and password:
                if username in users["username"].values:
                    st.error("⚠️ Username already exists!")
                else:
                    new_user = pd.DataFrame([{
                        "username": username,
                        "email": email,
                        "password": hash_password(password),
                        "role": role
                    }])
                    users = pd.concat([users, new_user], ignore_index=True)
                    save_users(users)
                    st.success("✅ Account created! Please login.")
                    st.rerun()
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
                        "role": user_row["role"]
                    }
                    st.success(f"✅ Welcome {username}!")
                    st.rerun()
                else:
                    st.error("❌ Incorrect password.")
            else:
                st.error("❌ User not found.")

# ---------------- MAIN APP ----------------
def main_app():
    user = st.session_state.user
    df = load_data()

    # Sidebar
    with st.sidebar:
        st.markdown(f"### 👋 Welcome {user['username']}")
        st.caption(user["email"])
        if st.button("🚪 Logout"):
            st.session_state.user = None
            st.rerun()

        st.markdown("---")
        nav = st.radio("Navigation", 
                       ["Home", "Report Issue", "My Reports", "Gallery"] + (["Admin Dashboard"] if user["role"]=="Admin" else []))

    # Pages
    if nav == "Home":
        st.subheader("📌 Recent Issues")
        if df.empty:
            st.info("No reports yet.")
        else:
            for _, row in df.sort_values("timestamp", ascending=False).iterrows():
                st.markdown(f"### {row['title']}")
                st.write(row["description"])
                st.caption(f"📂 {row['category']} | 🕒 {row['timestamp']} | 👤 {row['user']} | Status: {row['status']}")
                if row["image"] and os.path.exists(row["image"]):
                    st.image(row["image"], width=250)

    elif nav == "Report Issue":
        st.subheader("📝 Report a Civic Issue")
        with st.form("report_form"):
            title = st.text_input("Issue Title")
            description = st.text_area("Description")
            category = st.selectbox("Category", ["Pothole", "Garbage", "Streetlight", "Water Leakage", "Other"])
            uploaded_file = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"])
            submitted = st.form_submit_button("Submit Report")
            if submitted:
                if title and description:
                    img_path = save_image(uploaded_file)
                    new_report = {
                        "id": str(uuid.uuid4()),
                        "title": title,
                        "description": description,
                        "category": category,
                        "status": "Pending",
                        "image": img_path,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "user": user["username"]
                    }
                    df = pd.concat([df, pd.DataFrame([new_report])], ignore_index=True)
                    save_data(df)
                    st.success("✅ Report submitted successfully!")
                else:
                    st.error("Please fill all required fields.")

    elif nav == "My Reports":
        st.subheader("📂 My Reports")
        user_reports = df[df["user"] == user["username"]]
        if user_reports.empty:
            st.info("No reports yet.")
        else:
            st.dataframe(user_reports)

    elif nav == "Gallery":
        st.subheader("🖼️ Gallery of Issues")
        imgs = df[df["image"] != ""]
        if imgs.empty:
            st.info("No images available.")
        else:
            for _, row in imgs.iterrows():
                st.image(row["image"], caption=row["title"], width=300)

    elif nav == "Admin Dashboard" and user["role"] == "Admin":
        st.subheader("📊 Admin Dashboard")
        if df.empty:
            st.info("No reports.")
        else:
            st.write("### Stats Overview")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Total Reports", len(df))
            with col2:
                st.metric("Users Reported", df["user"].nunique())

            chart = px.histogram(df, x="category", color="status", barmode="group", title="Issues by Category & Status")
            st.plotly_chart(chart, use_container_width=True)

            st.write("### Manage Reports")
            for idx, row in df.iterrows():
                with st.expander(f"{row['title']} ({row['status']})"):
                    st.write(row["description"])
                    if row["image"] and os.path.exists(row["image"]):
                        st.image(row["image"], width=250)
                    new_status = st.selectbox("Update Status", ["Pending", "In Progress", "Resolved"], 
                                              index=["Pending", "In Progress", "Resolved"].index(row["status"]), 
                                              key=row["id"])
                    if st.button("Save", key="save_"+row["id"]):
                        df.at[idx, "status"] = new_status
                        save_data(df)
                        st.success("✅ Status updated!")

            st.download_button("⬇️ Export Reports CSV", data=df.to_csv(index=False), file_name="reports.csv", mime="text/csv")

# ---------------- ROUTER ----------------
if st.session_state.user:
    main_app()
else:
    login_signup()
