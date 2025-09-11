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
IMAGE_DIR = "uploaded_images"

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
    "Other": "Medium"
}

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
    return pd.DataFrame(columns=[
        "id", "title", "description", "category", "status",
        "image", "timestamp", "user", "location", "severity"
    ])

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
                    new_user = pd.DataFrame([{
                        "username": username,
                        "email": email,
                        "password": hash_password(password),
                        "role": role
                    }])
                    users = pd.concat([users, new_user], ignore_index=True)
                    save_users(users)
                    st.session_state.user = {
                        "username": username,
                        "email": email,
                        "role": role
                    }
                    st.success("✅ Account created & logged in successfully!")
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

# ---------------- ADMIN ANALYSIS ----------------
def admin_dashboard(df, users):
    st.subheader("📊 Admin Dashboard")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Reports", len(df))
    with col2:
        st.metric("Users Reported", df["user"].nunique())
    with col3:
        st.metric("Locations Covered", df["location"].nunique())

    st.markdown("### 🔹 Issue Analysis")

    # Severity Analysis
    st.markdown("#### Severity Distribution")
    severity_count = df["severity"].value_counts().reset_index()
    severity_count.columns = ["Severity", "Count"]
    fig1 = px.pie(severity_count, names="Severity", values="Count", title="Severity Distribution")
    st.plotly_chart(fig1, use_container_width=True)

    # Category vs Status
    st.markdown("#### Issues by Category & Status")
    fig2 = px.histogram(df, x="category", color="status", barmode="group", title="Category vs Status")
    st.plotly_chart(fig2, use_container_width=True)

    # Reports Over Time
    st.markdown("#### Reports Over Time")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    time_group = df.groupby(df["timestamp"].dt.date).size().reset_index(name="Reports")
    fig3 = px.line(time_group, x="timestamp", y="Reports", title="Reports Over Time")
    st.plotly_chart(fig3, use_container_width=True)

    # Location Analysis
    st.markdown("#### Reports by Location")
    fig4 = px.bar(df["location"].value_counts().reset_index().rename(columns={"index":"Location","location":"Reports"}), 
                  x="Location", y="Reports", title="Reports by Location")
    st.plotly_chart(fig4, use_container_width=True)

    # User Analysis
    st.markdown("#### Top Reporters")
    top_users = df["user"].value_counts().reset_index().rename(columns={"index":"User","user":"Reports"})
    fig5 = px.bar(top_users, x="User", y="Reports", title="Top Reporters")
    st.plotly_chart(fig5, use_container_width=True)

    # Download data
    st.markdown("### 🔹 Download Data")
    st.download_button("📥 Download Reports CSV", df.to_csv(index=False), file_name="reports.csv")
    st.download_button("📥 Download Users CSV", users.to_csv(index=False), file_name="users.csv")

# ---------------- MAIN APP ----------------
def main_app():
    user = st.session_state.user
    df = load_data()
    users = load_users()

    # Sidebar
    with st.sidebar:
        st.markdown(f"### 👋 Welcome {user['username']}")
        st.caption(user["email"])
        if st.button("🚪 Logout"):
            st.session_state.user = None
            st.rerun()

        st.markdown("---")
        if user["role"] == "Admin":
            pages = ["Dashboard", "Reports", "Users Management", "Gallery", "Analytics"]
        else:
            pages = ["Home", "Report Issue", "My Reports", "Gallery"]
        nav = st.radio("Navigation", pages)

    # ---------------- USER PAGES ----------------
    if user["role"] != "Admin":
        if nav == "Home":
            st.subheader("📌 Recent Issues")
            if df.empty:
                st.info("No reports yet.")
            else:
                sort_option = st.selectbox("Sort by", ["Latest", "Oldest"])
                sorted_df = df.sort_values("timestamp", ascending=(sort_option == "Oldest"))
                for _, row in sorted_df.iterrows():
                    st.markdown(f"### {row['title']}")
                    st.write(row["description"])
                    st.caption(f"📍 {row['location']} | 📂 {row['category']} | 🕒 {row['timestamp']} | 👤 {row['user']} | Status: {row['status']} | 🚦 Severity: {row['severity']}")
                    if row["image"] and os.path.exists(row["image"]):
                        st.image(row["image"], width=250)

        elif nav == "Report Issue":
            st.subheader("📝 Report a Civic Issue")
            with st.form("report_form"):
                title = st.text_input("Issue Title")
                description = st.text_area("Description")
                category = st.selectbox("Category", list(SEVERITY_MAPPING.keys()))
                location = st.text_input("Location")
                uploaded_file = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"])
                submitted = st.form_submit_button("Submit Report")
                if submitted:
                    if title and description and location:
                        img_path = save_image(uploaded_file)
                        severity = SEVERITY_MAPPING.get(category, "Medium")

                        new_report = {
                            "id": str(uuid.uuid4()),
                            "title": title,
                            "description": description,
                            "category": category,
                            "status": "Pending",
                            "image": img_path,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "user": user["username"],
                            "location": location,
                            "severity": severity
                        }
                        df = pd.concat([df, pd.DataFrame([new_report])], ignore_index=True)
                        save_data(df)
                        st.success("✅ Report submitted successfully!")
                        st.info(f"🚦 Severity: **{severity}**")
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
                    st.image(row["image"], caption=f"{row['title']} ({row['location']})", width=300)

    # ---------------- ADMIN PAGES ----------------
    else:
        if nav == "Dashboard":
            admin_dashboard(df, users)

        elif nav == "Reports":
            st.subheader("📂 All Reports")
            st.dataframe(df)

        elif nav == "Users Management":
            st.subheader("👥 All Users")
            st.dataframe(users)
            # Optionally add delete/edit users in future

        elif nav == "Gallery":
            st.subheader("🖼️ Issue Gallery")
            imgs = df[df["image"] != ""]
            if imgs.empty:
                st.info("No images available.")
            else:
                for _, row in imgs.iterrows():
                    st.image(row["image"], caption=f"{row['title']} ({row['location']})", width=300)

        elif nav == "Analytics":
            st.subheader("📊 Advanced Analytics")
            st.markdown("#### Filter & Explore Data")
            category_filter = st.multiselect("Filter by Category", options=df["category"].unique(), default=df["category"].unique())
            severity_filter = st.multiselect("Filter by Severity", options=df["severity"].unique(), default=df["severity"].unique())
            filtered_df = df[df["category"].isin(category_filter) & df["severity"].isin(severity_filter)]
            
            st.markdown("##### Reports by Category")
            fig6 = px.histogram(filtered_df, x="category", color="severity", barmode="group")
            st.plotly_chart(fig6, use_container_width=True)

            st.markdown("##### Reports Over Time")
            time_group = filtered_df.groupby(filtered_df["timestamp"].dt.date).size().reset_index(name="Reports")
            fig7 = px.line(time_group, x="timestamp", y="Reports")
            st.plotly_chart(fig7, use_container_width=True)

            st.markdown("##### Reports by Location")
            fig8 = px.bar(filtered_df["location"].value_counts().reset_index().rename(columns={"index":"Location","location":"Reports"}), 
                          x="Location", y="Reports")
            st.plotly_chart(fig8, use_container_width=True)

# ---------------- ROUTER ----------------
if st.session_state.user:
    main_app()
else:
    login_signup()
