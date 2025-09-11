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
    st.title("📌 Welcome to Civic Issues Reporter Pro")
    st.markdown("""
    **Guide & Features:**
    1. Report civic issues with photos and details.
    2. Track your reports and their progress.
    3. Like/Dislike, feedback, and report other users’ issues.
    4. Admin analytics and full dashboard.
    5. Contact support for any help.
    """)
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
                        "role": user_row["role"],
                        "phone": user_row.get("phone",""),
                        "profile_image": user_row.get("profile_image","")
                    }
                    st.success(f"✅ Welcome {username}!")
                    st.rerun()
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
            st.rerun()

        st.markdown("---")
        if user["role"] == "Admin":
            pages = ["Dashboard", "Reports", "Users Management", "Analytics", "Notifications", "Profile", "Feedback & Support"]
        else:
            pages = ["Home", "Report Issue", "My Reports", "Notifications", "Profile", "Contact Support", "Feedback"]
        nav = st.radio("Navigation", pages)

    # ===================== USER PAGES =====================
    if user["role"] != "Admin":
        if nav == "Home":
            st.subheader("📌 Recent Issues")
            if df.empty:
                st.info("No reports yet.")
            else:
                sorted_df = df.sort_values("timestamp", ascending=False)
                for _, row in sorted_df.iterrows():
                    st.markdown(f"### {row['title']}")
                    st.write(row["description"])
                    st.caption(f"📍 {row['location']} | 📂 {row['category']} | 🕒 {row['timestamp']} | 👤 {row['user']} | Status: {row['status']} | 🚦 Severity: {row['severity']}")
                    if row["image"] and os.path.exists(row["image"]):
                        st.image(row["image"], width=250)

                    # Like/Dislike
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button(f"👍 Like {row['id']}"):
                            df.at[df['id']==row['id'],'likes'] = df.at[df['id']==row['id'],'likes'].fillna(0) +1
                            save_data(df)
                            notif = load_notifications()
                            notif = pd.concat([notif, pd.DataFrame([{"user": row['user'], "message": f"{user['username']} liked your report '{row['title']}'", "timestamp": datetime.now()}])], ignore_index=True)
                            save_notifications(notif)
                            st.success("You liked this report.")
                    with col2:
                        if st.button(f"👎 Dislike {row['id']}"):
                            df.at[df['id']==row['id'],'dislikes'] = df.at[df['id']==row['id'],'dislikes'].fillna(0) +1
                            save_data(df)
                            notif = load_notifications()
                            notif = pd.concat([notif, pd.DataFrame([{"user": row['user'], "message": f"{user['username']} disliked your report '{row['title']}'", "timestamp": datetime.now()}])], ignore_index=True)
                            save_notifications(notif)
                            st.warning("You disliked this report.")

        elif nav == "Report Issue":
            st.subheader("📝 Report a Civic Issue")
            with st.form("report_form"):
                title = st.text_input("Issue Title")
                description = st.text_area("Description")
                category = st.selectbox("Category", list(SEVERITY_MAPPING.keys()))
                location = st.text_input("Location")
                phone = st.text_input("Phone Number")
                uploaded_file = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"])
                submitted = st.form_submit_button("Submit Report")

                if submitted:
                    if uploaded_file is None:
                        st.warning("⚠️ Please upload an image (png, jpg, jpeg).")
                    else:
                        img_path = save_image(uploaded_file)
                        if img_path is None:
                            st.warning("⚠️ Invalid image format. Upload png/jpg/jpeg only.")
                        else:
                            # check duplicate
                            dup = df[(df['title']==title) & (df['description']==description) & (df['user']==user['username'])]
                            if not dup.empty:
                                st.warning("⚠️ You have already submitted this report!")
                            else:
                                severity = SEVERITY_MAPPING.get(category,"Medium")
                                new_report = {
                                    "id": str(uuid.uuid4()),
                                    "title": title,
                                    "description": description,
                                    "category": category,
                                    "status": "Pending",
                                    "image": img_path,
                                    "timestamp": datetime.now(),
                                    "user": user["username"],
                                    "location": location,
                                    "severity": severity,
                                    "phone": phone,
                                    "likes": 0,
                                    "dislikes": 0
                                }
                                df = pd.concat([df, pd.DataFrame([new_report])], ignore_index=True)
                                save_data(df)
                                st.success("✅ Report submitted successfully!")
                                st.info(f"🚦 Severity: **{severity}**")

        elif nav == "My Reports":
            st.subheader("📂 My Reports")
            user_reports = df[df["user"]==user["username"]]
            if user_reports.empty:
                st.info("No reports yet.")
            else:
                for _, row in user_reports.iterrows():
                    st.markdown(f"### {row['title']}")
                    st.write(row["description"])
                    st.caption(f"📍 {row['location']} | 📂 {row['category']} | 🕒 {row['timestamp']} | Status: {row['status']} | 🚦 Severity: {row['severity']}")
                    if row["image"] and os.path.exists(row["image"]):
                        st.image(row["image"], width=250)

                    # Update report
                    with st.expander("Update Report"):
                        new_desc = st.text_area("Edit Description", value=row["description"])
                        new_status = st.selectbox("Status (not editable by user)", options=["Pending","In Progress","Resolved"], index=["Pending","In Progress","Resolved"].index(row["status"]), key=row['id'])
                        update_btn = st.button("Update Report", key=f"update_{row['id']}")
                        if update_btn:
                            df.loc[df['id']==row['id'],'description'] = new_desc
                            save_data(df)
                            st.success("Report updated successfully.")

        elif nav == "Notifications":
            st.subheader("🔔 Notifications")
            notif = load_notifications()
            user_notif = notif[notif['user']==user['username']]
            if user_notif.empty:
                st.info("No notifications yet.")
            else:
                for _, n in user_notif.iterrows():
                    st.write(f"{n['timestamp']} - {n['message']}")

        elif nav == "Profile":
            st.subheader("👤 My Profile")
            users.loc[users['username']==user['username'],'profile_image'] = user.get("profile_image","")
            st.text_input("Email", value=user['email'])
            st.text_input("Phone", value=user.get("phone",""))
            if user.get("profile_image") and os.path.exists(user.get("profile_image")):
                st.image(user["profile_image"], width=100)
            img = st.file_uploader("Change Profile Image", type=["png","jpg","jpeg"])
            if img:
                path = save_image(img)
                if path:
                    users.loc[users['username']==user['username'],'profile_image'] = path
                    save_users(users)
                    st.success("Profile image updated.")

        elif nav == "Contact Support":
            st.subheader("📩 Contact Support")
            st.markdown(f"Admin Email: {ADMIN_EMAIL}")
            with st.form("support_form"):
                msg = st.text_area("Your Issue")
                submitted = st.form_submit_button("Submit")
                if submitted and msg:
                    support = load_support()
                    support = pd.concat([support,pd.DataFrame([{"user":user["username"],"message":msg,"timestamp":datetime.now()}])],ignore_index=True)
                    save_support(support)
                    st.success("✅ Message sent to support!")

        elif nav == "Feedback":
            st.subheader("💬 Submit Feedback")
            with st.form("feedback_form"):
                feedback_msg = st.text_area("Your Feedback")
                submitted = st.form_submit_button("Submit Feedback")
                if submitted and feedback_msg:
                    feedback = load_feedback()
                    feedback = pd.concat([feedback,pd.DataFrame([{"user":user["username"],"message":feedback_msg,"timestamp":datetime.now()}])],ignore_index=True)
                    save_feedback(feedback)
                    st.success("✅ Feedback submitted!")

# ===================== ADMIN PAGES =====================
    else:
        if nav == "Dashboard":
            admin_dashboard(df, users)

        elif nav == "Reports":
            st.subheader("📂 All Reports")
            for _, row in df.iterrows():
                st.markdown(f"### {row['title']}")
                st.write(row["description"])
                st.caption(f"📍 {row['location']} | 📂 {row['category']} | 🕒 {row['timestamp']} | 👤 {row['user']} | Status: {row['status']} | 🚦 Severity: {row['severity']}")
                if row["image"] and os.path.exists(row["image"]):
                    st.image(row["image"], width=250)
                #
