# app.py
import streamlit as st
import pandas as pd
import os
import uuid
import hashlib
from datetime import datetime
from PIL import Image
import plotly.express as px
import io

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

# Page config
st.set_page_config(page_title=APP_TITLE, page_icon="📍", layout="wide", initial_sidebar_state="expanded")

# Ensure image dir exists
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
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def safe_read_csv(path, dtype=None):
    try:
        if os.path.exists(path):
            return pd.read_csv(path, dtype=dtype)
    except Exception:
        # attempt to read with default settings
        try:
            return pd.read_csv(path)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()

def load_users():
    df = safe_read_csv(USERS_FILE)
    if df.empty:
        df = pd.DataFrame(columns=["username", "email", "password", "role", "phone", "profile_image"])
    return df

def save_users(df):
    df.to_csv(USERS_FILE, index=False)

def load_data():
    df = safe_read_csv(DATA_FILE)
    # Ensure columns exist
    cols = ["id", "title", "description", "category", "status", "image", "timestamp", "user", "location", "severity", "phone", "likes", "dislikes"]
    for c in cols:
        if c not in df.columns:
            df[c] = pd.NA
    # Normalize types
    if not df.empty:
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
        df["likes"] = pd.to_numeric(df["likes"], errors='coerce').fillna(0).astype(int)
        df["dislikes"] = pd.to_numeric(df["dislikes"], errors='coerce').fillna(0).astype(int)
    return df[cols]

def save_data(df):
    # convert timestamp to ISO string for CSV stability
    df_copy = df.copy()
    if "timestamp" in df_copy.columns:
        df_copy["timestamp"] = df_copy["timestamp"].apply(lambda x: x.isoformat() if pd.notna(x) else "")
    df_copy.to_csv(DATA_FILE, index=False)

def load_notifications():
    df = safe_read_csv(NOTIFICATION_FILE)
    if df.empty:
        df = pd.DataFrame(columns=["user", "message", "timestamp", "read"])
    if "read" not in df.columns:
        df["read"] = False
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
    return df

def save_notifications(df):
    df_copy = df.copy()
    if "timestamp" in df_copy.columns:
        df_copy["timestamp"] = df_copy["timestamp"].apply(lambda x: x.isoformat() if pd.notna(x) else "")
    df_copy.to_csv(NOTIFICATION_FILE, index=False)

def load_feedback():
    df = safe_read_csv(FEEDBACK_FILE)
    if df.empty:
        df = pd.DataFrame(columns=["user", "message", "timestamp"])
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
    return df

def save_feedback(df):
    df_copy = df.copy()
    if "timestamp" in df_copy.columns:
        df_copy["timestamp"] = df_copy["timestamp"].apply(lambda x: x.isoformat() if pd.notna(x) else "")
    df_copy.to_csv(FEEDBACK_FILE, index=False)

def load_support():
    df = safe_read_csv(SUPPORT_FILE)
    if df.empty:
        df = pd.DataFrame(columns=["user", "message", "timestamp"])
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')
    return df

def save_support(df):
    df_copy = df.copy()
    if "timestamp" in df_copy.columns:
        df_copy["timestamp"] = df_copy["timestamp"].apply(lambda x: x.isoformat() if pd.notna(x) else "")
    df_copy.to_csv(SUPPORT_FILE, index=False)

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

def make_download_csv(df, filename="data.csv"):
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return buf.getvalue().encode('utf-8')

# ---------------- SESSION STATE ----------------
if "user" not in st.session_state:
    st.session_state.user = None
if "intro" not in st.session_state:
    st.session_state.intro = True
if "toast" not in st.session_state:
    st.session_state.toast = None

# ---------------- INTRO PAGE ----------------
def intro_page():
    st.title("📌 Welcome to Civic Issues Reporter Pro")
    st.markdown(APP_SUB)
    st.markdown("""
    **Guide & Features (advanced):**
    - Report civic issues with photos, phone and location.
    - Track status and receive notifications.
    - Admin analytics, user & report management.
    - CSV export, search, filters, pagination, broadcast notifications.
    """)
    if st.button("➡ Next"):
        st.session_state.intro = False
        st.rerun()

# ---------------- LOGIN / SIGNUP ----------------
def login_signup():
    st.markdown("## 🔑 Login or Signup")
    option = st.radio("Choose an option", ["Login", "Signup"], horizontal=True)

    users = load_users()

    if option == "Signup":
        st.subheader("🆕 Create Account")
        username = st.text_input("Username", key="signup_username")
        email = st.text_input("Email", key="signup_email")
        password = st.text_input("Password", type="password", key="signup_password")
        role = st.selectbox("Role", ["User", "Admin"], index=0, key="signup_role")
        phone = st.text_input("Phone Number", key="signup_phone")
        profile_image = st.file_uploader("Profile Image", type=["png","jpg","jpeg"], key="signup_profile")
        admin_code = None
        if role == "Admin":
            admin_code = st.text_input("Enter Admin Code", type="password", key="signup_admin_code")

        if st.button("Signup"):
            if username and email and password:
                if username in users["username"].values:
                    st.error("⚠ Username already exists!")
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
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            users = load_users()
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
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Reports", len(df))
    with col2:
        st.metric("Open Reports", int((df["status"] == "Pending").sum()))
    with col3:
        st.metric("Resolved", int((df["status"] == "Resolved").sum()))
    with col4:
        st.metric("Users", users.shape[0])

    if not df.empty:
        # Severity distribution
        severity_count = df["severity"].fillna("Unknown").value_counts().reset_index()
        severity_count.columns = ["Severity", "Count"]
        fig1 = px.pie(severity_count, names="Severity", values="Count", title="Severity Distribution")
        st.plotly_chart(fig1, use_container_width=True)

        # Category vs Status
        fig2 = px.histogram(df, x="category", color="status", barmode="group", title="Category vs Status")
        st.plotly_chart(fig2, use_container_width=True)

        # Reports over time
        df_time = df.dropna(subset=["timestamp"])
        if not df_time.empty:
            time_group = df_time.groupby(df_time["timestamp"].dt.date).size().reset_index(name="Reports")
            time_group.columns = ["date", "Reports"]
            fig3 = px.line(time_group, x="date", y="Reports", title="Reports Over Time")
            st.plotly_chart(fig3, use_container_width=True)

        # Top locations & users
        loc_counts = df["location"].fillna("Unknown").value_counts().reset_index().head(10)
        loc_counts.columns = ["Location", "Reports"]
        fig4 = px.bar(loc_counts, x="Location", y="Reports", title="Top Locations")
        st.plotly_chart(fig4, use_container_width=True)

        top_users = df["user"].fillna("Unknown").value_counts().reset_index().head(10)
        top_users.columns = ["User", "Reports"]
        fig5 = px.bar(top_users, x="User", y="Reports", title="Top Reporters")
        st.plotly_chart(fig5, use_container_width=True)
    else:
        st.info("No report data available to analyze.")

    st.markdown("### 🔹 Download Data")
    st.download_button("📥 Download Reports CSV", data=make_download_csv(df, "reports.csv"), file_name="reports.csv", mime="text/csv")
    st.download_button("📥 Download Users CSV", data=make_download_csv(users, "users.csv"), file_name="users.csv", mime="text/csv")

# ---------------- ADMIN - Reports management ----------------
def admin_reports_management(df):
    st.subheader("🛠️ Manage Reports")
    if df.empty:
        st.info("No reports available.")
        return

    # Filters
    cols = st.columns([2,2,2,2,1])
    with cols[0]:
        q = st.text_input("Search Title/Description", key="admin_search_q")
    with cols[1]:
        cat_filter = st.selectbox("Category", options=["All"] + sorted(df["category"].dropna().unique().tolist()), key="admin_cat")
    with cols[2]:
        status_filter = st.selectbox("Status", options=["All", "Pending", "In Progress", "Resolved"], key="admin_status")
    with cols[3]:
        loc_filter = st.selectbox("Location", options=["All"] + sorted(df["location"].fillna("Unknown").unique().tolist()), key="admin_loc")
    with cols[4]:
        per_page = st.number_input("Per page", min_value=5, max_value=50, value=10, step=5, key="admin_perpage")

    filt = df.copy()
    if q:
        filt = filt[filt["title"].str.contains(q, case=False, na=False) | filt["description"].str.contains(q, case=False, na=False)]
    if cat_filter and cat_filter != "All":
        filt = filt[filt["category"] == cat_filter]
    if status_filter and status_filter != "All":
        filt = filt[filt["status"] == status_filter]
    if loc_filter and loc_filter != "All":
        filt = filt[filt["location"] == loc_filter]

    filt = filt.sort_values("timestamp", ascending=False).reset_index(drop=True)
    total = len(filt)
    page = st.number_input("Page", min_value=1, max_value=max(1, (total // per_page) + 1), value=1, key="admin_page")
    start = (page - 1) * per_page
    end = start + per_page
    subset = filt.iloc[start:end]

    st.markdown(f"Showing {start+1} - {min(end, total)} of {total} reports")

    for _, row in subset.iterrows():
        st.markdown(f"### {row['title']}")
        st.write(row.get("description", ""))
        st.caption(f"📍 {row.get('location','')} | 📂 {row.get('category','')} | 🕒 {row.get('timestamp')} | 👤 {row.get('user','')} | Status: {row.get('status','')} | 🚦 {row.get('severity','')}")
        if row.get("image") and os.path.exists(row["image"]):
            st.image(row["image"], width=300)

        with st.expander("Admin Actions"):
            col1, col2, col3 = st.columns([2,2,1])
            with col1:
                new_status = st.selectbox("Change Status", options=["Pending","In Progress","Resolved"], index=["Pending","In Progress","Resolved"].index(row["status"] if row["status"] in ["Pending","In Progress","Resolved"] else "Pending"), key=f"admin_status_{row['id']}")
                if st.button("Update Status", key=f"admin_update_{row['id']}"):
                    df.loc[df['id'] == row['id'], 'status'] = new_status
                    save_data(df)
                    # notify user
                    notif = load_notifications()
                    notif = pd.concat([notif, pd.DataFrame([{"user": row['user'], "message": f"Admin changed status of your report '{row['title']}' to {new_status}", "timestamp": datetime.now(), "read": False}])], ignore_index=True)
                    save_notifications(notif)
                    st.success("Status updated and user notified.")
                    st.rerun()
            with col2:
                if st.button("Delete Report", key=f"admin_delete_{row['id']}"):
                    df = df[df['id'] != row['id']].reset_index(drop=True)
                    save_data(df)
                    st.success("Report deleted.")
                    st.rerun()
            with col3:
                st.write(f"Likes: {int(row.get('likes',0))}  Dislikes: {int(row.get('dislikes',0))}")

# ---------------- ADMIN - Users management ----------------
def admin_users_management(users):
    st.subheader("👥 Users Management")
    if users.empty:
        st.info("No users found.")
        return

    q = st.text_input("Search users (username or email)", key="users_search")
    filt = users.copy()
    if q:
        filt = filt[filt["username"].str.contains(q, case=False, na=False) | filt["email"].str.contains(q, case=False, na=False)]

    filt = filt.reset_index(drop=True)
    for _, u in filt.iterrows():
        st.markdown(f"### {u['username']}  —  {u['role']}")
        st.write(u.get("email",""))
        cols = st.columns([2,1,1])
        with cols[0]:
            new_role = st.selectbox("Role", options=["User","Admin"], index=0 if u.get("role","User")=="User" else 1, key=f"role_{u['username']}")
            if st.button("Update Role", key=f"role_update_{u['username']}"):
                users.loc[users['username']==u['username'], 'role'] = new_role
                save_users(users)
                st.success("Role updated.")
                st.rerun()
        with cols[1]:
            if st.button("Delete User", key=f"del_user_{u['username']}"):
                # prevent deleting last admin or self
                current_user = st.session_state.user.get("username") if st.session_state.user else None
                if u['username'] == current_user:
                    st.error("You cannot delete yourself.")
                else:
                    users = users[users['username'] != u['username']].reset_index(drop=True)
                    save_users(users)
                    st.success("User deleted.")
                    st.rerun()
        with cols[2]:
            if os.path.exists(u.get("profile_image","")):
                st.image(u["profile_image"], width=80)
            else:
                st.write("No image")

# ---------------- ADMIN - Notifications broadcast ----------------
def admin_notifications_page():
    st.subheader("📣 Broadcast Notifications")
    msg = st.text_area("Message to broadcast")
    target = st.selectbox("Target", options=["All Users","All Admins","All Users except Admins"], index=0)
    if st.button("Send Broadcast"):
        users = load_users()
        if users.empty:
            st.error("No users to send.")
        else:
            notif = load_notifications()
            if target == "All Users":
                targets = users["username"].tolist()
            elif target == "All Admins":
                targets = users[users["role"]=="Admin"]["username"].tolist()
            else:
                targets = users[users["role"]!="Admin"]["username"].tolist()
            new_notifs = []
            for t in targets:
                new_notifs.append({"user": t, "message": msg, "timestamp": datetime.now(), "read": False})
            if new_notifs:
                notif = pd.concat([notif, pd.DataFrame(new_notifs)], ignore_index=True)
                save_notifications(notif)
                st.success(f"Broadcast sent to {len(new_notifs)} users.")
            else:
                st.info("No matching users.")

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
        nav = st.radio("Navigation", pages, key="nav")

    # ===================== USER PAGES =====================
    if user["role"] != "Admin":
        if nav == "Home":
            st.subheader("📌 Recent Issues")
            if df.empty:
                st.info("No reports yet.")
            else:
                sorted_df = df.sort_values("timestamp", ascending=False)
                # quick filters
                f1, f2 = st.columns([3,1])
                q = f1.text_input("Search Title/Description", key="home_search")
                cat = f2.selectbox("Category", options=["All"] + list(sorted(set(df['category'].dropna().tolist()))), key="home_cat")
                view = sorted_df
                if q:
                    view = view[view["title"].str.contains(q, case=False, na=False) | view["description"].str.contains(q, case=False, na=False)]
                if cat and cat != "All":
                    view = view[view["category"] == cat]
                for _, row in view.iterrows():
                    st.markdown(f"### {row['title']}")
                    st.write(row.get("description", ""))
                    st.caption(f"📍 {row.get('location','')} | 📂 {row.get('category','')} | 🕒 {row.get('timestamp')} | 👤 {row.get('user','')}  | Status: {row.get('status','')} | 🚦 {row.get('severity','')}")
                    if row.get("image") and os.path.exists(row["image"]):
                        st.image(row["image"], width=300)

                    # Like/Dislike
                    col1, col2, col3 = st.columns([1,1,6])
                    with col1:
                        if st.button(f"👍 {row['id']}", key=f"like_{row['id']}"):
                            df.loc[df['id'] == row['id'], 'likes'] = df.loc[df['id'] == row['id'], 'likes'].fillna(0).astype(int) + 1
                            save_data(df)
                            notif = load_notifications()
                            notif = pd.concat([notif, pd.DataFrame([{"user": row['user'], "message": f"{user['username']} liked your report '{row['title']}'", "timestamp": datetime.now(), "read": False}])], ignore_index=True)
                            save_notifications(notif)
                            st.success("You liked this report.")
                            st.rerun()
                    with col2:
                        if st.button(f"👎 {row['id']}", key=f"dislike_{row['id']}"):
                            df.loc[df['id'] == row['id'], 'dislikes'] = df.loc[df['id'] == row['id'], 'dislikes'].fillna(0).astype(int) + 1
                            save_data(df)
                            notif = load_notifications()
                            notif = pd.concat([notif, pd.DataFrame([{"user": row['user'], "message": f"{user['username']} disliked your report '{row['title']}'", "timestamp": datetime.now(), "read": False}])], ignore_index=True)
                            save_notifications(notif)
                            st.warning("You disliked this report.")
                            st.rerun()
                    with col3:
                        st.write(f"Likes: {int(row.get('likes',0))}  Dislikes: {int(row.get('dislikes',0))}")

        elif nav == "Report Issue":
            st.subheader("📝 Report a Civic Issue")
            with st.form("report_form"):
                title = st.text_input("Issue Title", key="report_title")
                description = st.text_area("Description", key="report_description")
                category = st.selectbox("Category", list(SEVERITY_MAPPING.keys()), key="report_category")
                location = st.text_input("Location", key="report_location")
                phone = st.text_input("Phone Number", key="report_phone")
                uploaded_file = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"], key="report_image")
                submitted = st.form_submit_button("Submit Report")

                if submitted:
                    if not title or not description:
                        st.warning("Please provide title and description.")
                    else:
                        img_path = ""
                        if uploaded_file:
                            img_path = save_image(uploaded_file)
                            if img_path is None:
                                st.warning("⚠ Invalid image format. Upload png/jpg/jpeg only.")
                                img_path = ""
                        # duplicate check
                        dup = df[(df['title'] == title) & (df['description'] == description) & (df['user'] == user['username'])]
                        if not dup.empty:
                            st.warning("⚠ You have already submitted this report!")
                        else:
                            severity = SEVERITY_MAPPING.get(category, "Medium")
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
                            st.info(f"🚦 Severity: *{severity}*")
                            st.rerun()

        elif nav == "My Reports":
            st.subheader("📂 My Reports")
            user_reports = df[df["user"] == user["username"]].sort_values("timestamp", ascending=False)
            if user_reports.empty:
                st.info("No reports yet.")
            else:
                for _, row in user_reports.iterrows():
                    st.markdown(f"### {row['title']}")
                    st.write(row.get("description",""))
                    st.caption(f"📍 {row.get('location','')} | 📂 {row.get('category','')} | 🕒 {row.get('timestamp')} | Status: {row.get('status','')} | 🚦 {row.get('severity','')}")
                    if row.get("image") and os.path.exists(row["image"]):
                        st.image(row["image"], width=300)

                    # Update report (limited fields)
                    with st.expander("Update Report (description only)"):
                        new_desc = st.text_area("Edit Description", value=row.get("description",""), key=f"editdesc_{row['id']}")
                        update_btn = st.button("Update Report", key=f"update_{row['id']}")
                        delete_btn = st.button("Delete Report", key=f"delete_{row['id']}")
                        if update_btn:
                            df.loc[df['id'] == row['id'], 'description'] = new_desc
                            save_data(df)
                            st.success("Report updated successfully.")
                            st.rerun()
                        if delete_btn:
                            df = df[df['id'] != row['id']].reset_index(drop=True)
                            save_data(df)
                            st.success("Report deleted.")
                            st.rerun()

        elif nav == "Notifications":
            st.subheader("🔔 Notifications")
            notif = load_notifications()
            user_notif = notif[notif['user'] == user['username']].sort_values("timestamp", ascending=False)
            if user_notif.empty:
                st.info("No notifications yet.")
            else:
                for idx, n in user_notif.iterrows():
                    cols = st.columns([8,1])
                    with cols[0]:
                        st.write(f"{n.get('timestamp')} - {n.get('message')}")
                    with cols[1]:
                        if not n.get("read", False):
                            if st.button("Mark read", key=f"markread_{idx}"):
                                notif.loc[idx, "read"] = True
                                save_notifications(notif)
                                st.success("Marked as read.")
                                st.rerun()
                # Option to mark all read
                if st.button("Mark all read"):
                    notif.loc[notif['user'] == user['username'], 'read'] = True
                    save_notifications(notif)
                    st.success("All notifications marked read.")
                    st.rerun()

        elif nav == "Profile":
            st.subheader("👤 My Profile")
            users.loc[users['username'] == user['username'], 'profile_image'] = user.get("profile_image","")
            new_email = st.text_input("Email", value=user['email'], key="profile_email")
            new_phone = st.text_input("Phone", value=user.get("phone",""), key="profile_phone")
            if user.get("profile_image") and os.path.exists(user.get("profile_image")):
                st.image(user["profile_image"], width=100)
            img = st.file_uploader("Change Profile Image", type=["png","jpg","jpeg"], key="profile_img")
            if st.button("Update Profile"):
                if img:
                    path = save_image(img)
                    if path:
                        users.loc[users['username'] == user['username'], 'profile_image'] = path
                        user['profile_image'] = path
                users.loc[users['username'] == user['username'], 'email'] = new_email
                users.loc[users['username'] == user['username'], 'phone'] = new_phone
                save_users(users)
                st.session_state.user = user
                st.success("Profile updated.")
                st.rerun()

            st.markdown("---")
            st.subheader("Change Password")
            old_pwd = st.text_input("Old Password", type="password", key="old_pwd")
            new_pwd = st.text_input("New Password", type="password", key="new_pwd")
            if st.button("Change Password"):
                users = load_users()
                row = users[users['username'] == user['username']].iloc[0]
                if row['password'] == hash_password(old_pwd):
                    users.loc[users['username'] == user['username'], 'password'] = hash_password(new_pwd)
                    save_users(users)
                    st.success("Password changed.")
                else:
                    st.error("Old password incorrect.")

        elif nav == "Contact Support":
            st.subheader("📩 Contact Support")
            st.markdown(f"Admin Email: {ADMIN_EMAIL}")
            with st.form("support_form"):
                msg = st.text_area("Your Issue", key="support_msg")
                submitted = st.form_submit_button("Submit")
                if submitted and msg:
                    support = load_support()
                    support = pd.concat([support, pd.DataFrame([{"user": user["username"], "message": msg, "timestamp": datetime.now()}])], ignore_index=True)
                    save_support(support)
                    st.success("✅ Message sent to support!")

        elif nav == "Feedback":
            st.subheader("💬 Submit Feedback")
            with st.form("feedback_form"):
                feedback_msg = st.text_area("Your Feedback", key="feedback_msg")
                submitted = st.form_submit_button("Submit Feedback")
                if submitted and feedback_msg:
                    feedback = load_feedback()
                    feedback = pd.concat([feedback, pd.DataFrame([{"user": user["username"], "message": feedback_msg, "timestamp": datetime.now()}])], ignore_index=True)
                    save_feedback(feedback)
                    st.success("✅ Feedback submitted!")

    # ===================== ADMIN PAGES =====================
    else:
        if nav == "Dashboard":
            admin_dashboard(df, users)

        elif nav == "Reports":
            admin_reports_management(df)

        elif nav == "Users Management":
            admin_users_management(users)

        elif nav == "Analytics":
            admin_dashboard(df, users)

        elif nav == "Notifications":
            admin_notifications_page()

        elif nav == "Profile":
            # Admin profile same as user profile but show admin role
            st.subheader("👤 Admin Profile")
            st.write(f"Username: {user['username']}")
            st.write(f"Email: {user['email']}")
            st.write(f"Role: {user['role']}")
            users.loc[users['username'] == user['username'], 'profile_image'] = user.get("profile_image","")
            img = st.file_uploader("Change Profile Image", type=["png","jpg","jpeg"], key="admin_profile_img")
            if img:
                path = save_image(img)
                if path:
                    users.loc[users['username'] == user['username'], 'profile_image'] = path
                    save_users(users)
                    st.success("Profile image updated.")
                    st.rerun()

        elif nav == "Feedback & Support":
            st.subheader("🗂️ Feedback")
            fb = load_feedback().sort_values("timestamp", ascending=False)
            if fb.empty:
                st.info("No feedback yet.")
            else:
                for _, r in fb.iterrows():
                    st.write(f"{r.get('timestamp')} - {r.get('user')}: {r.get('message')}")
            st.markdown("---")
            st.subheader("🛟 Support Messages")
            sp = load_support().sort_values("timestamp", ascending=False)
            if sp.empty:
                st.info("No support messages.")
            else:
                for _, r in sp.iterrows():
                    st.write(f"{r.get('timestamp')} - {r.get('user')}: {r.get('message')}")

# ---------------- ROUTER ----------------
def router():
    if st.session_state.intro:
        intro_page()
    else:
        if st.session_state.user:
            try:
                main_app()
            except Exception as e:
                st.error(f"App error: {e}")
        else:
            login_signup()

if __name__ == "__main__":
    router()
