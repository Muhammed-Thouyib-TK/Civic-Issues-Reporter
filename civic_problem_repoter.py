# civic_problem_reporter_pro.py
# Ultra Pro version of Civic Issues Reporter (single-file Streamlit app)
# Improvements over original:
# - Strong validation for username, email and password (with confirmation + strength checks)
# - Optional email verification (works if SMTP env vars provided, otherwise simulated dev flow)
# - Auto-login after successful signup
# - Robust model loading (graceful fallback if models missing)
# - Severity prediction integrated and visible to admins; admins can override
# - More admin pages: Dashboard, Moderation, User Management, Analytics, System Settings
# - Safer image handling (resize + save) and improved data persistence
# - Filters, search and basic pagination on public pages

import streamlit as st
import pandas as pd
import os
import uuid
import hashlib
import joblib
import re
import smtplib
import json
from datetime import datetime
from PIL import Image
import plotly.express as px
from io import BytesIO

# ---------------- CONFIG ----------------
APP_TITLE = "Civic Issues Reporter — Pro"
APP_SUB = "Report. Track. Resolve. (Pro)"
DATA_FILE = "reports.csv"
USERS_FILE = "users.csv"
IMAGE_DIR = "uploaded_images"
DEFAULT_ADMIN_CODE = os.getenv("ADMIN_CODE", "admincode")

# SMTP (optional). If these are set in environment, the app will attempt to send verification emails.
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT")) if os.getenv("SMTP_PORT") else None
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")

# Model filenames (optional)
MODEL_FILES = {
    "clf": "clf.pkl",
    "tfidf": "tfidf_vectorizer.pkl",
    "svd": "svd_transformer.pkl",
    "img_scaler": "img_scaler.pkl",
    "pca": "pca_transformer.pkl",
    "label_encoder": "label_encoder.pkl",
    "severity_mapping": "severity_mapping.pkl",
}

st.set_page_config(page_title=APP_TITLE, page_icon="📍", layout="wide")

if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR, exist_ok=True)

# ---------------- UTILITIES ----------------

def validate_email(email: str) -> bool:
    # basic but practical email regex
    if not email or not isinstance(email, str):
        return False
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def validate_username(username: str) -> bool:
    # allow letters, numbers, underscore, dot, dash, 3-20 chars
    if not username or not isinstance(username, str):
        return False
    return bool(re.match(r"^[A-Za-z0-9_.-]{3,20}$", username))


def password_strength(password: str):
    # returns score 0-5 and list of missing suggestions
    suggestions = []
    score = 0
    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("At least 8 characters")
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Include an uppercase letter")
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Include a lowercase letter")
    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Include a digit")
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Include a special character")
    return score, suggestions


def hash_password(password: str, salt: str = "") -> str:
    return hashlib.sha256((salt + password).encode()).hexdigest()


# CSV load/save with schema enforcement
DEFAULT_REPORT_COLUMNS = [
    "id", "title", "description", "category", "status", "image", "timestamp",
    "user", "location", "severity", "assigned_to", "internal_comments"
]


def load_data():
    if os.path.exists(DATA_FILE):
        df = pd.read_csv(DATA_FILE)
    else:
        df = pd.DataFrame(columns=DEFAULT_REPORT_COLUMNS)
    # ensure required cols exist
    for c in DEFAULT_REPORT_COLUMNS:
        if c not in df.columns:
            df[c] = ""
    # fill NaNs
    df = df.fillna("")
    return df


def save_data(df: pd.DataFrame):
    df.to_csv(DATA_FILE, index=False)


DEFAULT_USER_COLUMNS = ["username", "email", "password", "role", "active"]

def load_users():
    if os.path.exists(USERS_FILE):
        users = pd.read_csv(USERS_FILE)
    else:
        users = pd.DataFrame(columns=DEFAULT_USER_COLUMNS)
    for c in DEFAULT_USER_COLUMNS:
        if c not in users.columns:
            users[c] = "" if c != "active" else True
    users = users.fillna("")
    # "active" column normalize
    if users['active'].dtype != bool:
        users['active'] = users['active'].astype(bool, errors='ignore')
    return users


def save_users(df: pd.DataFrame):
    df.to_csv(USERS_FILE, index=False)


def save_image(uploaded_file) -> str:
    if uploaded_file is None:
        return ""
    name = uploaded_file.name
    ext = os.path.splitext(name)[1].lower()
    if ext not in [".jpg", ".jpeg", ".png"]:
        return ""
    filename = f"{uuid.uuid4()}{ext}"
    filepath = os.path.join(IMAGE_DIR, filename)
    try:
        img = Image.open(uploaded_file)
        # convert to RGB to avoid issues with PNG palette, etc.
        if img.mode != "RGB":
            img = img.convert("RGB")
        # resize if too large (keep aspect ratio)
        img.thumbnail((1200, 1200))
        img.save(filepath, quality=85)
        return filepath
    except Exception as e:
        # fallback: write raw bytes
        with open(filepath, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return filepath


# Optional email sending

def send_verification_email(to_email: str, code: str) -> bool:
    if SMTP_SERVER and SMTP_USER and SMTP_PASS:
        try:
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT or 587, timeout=10)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            subject = "[Civic Reporter] Your verification code"
            body = f"Your verification code is: {code}\nIf you didn't request this, ignore."
            message = f"Subject: {subject}\n\n{body}"
            server.sendmail(SMTP_USER, to_email, message)
            server.quit()
            return True
        except Exception as e:
            print("Failed to send email:", e)
            return False
    else:
        return False


# ---------------- MODEL LOADING ----------------
@st.cache_resource
def load_models():
    models = {}
    for key, fname in MODEL_FILES.items():
        try:
            if os.path.exists(fname):
                models[key] = joblib.load(fname)
        except Exception as e:
            print(f"Failed to load {fname}: {e}")
    return models

models = load_models()
MODEL_READY = 'clf' in models and 'tfidf' in models and 'label_encoder' in models
severity_mapping = models.get('severity_mapping', {}) if models else {}

# ---------------- SESSION STATE ----------------
if 'user' not in st.session_state:
    st.session_state.user = None
if 'pending_verification' not in st.session_state:
    st.session_state.pending_verification = None

# ---------------- UI HELPERS ----------------

def render_header():
    col1, col2 = st.columns([0.12, 0.88])
    with col1:
        st.image("📍", width=48)
    with col2:
        st.title(APP_TITLE)
        st.caption(APP_SUB)


# ---------------- AUTH (SIGNUP / LOGIN) ----------------

def signup_ui():
    st.subheader("🆕 Create an account")
    with st.form("signup_form"):
        col1, col2 = st.columns(2)
        with col1:
            username = st.text_input("Username", key="signup_username")
            email = st.text_input("Email", key="signup_email")
            confirm_email = st.text_input("Confirm Email", key="signup_confirm_email")
        with col2:
            password = st.text_input("Password", type="password", key="signup_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="signup_confirm_password")
            role = st.selectbox("Role", ["User", "Admin"], key="signup_role")
            admin_code = ""
            if role == "Admin":
                admin_code = st.text_input("Admin Code", type="password", key="signup_admin_code")

        submitted = st.form_submit_button("Signup")

    if submitted:
        users = load_users()
        # validation
        errors = []
        if not validate_username(username):
            errors.append("Username must be 3-20 chars and may contain letters, numbers, _, . or -")
        if username in users['username'].values:
            errors.append("Username already exists")
        if not validate_email(email):
            errors.append("Invalid email format")
        if email != confirm_email:
            errors.append("Emails do not match")
        if email in users['email'].values:
            errors.append("Email already used")
        score, suggestions = password_strength(password)
        if password != confirm_password:
            errors.append("Passwords do not match")
        if score < 3:
            errors.append("Weak password: " + ", ".join(suggestions))
        if role == 'Admin' and admin_code != DEFAULT_ADMIN_CODE:
            errors.append("Invalid Admin Code")

        if errors:
            for e in errors:
                st.error(e)
            return

        # passed checks -> email verification
        verification_code = str(uuid.uuid4().int)[:6]
        sent = send_verification_email(email, verification_code)
        st.session_state.pending_verification = {
            'username': username,
            'email': email,
            'password_hash': hash_password(password, salt=username),
            'role': role,
            'code': verification_code,
            'sent': sent
        }

        if sent:
            st.info("A verification code was sent to your email. Please enter it below to finish signup.")
        else:
            st.warning("Email sending is not configured or failed. For development, we will show the code below so you can continue. In production, set SMTP env vars to enable email delivery.")
            st.info(f"Development verification code: {verification_code}")

    # If there is pending verification, show verification input
    if st.session_state.pending_verification:
        pv = st.session_state.pending_verification
        with st.form("verify_form"):
            code_input = st.text_input("Enter verification code sent to your email", key="verify_code")
            verify_submit = st.form_submit_button("Verify & Create Account")
        if verify_submit:
            if code_input == pv['code']:
                users = load_users()
                users = users.append({
                    'username': pv['username'],
                    'email': pv['email'],
                    'password': pv['password_hash'],
                    'role': pv['role'],
                    'active': True
                }, ignore_index=True)
                save_users(users)
                # auto-login after signup
                st.session_state.user = {
                    'username': pv['username'],
                    'email': pv['email'],
                    'role': pv['role']
                }
                st.success("Account created and logged in!")
                # clear pending
                st.session_state.pending_verification = None
                st.experimental_rerun()
            else:
                st.error("Incorrect verification code")


def login_ui():
    st.subheader("🔐 Login")
    with st.form("login_form"):
        identifier = st.text_input("Username or Email", key="login_identifier")
        password = st.text_input("Password", type="password", key="login_password")
        remember = st.checkbox("Remember me")
        submitted = st.form_submit_button("Login")

    if submitted:
        users = load_users()
        # lookup by username or email
        user_row = None
        if identifier in users['username'].values:
            user_row = users[users['username'] == identifier].iloc[0]
        elif identifier in users['email'].values:
            user_row = users[users['email'] == identifier].iloc[0]

        if user_row is None:
            st.error("User not found")
            return
        if not user_row.get('active', True):
            st.error("Account disabled. Contact admin.")
            return
        if user_row['password'] == hash_password(password, salt=user_row['username']):
            st.session_state.user = {
                'username': user_row['username'],
                'email': user_row['email'],
                'role': user_row['role']
            }
            st.success(f"Welcome {user_row['username']}!")
            st.experimental_rerun()
        else:
            st.error("Incorrect password")


def login_signup():
    render_header()
    st.markdown("## 🔑 Login or Signup")
    tabs = st.tabs(["Login", "Signup"])
    with tabs[0]:
        login_ui()
    with tabs[1]:
        signup_ui()


# ---------------- MAIN APP ----------------

def main_app():
    user = st.session_state.user
    if not user:
        st.error("No user in session")
        return

    df = load_data()

    # Sidebar
    with st.sidebar:
        st.markdown(f"### 👋 Welcome {user['username']}")
        st.caption(user['email'])
        if st.button("🚪 Logout"):
            st.session_state.user = None
            st.experimental_rerun()

        st.markdown("---")
        if user['role'] == 'Admin':
            pages = [
                "Home",
                "Report Issue",
                "My Reports",
                "Gallery",
                "Admin Dashboard",
                "Moderation",
                "User Management",
                "Analytics",
                "System Settings",
            ]
        else:
            pages = [
                "Home",
                "Report Issue",
                "My Reports",
                "Gallery",
                "Account Settings",
            ]
        nav = st.radio("Navigation", pages)

    # ---------------- Home ----------------
    if nav == "Home":
        st.subheader("📌 Recent Issues")
        # filters
        col1, col2, col3 = st.columns([3, 2, 1])
        with col1:
            q = st.text_input("Search title, description or location")
        with col2:
            cat = st.multiselect("Category", options=["Pothole", "Garbage", "Streetlight", "Water Leakage", "Other"], default=None)
        with col3:
            st.write(" ")
            if st.button("Refresh"):
                st.experimental_rerun()

        filtered = df.copy()
        if q:
            mask = filtered['title'].str.contains(q, case=False, na=False) | filtered['description'].str.contains(q, case=False, na=False) | filtered['location'].str.contains(q, case=False, na=False)
            filtered = filtered[mask]
        if cat:
            filtered = filtered[filtered['category'].isin(cat)]

        if filtered.empty:
            st.info("No reports yet.")
        else:
            # show paginated
            per_page = 6
            total = len(filtered)
            page = st.number_input("Page", min_value=1, max_value=max(1, (total-1)//per_page + 1), value=1)
            start = (page-1)*per_page
            end = start + per_page
            for _, row in filtered.sort_values('timestamp', ascending=False).iloc[start:end].iterrows():
                st.markdown(f"### {row['title']}")
                st.write(row['description'])
                st.caption(f"📍 {row['location']} | 📂 {row['category']} | 🕒 {row['timestamp']} | 👤 {row['user']} | Status: {row['status']} | Severity: {row.get('severity','')}")
                if row['image'] and os.path.exists(row['image']):
                    st.image(row['image'], width=300)

    # ---------------- Report Issue ----------------
    elif nav == "Report Issue":
        st.subheader("📝 Report a Civic Issue")
        with st.form("report_form"):
            title = st.text_input("Issue Title")
            description = st.text_area("Description")
            category = st.selectbox("Category", ["Pothole", "Garbage", "Streetlight", "Water Leakage", "Other"])
            location = st.text_input("Location")
            uploaded_file = st.file_uploader("Upload Image", type=["png", "jpg", "jpeg"])
            allow_override_severity = st.checkbox("Set severity manually (optional)")
            severity_manual = None
            if allow_override_severity:
                severity_manual = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"], index=1)
            submitted = st.form_submit_button("Submit Report")

        if submitted:
            if not (title and description and location):
                st.error("Please fill required fields: title, description, location")
            else:
                # duplicate check
                duplicate = df[(df['title'].str.lower() == title.lower()) & (df['location'].str.lower() == location.lower())]
                if not duplicate.empty:
                    st.warning("⚠️ Similar report already exists. It will still be saved.")
                img_path = save_image(uploaded_file)
                issue_type_pred = None
                severity_pred = "Medium"
                if MODEL_READY:
                    try:
                        tfidf = models.get('tfidf')
                        svd = models.get('svd')
                        clf = models.get('clf')
                        label_encoder = models.get('label_encoder')
                        text_features = tfidf.transform([description])
                        if svd is not None:
                            text_features = svd.transform(text_features)
                        prediction = clf.predict(text_features)
                        issue_type_pred = label_encoder.inverse_transform(prediction)[0]
                        severity_pred = severity_mapping.get(issue_type_pred, severity_pred)
                    except Exception as e:
                        print("Prediction failed:", e)
                # if user set severity manually, use it
                if severity_manual:
                    severity_pred = severity_manual

                new_report = {
                    'id': str(uuid.uuid4()),
                    'title': title,
                    'description': description,
                    'category': category,
                    'status': 'Pending',
                    'image': img_path,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'user': user['username'],
                    'location': location,
                    'severity': severity_pred,
                    'assigned_to': "",
                    'internal_comments': "",
                }
                df = pd.concat([df, pd.DataFrame([new_report])], ignore_index=True)
                save_data(df)
                st.success("✅ Report submitted successfully!")
                if issue_type_pred:
                    st.info(f"Predicted Issue Type: **{issue_type_pred}** | Severity: **{severity_pred}**")

    # ---------------- My Reports ----------------
    elif nav == "My Reports":
        st.subheader("📂 My Reports")
        user_reports = df[df['user'] == user['username']]
        if user_reports.empty:
            st.info("No reports yet.")
        else:
            st.dataframe(user_reports.sort_values('timestamp', ascending=False))
            # allow editing description for user's own reports (only if pending)
            for idx, row in user_reports.iterrows():
                with st.expander(f"{row['title']} — {row['status']}"):
                    st.write(row['description'])
                    st.caption(f"📍 {row['location']} | Severity: {row.get('severity','')} | Posted: {row['timestamp']}")
                    if row['image'] and os.path.exists(row['image']):
                        st.image(row['image'], width=300)
                    if row['status'] == 'Pending':
                        if st.button('Withdraw Report', key='withdraw_'+row['id']):
                            df.loc[df['id'] == row['id'], 'status'] = 'Withdrawn'
                            save_data(df)
                            st.success('Report withdrawn')
                            st.experimental_rerun()

    # ---------------- Gallery ----------------
    elif nav == "Gallery":
        st.subheader("🖼️ Gallery of Issues")
        imgs = df[df['image'] != ""]
        if imgs.empty:
            st.info("No images available.")
        else:
            cols = st.columns(3)
            for i, (_, row) in enumerate(imgs.iterrows()):
                with cols[i % 3]:
                    if os.path.exists(row['image']):
                        st.image(row['image'], caption=f"{row['title']} — {row['location']}\nStatus: {row['status']}", use_column_width=True)

    # ---------------- Admin Dashboard ----------------
    elif nav == "Admin Dashboard" and user['role'] == 'Admin':
        st.subheader("📊 Admin Dashboard")
        if df.empty:
            st.info("No reports.")
        else:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Reports", len(df))
            with col2:
                st.metric("Users Reported", df['user'].nunique())
            with col3:
                st.metric("Locations Covered", df['location'].nunique())

            # Charts
            st.write("### Issues by Category & Status")
            chart1 = px.histogram(df, x="category", color="status", barmode="group")
            st.plotly_chart(chart1, use_container_width=True)

            st.write("### Issue Status Distribution")
            chart2 = px.pie(df, names="status")
            st.plotly_chart(chart2, use_container_width=True)

            st.write("### Reports by Location")
            chart3 = px.bar(df, x="location")
            st.plotly_chart(chart3, use_container_width=True)

            st.write("### Recent Reports (manage below)")
            for idx, row in df.sort_values('timestamp', ascending=False).iterrows():
                with st.expander(f"{row['title']} — {row['status']} — Severity: {row.get('severity','')}"):
                    st.write(row['description'])
                    st.caption(f"📍 {row['location']} | 👤 {row['user']} | Posted: {row['timestamp']}")
                    if row['image'] and os.path.exists(row['image']):
                        st.image(row['image'], width=300)
                    # Admin controls
                    cols = st.columns([2,2,2,2])
                    new_status = cols[0].selectbox("Status", ["Pending","In Progress","Resolved","Withdrawn"], index=["Pending","In Progress","Resolved","Withdrawn"].index(row['status']) if row['status'] in ["Pending","In Progress","Resolved","Withdrawn"] else 0, key="status_"+row['id'])
                    new_severity = cols[1].selectbox("Severity", ["Low","Medium","High","Critical"], index=["Low","Medium","High","Critical"].index(row.get('severity','Medium') if row.get('severity','Medium') in ["Low","Medium","High","Critical"] else "Medium"), key="sev_"+row['id'])
                    assigned = cols[2].text_input("Assign to (staff)", value=row.get('assigned_to',''), key="assign_"+row['id'])
                    comment = cols[3].text_input("Internal comment", value=row.get('internal_comments',''), key="comment_"+row['id'])
                    if st.button("Save", key="save_"+row['id']):
                        df.at[idx, 'status'] = new_status
                        df.at[idx, 'severity'] = new_severity
                        df.at[idx, 'assigned_to'] = assigned
                        df.at[idx, 'internal_comments'] = comment
                        save_data(df)
                        st.success("Saved")
                        st.experimental_rerun()

            st.download_button("⬇️ Export Reports CSV", data=df.to_csv(index=False), file_name="reports.csv", mime="text/csv")

    # ---------------- Moderation ----------------
    elif nav == "Moderation" and user['role'] == 'Admin':
        st.subheader("🛠️ Moderation")
        st.write("Filter and moderate reports")
        status_filter = st.multiselect("Status", options=df['status'].unique().tolist(), default=df['status'].unique().tolist())
        severity_filter = st.multiselect("Severity", options=df['severity'].unique().tolist(), default=df['severity'].unique().tolist())
        filtered = df[df['status'].isin(status_filter) & df['severity'].isin(severity_filter)]
        st.dataframe(filtered)
        if not filtered.empty:
            ids = st.multiselect("Select reports to bulk-update (by id)", options=filtered['id'].tolist())
            if ids:
                new_status = st.selectbox("New status for selected", ["Pending","In Progress","Resolved","Withdrawn"])
                if st.button("Apply"):
                    df.loc[df['id'].isin(ids), 'status'] = new_status
                    save_data(df)
                    st.success("Bulk update applied")
                    st.experimental_rerun()

    # ---------------- User Management ----------------
    elif nav == "User Management" and user['role'] == 'Admin':
        st.subheader("👥 User Management")
        users = load_users()
        st.dataframe(users)
        # Promote/demote, disable
        sel_user = st.selectbox("Select user", options=users['username'].tolist())
        if sel_user:
            row = users[users['username'] == sel_user].iloc[0]
            st.write(f"Username: {row['username']} | Email: {row['email']} | Role: {row['role']} | Active: {row.get('active',True)}")
            new_role = st.selectbox("Role", ["User","Admin"], index=["User","Admin"].index(row['role']))
            active = st.checkbox("Active", value=row.get('active', True))
            if st.button("Save user changes"):
                users.loc[users['username'] == sel_user, 'role'] = new_role
                users.loc[users['username'] == sel_user, 'active'] = active
                save_users(users)
                st.success("User updated")
                st.experimental_rerun()
            if st.button("Reset user password (generate temporary)"):
                temp = uuid.uuid4().hex[:8]
                users.loc[users['username'] == sel_user, 'password'] = hash_password(temp, salt=row['username'])
                save_users(users)
                st.info(f"Temporary password: {temp}")

    # ---------------- Analytics ----------------
    elif nav == "Analytics" and user['role'] == 'Admin':
        st.subheader("📈 Analytics")
        if df.empty:
            st.info("No data for analytics yet.")
        else:
            st.write("Top locations by reports")
            top_loc = df['location'].value_counts().reset_index().rename(columns={'index':'location','location':'count'})
            st.dataframe(top_loc.head(20))
            # simple trend: reports per day
            df['date_only'] = pd.to_datetime(df['timestamp'], errors='coerce').dt.date
            trend = df.groupby('date_only').size().reset_index(name='reports')
            fig = px.line(trend, x='date_only', y='reports', title='Reports over time')
            st.plotly_chart(fig)

    # ---------------- Account Settings ----------------
    elif nav == "Account Settings":
        st.subheader("⚙️ Account Settings")
        users = load_users()
        me = users[users['username'] == user['username']].iloc[0]
        st.write("Update your details")
        with st.form("account_form"):
            new_email = st.text_input("Email", value=me['email'])
            change_pw = st.checkbox("Change password")
            new_pw = ""
            if change_pw:
                new_pw = st.text_input("New password", type="password")
                confirm_pw = st.text_input("Confirm new password", type="password")
            submit = st.form_submit_button("Save")
        if submit:
            if new_email and new_email != me['email']:
                if not validate_email(new_email):
                    st.error("Invalid email format")
                else:
                    users.loc[users['username'] == user['username'], 'email'] = new_email
                    save_users(users)
                    st.success("Email updated")
            if change_pw and new_pw:
                score, suggestions = password_strength(new_pw)
                if score < 3:
                    st.error("Password too weak: " + ", ".join(suggestions))
                else:
                    users.loc[users['username'] == user['username'], 'password'] = hash_password(new_pw, salt=user['username'])
                    save_users(users)
                    st.success("Password updated")

    # ---------------- System Settings (Admin) ----------------
    elif nav == "System Settings" and user['role'] == 'Admin':
        st.subheader("⚙️ System Settings")
        st.write("Change admin code and view email sending configuration")
        with st.form('sys_form'):
            admin_code = st.text_input("Admin Code (set new to change)")
            smtp_info = st.checkbox("Show SMTP configuration")
            submitted = st.form_submit_button('Save')
        if submitted:
            if admin_code:
                # naive store: save to a small local file (in production use secret manager)
                try:
                    with open('.admin_code', 'w') as f:
                        f.write(admin_code)
                    st.success('Admin code saved to .admin_code (local file)')
                except Exception as e:
                    st.error('Failed to save admin code: '+str(e))
        if smtp_info:
            st.write({
                'SMTP_SERVER': SMTP_SERVER,
                'SMTP_PORT': SMTP_PORT,
                'SMTP_USER': SMTP_USER,
                'SMTP_CONFIGURED': bool(SMTP_SERVER and SMTP_USER and SMTP_PASS)
            })

    else:
        st.warning("Page not available or you don't have permission.")


# ---------------- ROUTER ----------------
if st.session_state.user:
    main_app()
else:
    # Check for .admin_code override
    if os.path.exists('.admin_code'):
        try:
            DEFAULT_ADMIN_CODE = open('.admin_code').read().strip()
        except Exception:
            pass
    login_signup()


# ---------------- DEPENDENCIES & RUN NOTES ----------------
# To run locally:
# 1) install: pip install streamlit pandas plotly pillow joblib
# 2) (optional) set SMTP env vars if you want real email verification: SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS
# 3) run: streamlit run civic_problem_reporter_pro.py
# Notes:
# - This script will work without ML models. If model files (clf.pkl etc.) are present, text-based predictions will be used.
# - Existing reports.csv/users.csv will be loaded and missing columns will be added automatically.
# - Admin code can be changed by creating a local file named .admin_code or via System Settings (saved locally).
# - For production, consider a proper database, secure password hashing & salting mechanisms, and secure secret storage for SMTP/admin codes.
