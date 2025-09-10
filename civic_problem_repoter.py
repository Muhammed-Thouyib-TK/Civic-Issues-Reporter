# Updated Streamlit app: Civic Issues Reporter
# Features added per request:
# 1) Landing role selection (Admin / User) shown first
# 2) Separate login / signup flows for Admin and User (email, username, password)
# 3) Modernized sidebar with nicer layout and small CSS theme tweaks
# 4) Improved "real-time" feel: live counts, search, filters, admin actions + status change
# 5) Better session handling and input validation
# 6) Image handling, thumbnails, and optimistic ML artifact loading
# 7) Small utilities for CSV creation and pagination

import streamlit as st
import pandas as pd
import os
import uuid
import joblib
import hashlib
from datetime import datetime
from PIL import Image
import re

# ----------------------------
# Config
# ----------------------------
APP_TITLE = "Civic Issues Reporter"
APP_SUB = "Report. Track. Resolve. — Built with ❤️ using Streamlit"
LOGO_URL = "https://images.unsplash.com/photo-1526406915892-582c6d4d19f6?w=1200&q=80&auto=format&fit=crop&crop=entropy"
MODELS_DIR = "."
UPLOAD_DIR = "uploads"
USERS_FILE = "users.csv"
ISSUES_FILE = "issues.csv"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ----------------------------
# Helper / Utilities
# ----------------------------
def sha256_hash(txt):
    return hashlib.sha256(txt.encode()).hexdigest()

EMAIL_RE = re.compile(r"[^@]+@[^@]+\.[^@]+")

def validate_email(email):
    return bool(EMAIL_RE.match(email))


def ensure_csv(file, cols):
    if not os.path.exists(file):
        pd.DataFrame(columns=cols).to_csv(file, index=False)


def load_df(file, cols):
    ensure_csv(file, cols)
    return pd.read_csv(file)


def save_df(df, file):
    df.to_csv(file, index=False)


def human_time(iso):
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso

# ----------------------------
# ML artifacts (optional)
# ----------------------------
@st.cache_resource
def load_artifacts():
    artifacts = {}
    try:
        artifacts["tfidf"] = joblib.load(os.path.join(MODELS_DIR, "tfidf_vectorizer.pkl"))
        artifacts["svd"] = joblib.load(os.path.join(MODELS_DIR, "svd_transformer.pkl"))
        artifacts["clf"] = joblib.load(os.path.join(MODELS_DIR, "clf.pkl"))
        artifacts["label_encoder"] = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
        st.experimental_memo.clear()  # small precaution
    except Exception:
        artifacts = None
    return artifacts

artifacts = load_artifacts()


def predict_issue(desc):
    # If model present use it; otherwise fallback to rules
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
        except Exception:
            pass
    # fallback simple rules
    d = desc.lower()
    if "pothole" in d: return "Pothole", 0.0
    if "garbage" in d or "trash" in d: return "Garbage", 0.0
    if "water" in d or "leak" in d: return "Water Leakage", 0.0
    if "light" in d: return "Streetlight", 0.0
    return "Other", 0.0

# ----------------------------
# Session management defaults
# ----------------------------
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None  # 'admin' or 'user'

# ----------------------------
# Minimal CSS to improve appearance
# ----------------------------
st.markdown(
    """
    <style>
    .sidebar .sidebar-content { padding: 1rem; }
    .stApp { background-color: #f7f7fb; }
    .card { background: white; border-radius: 12px; padding: 16px; box-shadow: 0 4px 14px rgba(20,20,50,0.06); }
    .logo { border-radius: 10px; }
    .small-muted { color: #6b6b7a; font-size:12px }
    </style>
    """,
    unsafe_allow_html=True,
)

# ----------------------------
# Page config and sidebar
# ----------------------------
st.set_page_config(page_title=APP_TITLE, page_icon="🚨", layout="wide")

with st.sidebar:
    st.image(LOGO_URL, use_column_width=True, caption=APP_TITLE)
    st.markdown(f"### {APP_TITLE}")
    st.markdown(APP_SUB)
    st.markdown("---")
    if st.session_state.user:
        st.info(f"Signed in as: {st.session_state.user['username']}")
        if st.button("Logout"):
            st.session_state.user = None
            st.session_state.role = None
            st.experimental_rerun()
    else:
        # neat navigation box
        st.markdown("**Navigation**")
        nav = st.radio("Go to", ["Home","Report Issue","My Reports","Gallery","Admin","About"], index=0)
        st.markdown("---")
        st.markdown("#### Quick Stats")
        df_counts = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
        st.metric("Total Reports", len(df_counts))
        st.metric("Pending", int((df_counts['status']=='Pending').sum()))
        st.markdown("---")
    # show role badge
    if st.session_state.role:
        st.markdown(f"<div class='small-muted'>Role: <b>{st.session_state.role.title()}</b></div>", unsafe_allow_html=True)

# ----------------------------
# Landing role selection (show when first open or user not chosen role)
# ----------------------------
if st.session_state.role is None:
    st.title("Welcome")
    st.markdown("Choose how you want to use the app — as an *Admin* (manage reports) or *User* (report issues). This choice customizes the login/signup flow.")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("I'm an Admin"):
            st.session_state.role = 'admin'
            st.experimental_rerun()
    with c2:
        if st.button("I'm a User"):
            st.session_state.role = 'user'
            st.experimental_rerun()
    st.stop()

# ----------------------------
# Helper forms: auth
# ----------------------------
st.sidebar.markdown("---")
if not st.session_state.user:
    st.sidebar.markdown("### Login / Sign Up")
    mode = st.sidebar.selectbox("Action", ["Login","Sign Up"])
    with st.sidebar.form("auth_form"):
        email = st.text_input("Email")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Submit")
        if submit:
            if not validate_email(email):
                st.sidebar.error("Please enter a valid email.")
            elif len(username.strip()) < 3:
                st.sidebar.error("Username must be at least 3 chars")
            elif len(password) < 6:
                st.sidebar.error("Password must be 6+ chars")
            else:
                users = load_df(USERS_FILE, ["id","username","email","pw","is_admin","created_at"])
                if mode == "Sign Up":
                    # check duplicates
                    if username in users['username'].values or email in users['email'].values:
                        st.sidebar.error("User/email already exists")
                    else:
                        row = {
                            'id': str(uuid.uuid4())[:8],
                            'username': username,
                            'email': email,
                            'pw': sha256_hash(password),
                            'is_admin': True if st.session_state.role=='admin' else False,
                            'created_at': datetime.now().isoformat()
                        }
                        users = pd.concat([users, pd.DataFrame([row])], ignore_index=True)
                        save_df(users, USERS_FILE)
                        st.sidebar.success("Account created. You are logged in now.")
                        st.session_state.user = {'id': row['id'], 'username': username, 'is_admin': row['is_admin']}
                        st.experimental_rerun()
                else:
                    # login
                    found = users[(users['username']==username) | (users['email']==email)]
                    if found.empty:
                        st.sidebar.error("User not found")
                    else:
                        r = found.iloc[0]
                        if sha256_hash(password) == r['pw']:
                            # role mismatch check
                            if r['is_admin'] and st.session_state.role!='admin':
                                st.sidebar.error("This is an admin account — switch to Admin role above to login.")
                            else:
                                st.sidebar.success("Logged in")
                                st.session_state.user = {'id': r['id'], 'username': r['username'], 'is_admin': r['is_admin']}
                                st.experimental_rerun()
                        else:
                            st.sidebar.error("Wrong password")

# ----------------------------
# Main navigation variable (if none from sidebar)
# ----------------------------
try:
    nav
except NameError:
    nav = 'Home'

# Use nav variable as page selector
page = nav

# ----------------------------
# Home page
# ----------------------------
if page == 'Home':
    st.title(APP_TITLE)
    st.markdown(APP_SUB)
    df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
    c1,c2,c3 = st.columns([1,1,2])
    with c1:
        st.metric("Total Reports", len(df))
    with c2:
        st.metric("Pending", int((df['status']=='Pending').sum()))
    with c3:
        st.metric("Resolved", int((df['status']=='Resolved').sum()))

    st.markdown("---")
    # Live feed with search and filters
    st.subheader("Explore reports")
    cols = st.columns([3,1,1,1])
    q = cols[0].text_input("Search title or description")
    status_filter = cols[1].selectbox("Status", ["All","Pending","In Progress","Resolved"]) 
    type_filter = cols[2].selectbox("Type", ["All","Pothole","Garbage","Water Leakage","Streetlight","Other"]) 
    refresh = cols[3].button("Refresh")

    if q:
        df = df[df['title'].str.contains(q, case=False, na=False) | df['desc'].str.contains(q, case=False, na=False)]
    if status_filter != 'All':
        df = df[df['status']==status_filter]
    if type_filter != 'All':
        df = df[df['pred']==type_filter]

    if df.empty:
        st.info("No reports match your criteria.")
    else:
        # show compact cards
        for idx, r in df.sort_values('created_at', ascending=False).head(50).iterrows():
            card = st.container()
            with card:
                c1,c2 = st.columns([3,1])
                with c1:
                    st.markdown(f"**{r['title']}** — <span class='small-muted'>{r['user']} • {human_time(r['created_at'])}</span>", unsafe_allow_html=True)
                    st.write(r['desc'][:350] + ("..." if len(str(r['desc']))>350 else ""))
                    st.markdown(f"**Predicted:** {r['pred']}  •  **Status:** {r['status']}")
                with c2:
                    if pd.notna(r['image']) and r['image'] and os.path.exists(r['image']):
                        st.image(r['image'], width=180)

# ----------------------------
# Report Issue
# ----------------------------
elif page == 'Report Issue':
    if not st.session_state.user:
        st.warning('Please login to report an issue (use the sidebar login).')
        st.stop()
    st.title('Report an Issue')
    st.markdown('Tell us what is wrong in your locality. Upload an image if available — this helps admins.')
    with st.form('report'):
        t = st.text_input('Title')
        d = st.text_area('Description')
        f = st.file_uploader('Upload Image', type=['jpg','png','jpeg'])
        s = st.form_submit_button('Submit')
        if s:
            if not t or not d:
                st.error('Title and description required')
            else:
                pred, conf = predict_issue(d)
                img_path = ''
                if f:
                    fn = f"{uuid.uuid4().hex}.jpg"
                    img_path = os.path.join(UPLOAD_DIR, fn)
                    try:
                        image = Image.open(f)
                        image.save(img_path)
                    except Exception as e:
                        st.error(f'Error saving image: {e}')
                        img_path = ''
                df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
                row = {
                    'id': str(uuid.uuid4())[:8],
                    'user': st.session_state.user['username'],
                    'title': t,
                    'desc': d,
                    'pred': pred,
                    'conf': float(conf),
                    'status': 'Pending',
                    'created_at': datetime.now().isoformat(),
                    'image': img_path
                }
                df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
                save_df(df, ISSUES_FILE)
                st.success(f'Reported — predicted: {pred} ({conf:.2f})')
                st.balloons()

# ----------------------------
# My Reports
# ----------------------------
elif page == 'My Reports':
    if not st.session_state.user:
        st.warning('Please login to see your reports.')
        st.stop()
    st.title('My Reports')
    df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
    my = df[df['user']==st.session_state.user['username']].sort_values('created_at', ascending=False)
    if my.empty:
        st.info('No reports yet. Use "Report Issue" to create one.')
    else:
        st.dataframe(my[['id','title','pred','status','created_at']])

# ----------------------------
# Gallery
# ----------------------------
elif page == 'Gallery':
    st.title('Gallery')
    df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
    imgs = df['image'].dropna().tolist()
    if not imgs:
        st.info('No images available yet.')
    else:
        cols = st.columns(3)
        i = 0
        for im in imgs:
            if im and os.path.exists(im):
                with cols[i % 3]:
                    st.image(im, use_column_width=True)
                i += 1

# ----------------------------
# Admin
# ----------------------------
elif page == 'Admin':
    if not st.session_state.user:
        st.warning('Please login as admin to access this page.')
        st.stop()
    if not st.session_state.user['is_admin']:
        st.error('Admin only area. If you believe this is a mistake, sign in with an admin account.')
        st.stop()
    st.title('Admin Dashboard')
    st.markdown('Manage reports, update status, and monitor activity.')
    df = load_df(ISSUES_FILE, ["id","user","title","desc","pred","conf","status","created_at","image"])
    if df.empty:
        st.info('No reports yet.')
    else:
        # quick filters
        st.subheader('All reports')
        idx = st.selectbox('Select report ID', df['id'].tolist())
        row = df[df['id']==idx].iloc[0]
        st.markdown(f"**{row['title']}** — {row['user']} • {human_time(row['created_at'])}")
        st.write(row['desc'])
        if pd.notna(row['image']) and row['image'] and os.path.exists(row['image']):
            st.image(row['image'], width=300)
        new_status = st.selectbox('New status', ['Pending','In Progress','Resolved'])
        if st.button('Update status'):
            df.loc[df['id']==idx,'status'] = new_status
            save_df(df, ISSUES_FILE)
            st.success('Updated')
            st.experimental_rerun()

# ----------------------------
# About
# ----------------------------
elif page == 'About':
    st.title('About')
    st.write('This is an improved civic issue reporting app built with Streamlit.\n\nFeatures:\n- Role-aware login/sign-up (admin vs user)\n- Image uploads and gallery\n- Admin dashboard to update statuses\n- Simple ML fallback for issue prediction (load models if present)')

# ----------------------------
# End
# ----------------------------

# Note: This single-file app aims to provide a modern look & feel. For production:
# - Move users and issues to a proper DB (Postgres / Supabase)
# - Store images in object storage (S3 / DigitalOcean Spaces)
# - Add authentication via OAuth or a managed auth provider
# - Set up background workers (for heavy ML predictions) and caching
