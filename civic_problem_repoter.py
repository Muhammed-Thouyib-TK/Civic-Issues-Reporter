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
LOGO_URL = "https://cdn-icons-png.flaticon.com/512/684/684908.png"
DATA_FILE = "reports.csv"
IMAGE_DIR = "uploaded_images"

st.set_page_config(page_title=APP_TITLE, page_icon="🛠️", layout="wide")

if not os.path.exists(IMAGE_DIR):
    os.makedirs(IMAGE_DIR)

# ----------------------------
# Custom CSS
# ----------------------------
st.markdown("""
<style>
    /* Global */
    body {
        font-family: 'Inter', sans-serif;
    }
    .hero {
        text-align: center;
        padding: 2rem;
        background: linear-gradient(90deg, #1f2937, #111827);
        border-radius: 1rem;
        color: white;
        margin-bottom: 2rem;
    }
    .hero h1 {
        font-size: 2.5rem;
        font-weight: 700;
    }
    .hero p {
        font-size: 1.1rem;
        opacity: 0.85;
    }
    .issue-card {
        background: #ffffff;
        border-radius: 1rem;
        padding: 1rem;
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        margin-bottom: 1rem;
    }
    .issue-card h4 {
        margin: 0;
        font-weight: 600;
        color: #111827;
    }
    .issue-card span {
        font-size: 0.85rem;
        color: #6b7280;
    }
    .stButton>button {
        border-radius: 0.75rem;
        padding: 0.6rem 1.2rem;
        font-weight: 600;
    }
    .small-muted {
        font-size: 0.85rem;
        color: #9ca3af;
    }
</style>
""", unsafe_allow_html=True)

# ----------------------------
# Utility functions
# ----------------------------
def load_data():
    if os.path.exists(DATA_FILE):
        return pd.read_csv(DATA_FILE)
    return pd.DataFrame(columns=["id", "title", "description", "category", "status", "image", "timestamp", "user"])

def save_data(df):
    df.to_csv(DATA_FILE, index=False)

def save_image(uploaded_file):
    ext = os.path.splitext(uploaded_file.name)[1]
    filename = f"{uuid.uuid4()}{ext}"
    filepath = os.path.join(IMAGE_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return filepath

# ----------------------------
# Session State
# ----------------------------
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

# ----------------------------
# Sidebar
# ----------------------------
with st.sidebar:
    st.image(logo_url := LOGO_URL, width=60)
    st.markdown(f"### {APP_TITLE}")
    st.caption(APP_SUB + " — Built with ❤️ using Streamlit")

    # Auth card
    if st.session_state.user:
        u = st.session_state.user
        st.markdown(
            f"""
            **Signed in as**  
            **{u['username']}**  
            <span class='small-muted'>{u.get('email','')}</span>
            """,
            unsafe_allow_html=True
        )
        if st.button("Logout"):
            st.session_state.user = None
            st.experimental_rerun()
    else:
        st.markdown("#### Choose Role")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("👨‍💼 I'm an Admin"):
                st.session_state.role = "Admin"
                st.session_state.user = {"username": "Admin", "email": "admin@example.com"}
                st.experimental_rerun()
        with col2:
            if st.button("🙋 I'm a User"):
                st.session_state.role = "User"
                st.session_state.user = {"username": "User", "email": "user@example.com"}
                st.experimental_rerun()

    st.markdown("---")
    nav = st.radio("Navigation", ["Home", "Report Issue", "My Reports", "Gallery", "Admin Dashboard"] if st.session_state.role=="Admin" else ["Home", "Report Issue", "My Reports", "Gallery"])

# ----------------------------
# Main Hero
# ----------------------------
st.markdown(f"""
<div class="hero">
    <h1>{APP_TITLE}</h1>
    <p>{APP_SUB}</p>
</div>
""", unsafe_allow_html=True)

# ----------------------------
# Pages
# ----------------------------
df = load_data()

if nav == "Home":
    st.subheader("📌 Recent Issues")
    if df.empty:
        st.info("No reports yet. Be the first to submit one!")
    else:
        for _, row in df.sort_values("timestamp", ascending=False).iterrows():
            with st.container():
                st.markdown("<div class='issue-card'>", unsafe_allow_html=True)
                st.markdown(f"### {row['title']}  ")
                st.markdown(f"<span>{row['description']}</span>", unsafe_allow_html=True)
                st.caption(f"📂 {row['category']} | 🕒 {row['timestamp']} | 👤 {row['user']} | Status: {row['status']}")
                if pd.notna(row["image"]) and os.path.exists(row["image"]):
                    st.image(row["image"], width=250)
                st.markdown("</div>", unsafe_allow_html=True)

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
                img_path = save_image(uploaded_file) if uploaded_file else ""
                new_report = {
                    "id": str(uuid.uuid4()),
                    "title": title,
                    "description": description,
                    "category": category,
                    "status": "Pending",
                    "image": img_path,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "user": st.session_state.user["username"]
                }
                df = pd.concat([df, pd.DataFrame([new_report])], ignore_index=True)
                save_data(df)
                st.success("✅ Report submitted successfully!")
            else:
                st.error("Please fill in all required fields.")

elif nav == "My Reports":
    st.subheader("📂 My Reports")
    user_reports = df[df["user"] == st.session_state.user["username"]]
    if user_reports.empty:
        st.info("No reports submitted yet.")
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

elif nav == "Admin Dashboard" and st.session_state.role == "Admin":
    st.subheader("📊 Admin Dashboard")
    if df.empty:
        st.info("No reports to manage.")
    else:
        for idx, row in df.iterrows():
            with st.expander(f"{row['title']} - {row['status']}"):
                st.write(row["description"])
                if pd.notna(row["image"]) and os.path.exists(row["image"]):
                    st.image(row["image"], width=250)
                new_status = st.selectbox("Update Status", ["Pending", "In Progress", "Resolved"], index=["Pending", "In Progress", "Resolved"].index(row["status"]), key=row["id"])
                if st.button("Save", key="save_"+row["id"]):
                    df.at[idx, "status"] = new_status
                    save_data(df)
                    st.success("✅ Status updated!")

        st.download_button("⬇️ Export Reports CSV", data=df.to_csv(index=False), file_name="reports.csv", mime="text/csv")
