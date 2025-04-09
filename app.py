import streamlit as st
import pandas as pd
import pickle
import os
import altair as alt
import PyPDF2
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from user_auth import load_users, authenticate_user, register_user

# --- Page config ---
st.set_page_config(page_title="Cyber Threat Detection", layout="centered")

# --- Custom CSS Styling ---
def add_custom_css():
    st.markdown("""
        <style>
        h1, h2, h3 {
            color: #0077cc;
        }
        .css-1aumxhk {
            background-color: #f9f9f9;
            border-radius: 10px;
            padding: 1rem;
        }
        .custom-button {
            background-color: #0077cc;
            color: white;
            padding: 0.5em 1.5em;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: bold;
        }
        .custom-button:hover {
            background-color: #005fa3;
        }
        .alert-box {
            background-color: #ffe6e6;
            border-left: 6px solid red;
            padding: 1em;
            border-radius: 5px;
            margin: 1em 0;
        }
        </style>
    """, unsafe_allow_html=True)

add_custom_css()

# --- Load model ---
MODEL_PATH = "cyber_threat_model.pkl"
PDF_MODEL_PATH = "pdf_threat_model.pkl"

model = pickle.load(open(MODEL_PATH, "rb")) if os.path.exists(MODEL_PATH) else None
pdf_model = pickle.load(open(PDF_MODEL_PATH, "rb")) if os.path.exists(PDF_MODEL_PATH) else None

if not model:
    st.error("CSV model file not found.")
    st.stop()

# --- Load users ---
users = load_users()
st.image("Logo.png", use_container_width=True)
st.title("🛡 Real-Time Cyber Threat Detection")

# --- Session State ---
for key in ["authenticated", "welcome_shown", "username"]:
    if key not in st.session_state:
        st.session_state[key] = False if key != "username" else ""

# --- Login / Register ---
if not st.session_state["authenticated"]:
    login_tab, register_tab = st.tabs(["🔐 Login", "🆕 Register"])

    with login_tab:
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if authenticate_user(username, password):
                st.session_state["authenticated"] = True
                st.session_state["username"] = username
                st.success("✅ Login successful!")
                st.rerun()
            else:
                st.error("❌ Invalid username or password.")

    with register_tab:
        st.subheader("Register")
        new_user = st.text_input("New Username")
        new_pass = st.text_input("New Password", type="password")
        security_answer = st.text_input("What is your favorite color?")

        if st.button("Register"):
            if new_user and new_pass and security_answer:
                if register_user(new_user, new_pass, security_answer):
                    st.success("✅ Registered successfully! You can now log in.")
                else:
                    st.warning("⚠ Username already exists.")
            else:
                st.warning("Please fill in all fields.")
    st.stop()

# --- User Folder ---
username = st.session_state["username"]
user_dir = f"user_data/{username}"
os.makedirs(user_dir, exist_ok=True)

# --- Welcome Message ---
if not st.session_state["welcome_shown"]:
    st.markdown(f"### 👋 Welcome, {username}!")
    st.markdown("""
    Welcome to the Cyber Threat Detection System.
    Upload your **CSV or PDF** file to:
    - 🔍 Detect real-time cyber threats
    - 📊 Analyze threat data
    - 🔒 Export detailed reports
    """)
    if st.button("🚀 Start Detection"):
        st.session_state["welcome_shown"] = True
        st.rerun()
    st.stop()

# --- File Upload ---
st.subheader("📂 Upload a File for Threat Detection")
uploaded_file = st.file_uploader("Choose a file", type=["csv", "pdf"])

if uploaded_file:
    try:
        # --- CSV File Handling ---
        if uploaded_file.name.endswith(".csv"):
            df = pd.read_csv(uploaded_file)
            st.subheader("📄 Uploaded Data")
            st.dataframe(df)

            if "IsThreat" in df.columns:
                df = df.drop("IsThreat", axis=1)

            predictions = model.predict(df)
            df["Prediction"] = ["Threat" if p == 1 else "Safe" for p in predictions]

            total, threat_count = len(df), (predictions == 1).sum()
            percent = (threat_count / total) * 100

            st.markdown("### ⚠ Threat Summary")
            st.write(f"- Total Records: {total}")
            st.write(f"- Threats Detected: {threat_count}")
            st.write(f"- Threat Rate: {percent:.2f}%")

            if threat_count:
                st.markdown(f"""
                    <div class='alert-box'>
                        🚨 <strong>Alert:</strong> {threat_count} potential threats detected!
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.success("✅ No threats detected.")

            chart_data = pd.DataFrame({"Category": ["Threats", "Safe"], "Count": [threat_count, total - threat_count]})
            chart = alt.Chart(chart_data).mark_bar().encode(
                x='Category', y='Count', color='Category'
            ).properties(title="Threat vs Safe Predictions")
            st.altair_chart(chart, use_container_width=True)

            st.subheader("📊 Prediction Results")
            st.dataframe(df)

            full_path = os.path.join(user_dir, "full_predictions.csv")
            threats_path = os.path.join(user_dir, "threats_only.csv")
            df.to_csv(full_path, index=False)
            df[df["Prediction"] == "Threat"].to_csv(threats_path, index=False)

            st.download_button("⬇ Download Full Results", full_path, "full_predictions.csv")
            if threat_count:
                st.download_button("⬇ Download Threat Report", threats_path, "threats_only.csv")

        # --- PDF File Handling ---
        elif uploaded_file.name.endswith(".pdf"):
            pdf_reader = PyPDF2.PdfReader(uploaded_file)
            text = "\n".join([p.extract_text() for p in pdf_reader.pages if p.extract_text()])
            st.subheader("📄 Extracted Text from PDF")
            st.text_area("PDF Content", text, height=300)

            st.download_button("⬇ Download Extracted Text", text.encode("utf-8"), "extracted_text.txt")

            if pdf_model:
                prediction = pdf_model.predict([text])[0]
                if prediction == 1:
                    st.markdown("""
                    <div class='alert-box'>
                        🚨 <strong>ALERT:</strong> Threat detected in PDF content!
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    st.success("✅ No threat detected in this PDF.")
            else:
                st.warning("⚠ PDF model not available. Only displaying text.")

    except Exception as e:
        st.error(f"❌ Error during prediction: {e}")

# --- Logout ---
if st.button("🔒 Logout"):
    st.session_state["authenticated"] = False
    st.session_state["username"] = ""
    st.session_state["welcome_shown"] = False
    st.success("🔓 Logged out successfully!")
    st.rerun()
