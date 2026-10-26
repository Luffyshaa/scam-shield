import html

import streamlit as st
from scam_detector import analyze_message

st.set_page_config(
    page_title="Scam Shield",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(180deg, #f8fbff 0%, #ffffff 40%);
    }
    .block-container {
        max-width: 860px;
        padding-top: 2.2rem;
        padding-bottom: 3rem;
    }
    html, body, [class*="css"] {
        font-size: 18px;
    }
    h1 {
        font-size: 3rem !important;
        margin-bottom: 0.2rem !important;
    }
    .hero {
        text-align: center;
        padding: 1rem 0 1.4rem 0;
    }
    .hero-badge {
        display: inline-block;
        background: #e8f2ff;
        color: #164b8f;
        border-radius: 999px;
        padding: 0.35rem 0.8rem;
        font-weight: 700;
        margin-bottom: 0.6rem;
    }
    .hero-subtitle {
        font-size: 1.25rem;
        color: #445164;
        max-width: 700px;
        margin: 0 auto;
        line-height: 1.55;
    }
    .safety-strip {
        background: #fff8e6;
        border: 1px solid #f0d58c;
        border-radius: 14px;
        padding: 0.9rem 1rem;
        margin: 1rem 0 1.4rem 0;
        font-size: 1rem;
    }
    .result-card {
        border-radius: 18px;
        padding: 1.25rem 1.35rem;
        margin: 1.1rem 0;
        border: 2px solid transparent;
    }
    .result-card.scam {
        background: #fff0f0;
        border-color: #e25555;
    }
    .result-card.caution {
        background: #fff8e6;
        border-color: #dda72b;
    }
    .result-card.safe {
        background: #edf9f1;
        border-color: #4c9f67;
    }
    .result-title {
        font-size: 1.65rem;
        font-weight: 800;
        margin-bottom: 0.35rem;
    }
    .result-score {
        font-size: 1rem;
        font-weight: 700;
        opacity: 0.75;
        margin-bottom: 0.55rem;
    }
    .tip-card {
        background: #f5f7fa;
        border-radius: 14px;
        padding: 1rem;
        margin-bottom: 0.7rem;
    }
    .stTextArea textarea {
        font-size: 1.08rem !important;
        line-height: 1.5 !important;
        border-radius: 14px !important;
    }
    .stButton > button {
        min-height: 3.25rem;
        font-size: 1.12rem;
        font-weight: 800;
        border-radius: 14px;
    }
    div[data-testid="stExpander"] {
        border-radius: 12px;
        border: 1px solid #d9e0e8;
    }
    .footer-note {
        color: #667085;
        font-size: 0.92rem;
        text-align: center;
        line-height: 1.5;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
        <div class="hero-badge">Built for everyday scam safety</div>
        <h1>🛡️ Scam Shield</h1>
        <div class="hero-subtitle">
            Before you reply, click, pay, or share information, paste the message here.
            Scam Shield looks for common warning signs and explains them in simple language.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="safety-strip">
        <strong>Simple rule:</strong> If a message asks for money, passwords, gift cards, crypto,
        remote access, or a verification code, stop and verify it another way before doing anything.
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown("### 1. Paste the suspicious message")
message = st.text_area(
    "Message to check",
    height=220,
    placeholder=(
        "Paste a text message, email, social-media message, or popup here.\n\n"
        "Example: This is the IRS. Pay immediately with gift cards or you will be arrested..."
    ),
    label_visibility="collapsed",
)

st.caption("📷 Screenshot/photo checking is planned for the next version.")

check_clicked = st.button(
    "🔎 Check this message",
    type="primary",
    use_container_width=True,
)

if check_clicked:
    if not message.strip():
        st.warning("Please paste a message first.")
    else:
        result = analyze_message(message)
        verdict = result["verdict"]

        if verdict == "LIKELY SCAM":
            card_class = "scam"
        elif verdict == "BE CAREFUL":
            card_class = "caution"
        else:
            card_class = "safe"

        st.markdown("### 2. Your result")
        st.markdown(
            f"""
            <div class="result-card {card_class}">
                <div class="result-title">{html.escape(result['emoji'])} {html.escape(verdict)}</div>
                <div class="result-score">Risk score: {result['score']}</div>
                <div>{html.escape(result['summary'])}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("### Why Scam Shield noticed these warning signs")
        if result["red_flags"]:
            for flag in result["red_flags"]:
                with st.expander(f"⚠️ {flag['title']}  (+{flag['score']})"):
                    st.write(flag["explanation"])
        else:
            st.info(
                "No obvious warning signs matched the current rule set. "
                "That does not prove the message is genuine."
            )

        st.markdown("### 3. What to do now")
        for index, action in enumerate(result["actions"], start=1):
            st.markdown(
                f"<div class='tip-card'><strong>{index}.</strong> {html.escape(action)}</div>",
                unsafe_allow_html=True,
            )

        st.markdown("### 4. Ask someone you trust")
        st.write(
            "If you are still unsure, copy this summary and send it to a family member, friend, "
            "caregiver, bank representative, or the organization using a phone number you find independently."
        )
        st.text_area(
            "Family-share summary",
            value=result["family_summary"],
            height=150,
            label_visibility="collapsed",
        )

        if verdict != "NO RED FLAGS":
            st.warning(
                "Do not use phone numbers, links, or contact details from the suspicious message itself. "
                "Find the official contact information independently."
            )

st.divider()
st.markdown(
    """
    <div class="footer-note">
        <strong>Scam Shield is a safety aid, not a guarantee.</strong><br>
        A low-risk result does not prove a message is genuine. When money, passwords,
        codes, personal information, or account access are involved, verify independently.
    </div>
    """,
    unsafe_allow_html=True,
)
