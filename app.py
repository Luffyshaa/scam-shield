import html

import streamlit as st
from image_processor import OCRProcessingError, extract_text_from_image
from scam_detector import VERDICT_CLEAR, analyze_message

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
    html, body, [class*="css"] { font-size: 18px; }
    h1 { font-size: 3rem !important; margin-bottom: 0.2rem !important; }
    .hero { text-align: center; padding: 1rem 0 1.4rem 0; }
    .hero-badge {
        display: inline-block; background: #e8f2ff; color: #164b8f;
        border-radius: 999px; padding: 0.35rem 0.8rem; font-weight: 700;
        margin-bottom: 0.6rem;
    }
    .hero-subtitle {
        font-size: 1.25rem; color: #445164; max-width: 700px;
        margin: 0 auto; line-height: 1.55;
    }
    .safety-strip {
        background: #fff8e6; border: 1px solid #f0d58c; border-radius: 14px;
        padding: 0.9rem 1rem; margin: 1rem 0 1.4rem 0; font-size: 1rem;
    }
    .result-card {
        border-radius: 18px; padding: 1.25rem 1.35rem; margin: 1.1rem 0;
        border: 2px solid transparent;
    }
    .result-card.scam { background: #fff0f0; border-color: #e25555; }
    .result-card.caution { background: #fff8e6; border-color: #dda72b; }
    .result-card.safe { background: #edf9f1; border-color: #4c9f67; }
    .result-title { font-size: 1.65rem; font-weight: 800; margin-bottom: 0.35rem; }
    .result-level { font-size: 1rem; font-weight: 700; opacity: 0.75; margin-bottom: 0.55rem; }
    .tip-card {
        background: #f5f7fa; border-radius: 14px; padding: 1rem; margin-bottom: 0.7rem;
    }
    .stTextArea textarea {
        font-size: 1.08rem !important; line-height: 1.5 !important; border-radius: 14px !important;
    }
    .stButton > button {
        min-height: 3.25rem; font-size: 1.12rem; font-weight: 800; border-radius: 14px;
    }
    div[data-testid="stExpander"] { border-radius: 12px; border: 1px solid #d9e0e8; }
    .footer-note {
        color: #667085; font-size: 0.92rem; text-align: center; line-height: 1.5;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
        <div class="hero-badge">Scam Shield v0.2</div>
        <h1>🛡️ Scam Shield</h1>
        <div class="hero-subtitle">
            Paste a suspicious message or upload a screenshot/photo. Scam Shield checks the text
            for common scam warning signs and explains what to do next in simple language.
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

input_mode = st.radio(
    "How do you want to check the message?",
    ["✍️ Paste text", "📷 Upload screenshot/photo"],
    horizontal=True,
)

channel = st.selectbox(
    "How did this reach you?",
    ["Text message", "Email", "Phone call", "Pop-up on screen", "Social media or other"],
)

message = ""

if input_mode == "✍️ Paste text":
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
else:
    st.markdown("### 1. Upload a screenshot or photo")
    uploaded_file = st.file_uploader(
        "Upload an image containing the suspicious message",
        type=["png", "jpg", "jpeg", "webp"],
        help="For best results, crop the image so the message text fills most of the picture.",
    )

    if uploaded_file is not None:
        st.image(uploaded_file, caption="Uploaded image", use_container_width=True)
        try:
            with st.spinner("Reading the text in this image..."):
                extracted_text = extract_text_from_image(uploaded_file)
            st.success("Text found. Please review it before analysis.")
            message = st.text_area(
                "Text detected from the image",
                value=extracted_text,
                height=220,
                help="You can correct any OCR mistakes before checking the message.",
            )
        except OCRProcessingError as exc:
            st.error(str(exc))

check_clicked = st.button(
    "🔎 Check this message",
    type="primary",
    use_container_width=True,
)

if check_clicked:
    if not message.strip():
        st.warning("Please paste a message or upload a readable screenshot/photo first.")
    else:
        result = analyze_message(message, channel=channel)
        verdict = result["verdict"]

        card_class = result["card_class"]

        st.markdown("### 2. Your result")
        st.markdown(
            f"""
            <div class="result-card {card_class}">
                <div class="result-title">{html.escape(result['emoji'])} {html.escape(verdict)}</div>
                <div class="result-level">Risk level: {html.escape(result['level'])}</div>
                <div>{html.escape(result['summary'])}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("### Why Scam Shield noticed these warning signs")
        if result["red_flags"]:
            for flag in result["red_flags"]:
                with st.expander(f"⚠️ {flag['title']}"):
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

        if verdict != VERDICT_CLEAR:
            st.warning(
                "Do not use phone numbers, links, or contact details from the suspicious message itself. "
                "Find the official contact information independently."
            )

with st.expander("I already paid or shared information. What do I do now?"):
    st.write("Stop contact with the sender. Do not send more money, even if someone promises to recover it for a fee.")
    st.write("If you paid, contact your bank or payment provider immediately using its official app or a number you trust. Ask whether the payment can be stopped or disputed.")
    st.write("If you shared a password or code, use the real website or app to change your password and review account access. Contact the account provider for help.")
    st.write("If you allowed remote access, disconnect the device from the internet and get help from a trusted technician. Use a different trusted device to secure your accounts.")
    st.write("If you shared identity information, contact the affected organization and ask about identity-theft recovery and credit protection. Ask someone you trust to help.")

with st.expander("Reporting and help"):
    st.write("In the United States, you can report scams to the Federal Trade Commission and internet crime to the FBI's Internet Crime Complaint Center (IC3). Find their official government websites independently.")
    st.write("Outside the United States, contact your local consumer-protection agency or police through official channels.")
    st.write("Save relevant messages and payment details privately for your bank or an official report. Do not send them back to the suspicious sender.")

st.divider()
st.markdown(
    """
    <div class="footer-note">
        <strong>Scam Shield is a safety aid, not a guarantee.</strong><br>
        OCR can misread text in blurry or unusual images. Always review the detected text.
        A low-risk result does not prove a message is genuine. Verify independently when money,
        passwords, codes, personal information, or account access are involved.
    </div>
    """,
    unsafe_allow_html=True,
)
