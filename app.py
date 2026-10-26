import streamlit as st
from scam_detector import analyze_message

st.set_page_config(page_title="Scam Shield", page_icon="🛡️", layout="centered")

st.title("🛡️ Scam Shield")
st.subheader("Check a suspicious message before you act")
st.write(
    "Paste a text message, email, social-media message, or popup below. "
    "Scam Shield looks for common scam warning signs and explains them in plain English."
)

message = st.text_area(
    "Paste the message here",
    height=220,
    placeholder="Example: This is the IRS. Pay immediately with gift cards or you will be arrested...",
)

if st.button("Check this message", type="primary", use_container_width=True):
    if not message.strip():
        st.warning("Please paste a message first.")
    else:
        result = analyze_message(message)

        if result["verdict"] == "LIKELY SCAM":
            st.error(f'{result["emoji"]} {result["verdict"]} — Risk score {result["score"]}')
        elif result["verdict"] == "BE CAREFUL":
            st.warning(f'{result["emoji"]} {result["verdict"]} — Risk score {result["score"]}')
        else:
            st.success(f'{result["emoji"]} {result["verdict"]} — Risk score {result["score"]}')

        st.write(result["summary"])

        st.markdown("### Why Scam Shield flagged it")
        if result["red_flags"]:
            for flag in result["red_flags"]:
                with st.expander(f'⚠️ {flag["title"]} (+{flag["score"]})'):
                    st.write(flag["explanation"])
        else:
            st.write("No obvious warning signs matched the current rule set.")

        st.markdown("### What to do now")
        for action in result["actions"]:
            st.write(f"• {action}")

        st.markdown("### Share with family")
        st.text_area(
            "Copy this summary and send it to someone you trust",
            value=result["family_summary"],
            height=140,
        )

st.divider()
st.caption(
    "Scam Shield is a safety aid, not a guarantee. A low-risk result does not prove a message is genuine. "
    "When money, passwords, codes, or account access are involved, verify independently."
)
