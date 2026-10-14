import json
import time
import streamlit as st
from google import genai
from google.genai import types

# Models are tried in order. If the first is overloaded, the next one is used.
# Edit these to match the model names listed in your AI Studio account.
FALLBACK_MODELS = ["gemini-3.8-flash", "gemini-3.8-flash-lite"]
MAX_RETRIES = 2        # extra attempts if the reviewer rejects
MAX_QUESTIONS = 15     # per session, protects the free quota

client = genai.Client(api_key=st.secrets["GEMINI_API_KEY"])

CONSULTANT_PROMPT = """You are a cybersecurity consultant advising small organizations.
For each question: identify the risks, rate severity (low/medium/high/critical),
and give concrete, prioritized fixes. Ask for missing context (OS, network size,
data involved) when needed. Only defensive advice: refuse to help attack systems
the user does not own, and explain why. Be specific and avoid vague generalities."""

REVIEWER_PROMPT = """You are a strict reviewer of cybersecurity advice.
Check the answer against these criteria:
1. Technically accurate (no invented CVEs, tools or commands).
2. Specific and actionable, not generic.
3. Defensive only; nothing that helps attack systems.
4. Actually answers the user's question, with severity/priorities.
Reply ONLY with JSON: {"approved": true/false, "feedback": "what to fix"}"""


def generate(contents, config):
    """Call Gemini with retries on overload (503) or rate limit (429),
    then fall back to the next model in FALLBACK_MODELS."""
    last_error = None
    for model in FALLBACK_MODELS:
        for attempt in range(3):
            try:
                return client.models.generate_content(
                    model=model, contents=contents, config=config)
            except Exception as e:
                last_error = e
                msg = str(e)
                if "503" in msg or "429" in msg:
                    time.sleep(2 * (attempt + 1))   # wait 2s, 4s, 6s
                    continue
                if "404" in msg:
                    break                           # bad model name: try next model
                raise                               # other errors: stop
    raise last_error


def consultant(messages, draft=None, feedback=None):
    contents = [
        types.Content(
            role="user" if m["role"] == "user" else "model",
            parts=[types.Part(text=m["content"])],
        )
        for m in messages
    ]
    if draft and feedback:
        contents.append(types.Content(role="model", parts=[types.Part(text=draft)]))
        contents.append(types.Content(role="user", parts=[types.Part(
            text=f"A reviewer rejected your answer: {feedback}\nRewrite it, fixing these issues.")]))
    r = generate(
        contents,
        types.GenerateContentConfig(system_instruction=CONSULTANT_PROMPT),
    )
    return r.text


def review(question, answer):
    r = generate(
        f"USER QUESTION:\n{question}\n\nCONSULTANT ANSWER:\n{answer}",
        types.GenerateContentConfig(
            system_instruction=REVIEWER_PROMPT,
            response_mime_type="application/json",
        ),
    )
    try:
        return json.loads(r.text)
    except Exception:
        return {"approved": True, "feedback": ""}


st.title("🛡️ Security Consultant Agent")
st.caption("Consultant model + reviewer model. Defensive advice only.")

if "messages" not in st.session_state:
    st.session_state.messages = []
    st.session_state.count = 0

for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        st.markdown(m["content"])

if prompt := st.chat_input("Describe your setup or ask a security question"):
    if st.session_state.count >= MAX_QUESTIONS:
        st.warning("Question limit reached for this session.")
        st.stop()
    st.session_state.count += 1
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        try:
            log = []
            with st.spinner("Consultant is working..."):
                answer = consultant(st.session_state.messages)
                for attempt in range(MAX_RETRIES + 1):
                    verdict = review(prompt, answer)
                    log.append(f"Attempt {attempt + 1}: "
                               f"{'approved' if verdict.get('approved') else 'rejected'}"
                               f" {verdict.get('feedback', '')}")
                    if verdict.get("approved") or attempt == MAX_RETRIES:
                        break
                    answer = consultant(st.session_state.messages, answer,
                                        verdict.get("feedback", ""))
            st.markdown(answer)
            with st.expander("Reviewer log"):
                st.write("\n\n".join(log))
            st.session_state.messages.append({"role": "assistant", "content": answer})
        except Exception as e:
            # Remove the unanswered question so the chat history stays valid
            st.session_state.messages.pop()
            st.session_state.count -= 1
            st.error(f"The request failed. Please try again in a minute.\n\nDetails: {e}")
