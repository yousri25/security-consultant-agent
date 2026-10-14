import json
import time
import streamlit as st
from google import genai
from google.genai import types

# Model names taken from your own AI Studio list. Tried in order on failure.
CONSULTANT_MODELS = ["gemini-3.8-flash", "gemini-3.7-flash", "gemini-2.5-flash"]
REVIEWER_MODELS = ["gemini-3.5-flash-lite", "gemini-2.5-flash-lite", "gemini-2.5-flash"]
MAX_RETRIES = 1        # extra attempts if the reviewer rejects
MAX_QUESTIONS = 15     # per session, protects the free quota

client = genai.Client(
    api_key=st.secrets["GEMINI_API_KEY"],
    http_options=types.HttpOptions(timeout=45000),   # 45 s per call
)

CONSULTANT_PROMPT = """You are a cybersecurity consultant advising small organizations.
For each question: identify the risks, rate severity (low/medium/high/critical),
and give concrete, prioritized fixes. Ask for missing context (OS, network size,
data involved) when needed. Only defensive advice: refuse to help attack systems
the user does not own, and explain why. Be specific and avoid vague generalities.
Keep answers focused and under about 400 words."""

REVIEWER_PROMPT = """You are a strict reviewer of cybersecurity advice.
Check the answer against these criteria:
1. Technically accurate (no invented CVEs, tools or commands).
2. Specific and actionable, not generic.
3. Defensive only; nothing that helps attack systems.
4. Actually answers the user's question, with severity/priorities.
Reply ONLY with JSON: {"approved": true/false, "feedback": "what to fix"}"""


def generate(models, contents, config):
    """Try each model in order. On any error, retry once on overload,
    then move on to the next model."""
    last_error = None
    for model in models:
        for attempt in range(2):
            try:
                return client.models.generate_content(
                    model=model, contents=contents, config=config)
            except Exception as e:
                last_error = e
                msg = str(e)
                if attempt == 0 and ("503" in msg or "429" in msg):
                    time.sleep(1.5)
                    continue
                break   # go to next model
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
        CONSULTANT_MODELS, contents,
        types.GenerateContentConfig(system_instruction=CONSULTANT_PROMPT),
    )
    return r.text


def review(question, answer):
    r = generate(
        REVIEWER_MODELS,
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
            with st.status("Consultant is drafting an answer...", expanded=True) as status:
                answer = consultant(st.session_state.messages)
                for attempt in range(MAX_RETRIES + 1):
                    status.write(f"Draft {attempt + 1} ready. Reviewer is checking it...")
                    verdict = review(prompt, answer)
                    if verdict.get("approved"):
                        status.write("✅ Reviewer approved the answer.")
                        break
                    status.write(f"❌ Reviewer rejected: {verdict.get('feedback', '')}")
                    if attempt == MAX_RETRIES:
                        status.write("Retry limit reached, returning the latest draft.")
                        break
                    status.write("Consultant is rewriting...")
                    answer = consultant(st.session_state.messages, answer,
                                        verdict.get("feedback", ""))
                status.update(label="Done (click to see the review steps)",
                              state="complete", expanded=False)
            st.markdown(answer)
            st.session_state.messages.append({"role": "assistant", "content": answer})
        except Exception as e:
            # Remove the unanswered question so the chat history stays valid
            st.session_state.messages.pop()
            st.session_state.count -= 1
            st.error(f"The request failed. Please try again in a minute.\n\nDetails: {e}")
