import json
import re
import time
import streamlit as st
from openai import OpenAI

# Preferred models, best first. The app keeps only the ones your key can actually use.
CONSULTANT_PREFS = ["openai/gpt-oss-120b", "llama-3.3-70b-versatile", "openai/gpt-oss-20b", "llama-3.1-8b-instant"]
REVIEWER_PREFS = ["llama-3.1-8b-instant", "openai/gpt-oss-20b", "llama-3.3-70b-versatile"]
MAX_RETRIES = 1        # extra attempts if the reviewer rejects
MAX_QUESTIONS = 20     # per session, protects the free quota

client = OpenAI(
    api_key=st.secrets["GROQ_API_KEY"],
    base_url="https://api.groq.com/openai/v1",
    timeout=60,
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
Reply with ONLY a JSON object, no other text:
{"approved": true or false, "feedback": "what to fix"}"""


@st.cache_resource(ttl=3600)
def available_models():
    try:
        return [m.id for m in client.models.list().data]
    except Exception:
        return []


def pick(prefs):
    avail = available_models()
    chosen = [m for m in prefs if m in avail] if avail else list(prefs)
    return chosen or list(prefs)


def generate(models, messages):
    """Try each model in order. Retry once on overload (503).
    If everything fails, raise ONE error listing what happened to each model."""
    errors = []
    for model in models:
        for attempt in range(2):
            try:
                r = client.chat.completions.create(model=model, messages=messages)
                return r.choices[0].message.content or ""
            except Exception as e:
                msg = str(e)
                if attempt == 0 and "503" in msg:
                    time.sleep(1.5)
                    continue
                errors.append(f"- {model}: {msg[:250]}")
                break   # next model
    raise RuntimeError("All models failed:\n" + "\n".join(errors))


def consultant(history, draft=None, feedback=None):
    messages = [{"role": "system", "content": CONSULTANT_PROMPT}] + [
        {"role": m["role"], "content": m["content"]} for m in history
    ]
    if draft and feedback:
        messages.append({"role": "assistant", "content": draft})
        messages.append({"role": "user", "content":
            f"A reviewer rejected your answer: {feedback}\nRewrite it, fixing these issues."})
    return generate(pick(CONSULTANT_PREFS), messages)


def review(question, answer):
    messages = [
        {"role": "system", "content": REVIEWER_PROMPT},
        {"role": "user", "content":
            f"USER QUESTION:\n{question}\n\nCONSULTANT ANSWER:\n{answer}"},
    ]
    text = generate(pick(REVIEWER_PREFS), messages)
    try:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        return json.loads(match.group(0))
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
                t0 = time.time()
                answer = consultant(st.session_state.messages)
                status.write(f"Draft 1 ready after {time.time() - t0:.0f}s.")
                for attempt in range(MAX_RETRIES + 1):
                    status.write("Reviewer is checking it...")
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
            st.error(f"The request failed.\n\n{e}")

with st.sidebar:
    with st.expander("Models available to this key"):
        st.write(available_models() or "Could not list models")
