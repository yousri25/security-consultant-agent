import json
import re
import time
from urllib.parse import quote

import dns.resolver
import requests
import streamlit as st
from openai import OpenAI

st.set_page_config(page_title="Security Consultant Agent", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

# Preferred models, best first. The app keeps only the ones your key can use.
CONSULTANT_PREFS = ["openai/gpt-oss-120b", "llama-3.3-70b-versatile", "openai/gpt-oss-20b"]
REVIEWER_PREFS = ["llama-3.1-8b-instant", "openai/gpt-oss-20b", "llama-3.3-70b-versatile"]
MAX_RETRIES = 1        # extra attempts if the reviewer rejects
MAX_QUESTIONS = 20     # per session, protects the free quota
MAX_TOOL_ROUNDS = 4    # tool-calling rounds per answer
MAX_REPORTS = 3        # report generations per session
HTTP_TIMEOUT = 15
UA = {"User-Agent": "security-consultant-school-project"}

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BREACH_URL = "https://api.xposedornot.com/v1/check-email/"
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
DOMAIN_RE = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}")

client = OpenAI(
    api_key=st.secrets["GROQ_API_KEY"],
    base_url="https://api.groq.com/openai/v1",
    timeout=60,
)

CONSULTANT_PROMPT = """You are a cybersecurity consultant advising small organizations.

How to behave:
- Greetings or vague messages: reply in 1-2 short sentences and ask what they need.
- If key details are missing (OS, network size, tools, data involved), ask at most 3
  short clarifying questions and give only a brief first-pass answer.
- With enough context, give a tailored assessment: main risks, a severity
  (low/medium/high/critical) for each, and prioritized fixes.
- Match answer length to the question. Never exceed about 400 words.
- Only defensive advice. Refuse to help attack systems the user does not own and
  explain why in one or two sentences.

Tools (use them instead of guessing):
- lookup_cve: when the user mentions a CVE ID or a specific product/version.
- check_kev: after finding a CVE, check whether it is known to be exploited in the
  wild. If it is, say it must be patched first.
- check_email_domain_security: when the user gives a domain or an email address and
  asks about email security, spoofing or phishing protection.
- check_email_breach: ONLY when the user gives an email address and asks whether it
  was exposed in data breaches. Remind them to check only their own or a test address.

Rules for tool results:
- Never invent CVE IDs, scores or breach names. Use only what the tools returned.
- If a tool returns an error, say plainly that the check could not be completed.
  Never present a failed check as a clean result.
- "Not found in breaches" does NOT mean safe; say so.
- DKIM "not found" only means common selectors were not found, not that DKIM is absent."""

REVIEWER_PROMPT = """You are a strict reviewer of cybersecurity consultant answers.
You get the conversation, the raw tool results (if any), and the consultant's answer.
Check:
1. It fits the question. A greeting or vague message must get a short reply asking
   for details. REJECT long generic checklists written without context.
2. Every CVE ID, score, breach name or DNS finding in the answer must appear in the
   tool results. REJECT anything invented or contradicted by the tool results.
3. If a tool returned an error, the answer must say the check failed. REJECT any
   answer that presents a failed check as a clean result.
4. Technically accurate, specific to the user's situation, and defensive only.
5. Reasonable length (under about 400 words).
Reply with ONLY a JSON object, no other text:
{"approved": true or false, "feedback": "what to fix"}"""


# ----------------------------------------------------------------------------
# Tools
# ----------------------------------------------------------------------------
def _nvd_key():
    try:
        return st.secrets["NVD_API_KEY"]
    except Exception:
        return None


def lookup_cve(query):
    query = (query or "").strip()
    if not query:
        return {"error": "Empty query."}
    headers = dict(UA)
    if _nvd_key():
        headers["apiKey"] = _nvd_key()
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", query, re.I):
        params = {"cveId": query.upper()}
    else:
        params = {"keywordSearch": query, "resultsPerPage": 20}
    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=HTTP_TIMEOUT)
        if r.status_code in (403, 429):
            return {"error": "NVD rate limit reached. Try again in about a minute."}
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {"error": f"Could not reach the NVD database: {e}"}

    items = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        desc = next((d["value"] for d in c.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        score = sev = None
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if c.get("metrics", {}).get(k):
                m = c["metrics"][k][0]
                score = m.get("cvssData", {}).get("baseScore")
                sev = m.get("cvssData", {}).get("baseSeverity") or m.get("baseSeverity")
                break
        items.append({"id": c.get("id"), "published": (c.get("published") or "")[:10],
                      "cvss": score, "severity": sev, "description": desc[:350]})
    items.sort(key=lambda x: x["published"], reverse=True)
    return {"total_matches": data.get("totalResults"), "shown": items[:5],
            "note": "Keyword searches return a sample, not every match."}


@st.cache_data(ttl=21600)
def _load_kev():
    r = requests.get(KEV_URL, headers=UA, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()["vulnerabilities"]


def check_kev(cve_id):
    cve_id = (cve_id or "").strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id):
        return {"error": "Invalid CVE ID format."}
    try:
        vulns = _load_kev()
    except Exception as e:
        return {"error": f"Could not load the CISA KEV list: {e}"}
    for v in vulns:
        if v.get("cveID") == cve_id:
            return {"cve": cve_id, "in_kev": True,
                    "product": f"{v.get('vendorProject')} {v.get('product')}",
                    "name": v.get("vulnerabilityName"),
                    "date_added": v.get("dateAdded"),
                    "required_action": v.get("requiredAction"),
                    "used_in_ransomware": v.get("knownRansomwareCampaignUse")}
    return {"cve": cve_id, "in_kev": False,
            "note": "Not in the CISA KEV list. This does not prove it is not exploited."}


def _txt(name):
    res = dns.resolver.Resolver()
    res.lifetime = 5
    try:
        answers = res.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return ["".join(s.decode("utf-8", "ignore") for s in rr.strings) for rr in answers]


def check_email_domain_security(domain_or_email):
    d = (domain_or_email or "").strip().lower()
    if "@" in d:
        d = d.split("@")[-1]
    if not DOMAIN_RE.fullmatch(d):
        return {"error": "Invalid domain."}
    try:
        spf = [t for t in _txt(d) if t.lower().startswith("v=spf1")]
        dmarc = [t for t in _txt("_dmarc." + d) if t.lower().startswith("v=dmarc1")]
    except Exception as e:
        return {"error": f"DNS lookup failed: {e}"}

    out = {"domain": d}
    if not spf:
        out["spf"] = {"found": False, "verdict": "MISSING: anyone can more easily spoof this domain."}
    else:
        rec = spf[0]
        if "-all" in rec:
            verdict = "Strict (-all): good."
        elif "~all" in rec:
            verdict = "Soft fail (~all): acceptable, -all is stricter."
        elif "?all" in rec:
            verdict = "Neutral (?all): weak."
        elif "+all" in rec:
            verdict = "DANGEROUS (+all): allows anyone to send as this domain."
        else:
            verdict = "No 'all' mechanism found: unclear or incomplete policy."
        out["spf"] = {"found": True, "record": rec[:300], "verdict": verdict}

    if not dmarc:
        out["dmarc"] = {"found": False, "verdict": "MISSING: no policy against spoofed mail."}
    else:
        rec = dmarc[0]
        m = re.search(r"\bp=(none|quarantine|reject)", rec, re.I)
        policy = m.group(1).lower() if m else "unknown"
        verdicts = {"none": "p=none: monitoring only, spoofed mail is still delivered.",
                    "quarantine": "p=quarantine: good.",
                    "reject": "p=reject: strongest.",
                    "unknown": "Policy could not be parsed."}
        out["dmarc"] = {"found": True, "record": rec[:300], "policy": policy,
                        "verdict": verdicts[policy], "reporting_enabled": "rua=" in rec.lower()}

    found = []
    for sel in ("google", "selector1", "selector2", "default", "k1", "s1"):
        try:
            if any("v=dkim1" in t.lower() for t in _txt(f"{sel}._domainkey.{d}")):
                found.append(sel)
        except Exception:
            pass
    out["dkim"] = {"selectors_found": found,
                   "note": "Only common selectors were tried. Not found does not prove DKIM is absent."}
    return out


def check_email_breach(email):
    email = (email or "").strip()
    if not EMAIL_RE.fullmatch(email):
        return {"error": "Invalid email address."}
    try:
        r = requests.get(BREACH_URL + quote(email), headers=UA, timeout=HTTP_TIMEOUT)
    except Exception as e:
        return {"error": f"Could not reach the breach database: {e}"}
    if r.status_code == 404:
        return {"email": email, "found_in_breaches": False,
                "note": "Not found in this database. That does NOT prove the email is safe."}
    if r.status_code == 429:
        return {"error": "Breach database rate limit reached. Try again later."}
    if r.status_code != 200:
        return {"error": f"Breach database returned HTTP {r.status_code}."}
    try:
        raw = r.json().get("breaches", [])
        names = []
        for item in raw:
            names.extend(item if isinstance(item, list) else [item])
    except Exception as e:
        return {"error": f"Unexpected response from the breach database: {e}"}
    return {"email": email, "found_in_breaches": bool(names),
            "breach_count": len(names), "breaches": names[:25]}


def _fn(name, desc, prop, prop_desc):
    return {"type": "function", "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object",
                       "properties": {prop: {"type": "string", "description": prop_desc}},
                       "required": [prop]}}}


TOOLS = [
    _fn("lookup_cve", "Search the NIST NVD for a CVE ID or a product/version keyword.",
        "query", "A CVE ID like CVE-2021-44228, or keywords like 'openssl 3.0'."),
    _fn("check_kev", "Check if a CVE is in CISA's Known Exploited Vulnerabilities list.",
        "cve_id", "A CVE ID like CVE-2021-44228."),
    _fn("check_email_domain_security", "Check a domain's SPF, DMARC and DKIM email protections.",
        "domain_or_email", "A domain like example.com, or an email address."),
    _fn("check_email_breach", "Check whether an email address appears in known data breaches.",
        "email", "The email address to check."),
]
TOOL_FUNCS = {
    "lookup_cve": lambda a: lookup_cve(a.get("query")),
    "check_kev": lambda a: check_kev(a.get("cve_id")),
    "check_email_domain_security": lambda a: check_email_domain_security(a.get("domain_or_email")),
    "check_email_breach": lambda a: check_email_breach(a.get("email")),
}


def run_tool(name, raw_args):
    try:
        args = json.loads(raw_args) if raw_args else {}
    except Exception:
        args = {}
    fn = TOOL_FUNCS.get(name)
    result = fn(args) if fn else {"error": f"Unknown tool {name}"}
    return args, json.dumps(result, ensure_ascii=False)[:3500]


# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------
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


def chat(model, messages, tools=None):
    kwargs = {"model": model, "messages": messages}
    if tools:
        kwargs["tools"] = tools
    for attempt in range(2):
        try:
            return client.chat.completions.create(**kwargs).choices[0].message
        except Exception as e:
            if attempt == 0 and "503" in str(e):
                time.sleep(1.5)
                continue
            raise


def consultant(history, on_event, draft=None, feedback=None, evidence=""):
    base = [{"role": "system", "content": CONSULTANT_PROMPT}] + [
        {"role": m["role"], "content": m["content"]} for m in history
    ]
    if draft and feedback:
        base.append({"role": "assistant", "content": draft})
        note = f"A reviewer rejected your answer: {feedback}\n"
        if evidence:
            note += f"Tool results already gathered:\n{evidence}\n"
        base.append({"role": "user", "content": note + "Rewrite it, fixing these issues."})

    errors = []
    for model in pick(CONSULTANT_PREFS):
        msgs = list(base)
        log = []
        try:
            for rnd in range(MAX_TOOL_ROUNDS + 1):
                msg = chat(model, msgs, TOOLS if rnd < MAX_TOOL_ROUNDS else None)
                if not msg.tool_calls:
                    if not (msg.content or "").strip():
                        raise RuntimeError("empty reply")
                    return msg.content, log
                msgs.append({
                    "role": "assistant", "content": msg.content or "",
                    "tool_calls": [{"id": tc.id, "type": "function",
                                    "function": {"name": tc.function.name,
                                                 "arguments": tc.function.arguments}}
                                   for tc in msg.tool_calls]})
                for tc in msg.tool_calls:
                    args, result = run_tool(tc.function.name, tc.function.arguments)
                    on_event(f"🔧 `{tc.function.name}` {args}")
                    log.append(f"{tc.function.name}({json.dumps(args)}) -> {result}")
                    msgs.append({"role": "tool", "tool_call_id": tc.id, "content": result})
            raise RuntimeError("too many tool rounds")
        except Exception as e:
            errors.append(f"- {model}: {str(e)[:250]}")
            on_event(f"⚠️ {model} failed, trying the next model...")
    raise RuntimeError("All models failed:\n" + "\n".join(errors))


def review(history, answer, evidence):
    convo = "\n".join(f"{m['role'].upper()}: {m['content']}" for m in history[-6:])
    messages = [
        {"role": "system", "content": REVIEWER_PROMPT},
        {"role": "user", "content":
            f"CONVERSATION:\n{convo}\n\nTOOL RESULTS:\n{evidence or 'none'}\n\n"
            f"CONSULTANT ANSWER TO CHECK:\n{answer}"},
    ]
    errors = []
    for model in pick(REVIEWER_PREFS):
        try:
            text = chat(model, messages).content or ""
            match = re.search(r"\{.*\}", text, re.DOTALL)
            return json.loads(match.group(0))
        except Exception as e:
            errors.append(f"- {model}: {str(e)[:200]}")
    # If no reviewer works, do not block the answer
    return {"approved": True, "feedback": ""}


# ----------------------------------------------------------------------------
# Report generation
# ----------------------------------------------------------------------------
REPORT_PROMPT = """You write short security assessment reports for small organizations.
You get the conversation and the raw tool results gathered during it.
Write a clear Markdown report with exactly these sections:
## Executive summary
3-5 sentences.
## Scope
What was assessed, taken from the conversation.
## Findings
A table with columns: # | Finding | Severity | Evidence. Severity is low, medium, high or critical.
## Recommended actions
Three groups: Do now / This month / Later.
## Limitations
What was not checked and what the tools cannot prove.

Rules:
- Use only facts from the conversation and the tool results.
- Never invent CVE IDs, scores, breach names or DNS findings.
- If a tool returned an error, write that the check could not be completed.
- "Not found in breaches" is not proof of safety. DKIM "not found" only means common
  selectors were not found.
- If there is too little information for real findings, say so plainly and list what
  is missing instead of padding the report.
- Defensive advice only. Maximum about 700 words. Do not write a title or a date."""

REPORT_FOOTER = ("\n\n---\n*Generated by an AI assistant from a chat session and public "
                 "data sources (NVD, CISA KEV, DNS, XposedOrNot). Verify critical findings "
                 "before acting on them. This is not a penetration test or a compliance audit.*")


def generate_report(history, findings):
    convo = "\n".join(f"{m['role'].upper()}: {m['content']}" for m in history)[-9000:]
    evidence = "\n".join(findings)[-8000:] or "No tools were used in this session."
    messages = [
        {"role": "system", "content": REPORT_PROMPT},
        {"role": "user", "content": f"CONVERSATION:\n{convo}\n\nTOOL RESULTS:\n{evidence}"},
    ]
    errors = []
    for model in pick(CONSULTANT_PREFS):
        try:
            body = (chat(model, messages).content or "").strip()
            if not body:
                raise RuntimeError("empty reply")
            stamp = time.strftime("%Y-%m-%d %H:%M")
            head = f"# Security Assessment Report\n\n*Generated: {stamp}*\n\n"
            return head + body + REPORT_FOOTER
        except Exception as e:
            errors.append(f"- {model}: {str(e)[:200]}")
    raise RuntimeError("All models failed:\n" + "\n".join(errors))


def report_to_html(md_text):
    try:
        import markdown
        body = markdown.markdown(md_text, extensions=["tables"])
    except Exception:
        from html import escape
        body = f"<pre style='white-space:pre-wrap'>{escape(md_text)}</pre>"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Security Assessment Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#1b2433;line-height:1.55}}
h1{{border-bottom:3px solid #00b37e;padding-bottom:.4rem}}
h2{{color:#0b5d49;margin-top:1.8rem}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #cfd8e3;padding:.45rem .6rem;text-align:left;vertical-align:top}}
th{{background:#eaf7f2}}
hr{{border:none;border-top:1px solid #cfd8e3;margin-top:2rem}}
@media print{{body{{margin:0}}}}
</style></head><body>{body}</body></html>"""


# ----------------------------------------------------------------------------
# UI content
# ----------------------------------------------------------------------------
CAPABILITIES = [
    ("🎯", "Risk assessment", "Main risks, severity (low to critical) and prioritized fixes for your setup."),
    ("🧪", "Live vulnerability intel", "Real CVEs plus an exploited-in-the-wild check, so patch order is evidence-based."),
    ("📧", "Email protection audit", "SPF, DMARC and DKIM review to show how easy your domain is to spoof."),
    ("🕵️", "Breach exposure check", "Does an email address appear in known data breaches?"),
    ("⚖️", "Reviewer model", "A second model fact-checks every answer against the raw tool output."),
    ("📄", "Report export", "Turn the session into a structured report (Markdown or HTML)."),
]

TOOL_INFO = [
    ("lookup_cve", "🔎", "CVE lookup", "NIST NVD",
     "Finds a CVE by ID or by product/version keyword, with CVSS score and description.",
     "Tell me about CVE-2021-44228"),
    ("check_kev", "🚨", "Exploited?", "CISA KEV",
     "Checks if a CVE is on CISA's Known Exploited Vulnerabilities list.",
     "Is CVE-2023-4863 being exploited in the wild?"),
    ("check_email_domain_security", "📧", "Email security", "DNS (SPF / DMARC / DKIM)",
     "Audits a domain's anti-spoofing and anti-phishing records.",
     "Check the email security of example.com"),
    ("check_email_breach", "🕵️", "Breach check", "XposedOrNot",
     "Lists known data breaches that include an email address. Use your own or a test address.",
     "Has test@example.com been in a data breach?"),
]

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=JetBrains+Mono:wght@400;600&display=swap');
:root{--cy:#00f0ff;--vi:#8b5cf6;--gr:#00ffa3;--bg:#05070d;--glass:rgba(10,16,30,.62);--line:rgba(0,240,255,.18)}

/* background: faint grid + glow */
.stApp{background:
  radial-gradient(900px 500px at 85% -10%,rgba(139,92,246,.18),transparent 60%),
  radial-gradient(800px 500px at -10% 10%,rgba(0,240,255,.12),transparent 60%),
  linear-gradient(rgba(0,240,255,.035) 1px,transparent 1px),
  linear-gradient(90deg,rgba(0,240,255,.035) 1px,transparent 1px),
  var(--bg);
  background-size:auto,auto,44px 44px,44px 44px,auto}
[data-testid="stHeader"]{background:transparent}
.block-container{max-width:900px;padding-top:2rem}

/* hero */
.hero{position:relative;padding:1.4rem 0 1.1rem;margin-bottom:.6rem}
.hero::after{content:"";position:absolute;left:0;bottom:0;height:2px;width:100%;
  background:linear-gradient(90deg,transparent,var(--cy),var(--vi),transparent);
  background-size:200% 100%;animation:sweep 5s linear infinite}
@keyframes sweep{0%{background-position:200% 0}100%{background-position:-200% 0}}
.status{font:600 .72rem 'JetBrains Mono',monospace;letter-spacing:.18em;color:var(--gr);margin-bottom:.5rem}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--gr);margin-right:.55rem;
  box-shadow:0 0 10px var(--gr);animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.35;transform:scale(.7)}}
.hero h1{margin:0;font:900 2.5rem 'Orbitron','Segoe UI',sans-serif;letter-spacing:.06em;line-height:1.1;
  background:linear-gradient(90deg,#fff 0%,var(--cy) 45%,var(--vi) 100%);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  filter:drop-shadow(0 0 14px rgba(0,240,255,.35))}
.hero .sub{margin:.55rem 0 .7rem;color:#8ea3bd;font:400 .95rem 'JetBrains Mono',monospace}
.chip{display:inline-block;padding:.12rem .65rem;margin:0 .4rem .2rem 0;border-radius:4px;
  border:1px solid var(--line);color:var(--cy);font:600 .68rem 'JetBrains Mono',monospace;letter-spacing:.12em}
.note{color:#5d718a;font:400 .72rem 'JetBrains Mono',monospace;margin-top:.5rem}

/* section labels */
.sec{margin:.9rem 0 .3rem;font:600 .7rem 'JetBrains Mono',monospace;letter-spacing:.2em;
  text-transform:uppercase;color:var(--cy);opacity:.85}
.sec::before{content:"// ";opacity:.5}
.cap{font-size:.82rem;color:#9db0c7;margin:.25rem 0}
.cap b{color:#e6edf7}

/* chat = glass panels */
[data-testid="stChatMessage"]{background:var(--glass);border:1px solid var(--line);border-radius:14px;
  backdrop-filter:blur(8px);padding:1rem 1.1rem;margin-bottom:.7rem}
[data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarAssistant"]){border-left:3px solid var(--cy);
  box-shadow:-8px 0 24px -14px var(--cy)}
[data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]){border-left:3px solid var(--vi)}

/* input */
[data-testid="stChatInput"]{border:1px solid var(--line);border-radius:14px;background:rgba(8,12,24,.85)}
[data-testid="stChatInput"]:focus-within{border-color:var(--cy);box-shadow:0 0 0 1px var(--cy),0 0 22px rgba(0,240,255,.25)}

/* buttons */
.stButton>button,.stDownloadButton>button{background:transparent;color:#d8e6f5;border:1px solid var(--line);
  border-radius:10px;font:600 .8rem 'JetBrains Mono',monospace;transition:all .2s}
.stButton>button:hover,.stDownloadButton>button:hover{border-color:var(--cy);color:var(--cy);
  box-shadow:0 0 16px rgba(0,240,255,.3);transform:translateY(-1px)}
.stButton>button[kind="primary"]{background:linear-gradient(90deg,var(--cy),var(--vi));color:#03060c;border:none;
  box-shadow:0 0 18px rgba(0,240,255,.35)}
.stButton>button[kind="primary"]:hover{color:#03060c;box-shadow:0 0 28px rgba(139,92,246,.55)}

/* containers */
[data-testid="stExpander"]{border:1px solid var(--line);border-radius:10px;background:rgba(10,16,30,.45)}
[data-testid="stVerticalBlockBorderWrapper"]:has(.report-mark){border-color:var(--cy)!important;
  box-shadow:0 0 28px -10px var(--cy);background:var(--glass)}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#070b16,#05070d);border-right:1px solid var(--line)}
[data-testid="stProgress"] div[role="progressbar"]>div{background:linear-gradient(90deg,var(--cy),var(--vi))}
::-webkit-scrollbar{width:8px}::-webkit-scrollbar-thumb{background:#14304a;border-radius:8px}
</style>
"""


# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------
st.markdown(CSS, unsafe_allow_html=True)

for key, default in (("messages", []), ("count", 0), ("findings", []),
                     ("report", None), ("reports_made", 0)):
    if key not in st.session_state:
        st.session_state[key] = default

# ---- Sidebar ---------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ Security Consultant")
    st.caption("Defensive advice only. Never paste real passwords or secrets.")

    st.markdown('<div class="sec">Session</div>', unsafe_allow_html=True)
    st.progress(min(st.session_state.count / MAX_QUESTIONS, 1.0),
                text=f"Questions used: {st.session_state.count}/{MAX_QUESTIONS}")

    st.markdown('<div class="sec">Report</div>', unsafe_allow_html=True)
    can_report = bool(st.session_state.messages) and st.session_state.reports_made < MAX_REPORTS
    if st.button("📄 Generate report", type="primary", use_container_width=True,
                 disabled=not can_report,
                 help="Builds a structured report from this conversation and its tool results."):
        try:
            with st.spinner("Writing your report..."):
                st.session_state.report = generate_report(
                    st.session_state.messages, st.session_state.findings)
            st.session_state.reports_made += 1
        except Exception as e:
            st.error(f"Report generation failed.\n\n{e}")
    if not st.session_state.messages:
        st.caption("Ask something first, then generate a report from the chat.")

    st.markdown('<div class="sec">Tools</div>', unsafe_allow_html=True)
    for _, icon, title, source, desc, _ex in TOOL_INFO:
        with st.expander(f"{icon} {title}"):
            st.write(desc)
            st.caption(f"Source: {source}")

    st.markdown('<div class="sec">Capabilities</div>', unsafe_allow_html=True)
    with st.expander("What this agent can do"):
        for icon, title, desc in CAPABILITIES:
            st.markdown(f'<div class="cap">{icon} <b>{title}</b><br>{desc}</div>',
                        unsafe_allow_html=True)

    st.divider()
    if st.button("🗑️ Clear conversation", use_container_width=True):
        for key in ("messages", "findings"):
            st.session_state[key] = []
        st.session_state.report = None
        st.rerun()

# ---- Main ------------------------------------------------------------------
st.markdown(
    '<div class="hero"><div class="status"><span class="dot"></span>SYSTEM ONLINE · REVIEWER ACTIVE</div>'
    '<h1>SECURITY CONSULTANT</h1>'
    '<div class="sub">Real threat data. Verified answers.</div>'
    '<span class="chip">LIVE DATA</span><span class="chip">AI-REVIEWED</span><span class="chip">EXPORTABLE</span>'
    '<div class="note">Check only your own or a test email. Never type real passwords or secrets.</div></div>',
    unsafe_allow_html=True)

welcome = st.empty()
if not st.session_state.messages:
    with welcome.container():
        st.markdown('<div class="sec">Quick scan</div>', unsafe_allow_html=True)
        cols = st.columns(len(TOOL_INFO))
        for col, (_, icon, title, _s, _d, example) in zip(cols, TOOL_INFO):
            if col.button(f"{icon} {title}", help=example, use_container_width=True):
                st.session_state.queued = example
        st.markdown('<div class="note">…or describe your setup below and get a tailored assessment.</div>',
                    unsafe_allow_html=True)

for m in st.session_state.messages:
    with st.chat_message(m["role"]):
        if m.get("steps"):
            with st.expander("Steps (tools, review)"):
                for line in m["steps"]:
                    st.write(line)
        st.markdown(m["content"])

if st.session_state.report:
    with st.container(border=True):
        st.markdown('<span class="report-mark"></span>', unsafe_allow_html=True)
        st.markdown('<div class="sec">Security report</div>', unsafe_allow_html=True)
        st.markdown(st.session_state.report)
        c1, c2 = st.columns(2)
        c1.download_button("⬇️ Markdown", st.session_state.report,
                           file_name="security-report.md", mime="text/markdown",
                           use_container_width=True)
        c2.download_button("⬇️ HTML (print to PDF)",
                           report_to_html(st.session_state.report),
                           file_name="security-report.html", mime="text/html",
                           use_container_width=True)

if prompt := (st.chat_input("Describe your setup or ask a security question")
              or st.session_state.pop("queued", None)):
    welcome.empty()
    if st.session_state.count >= MAX_QUESTIONS:
        st.warning("Question limit reached for this session.")
        st.stop()
    st.session_state.count += 1
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        try:
            with st.status("Consultant is working...", expanded=True) as status:
                t0 = time.time()
                all_evidence, steps = [], []

                def note(text):
                    steps.append(text)
                    status.write(text)

                answer, log = consultant(st.session_state.messages, note)
                all_evidence += log
                note(f"Draft 1 ready after {time.time() - t0:.0f}s.")
                for attempt in range(MAX_RETRIES + 1):
                    note("Reviewer is checking it...")
                    evidence = "\n".join(all_evidence)[-6000:]
                    verdict = review(st.session_state.messages, answer, evidence)
                    if verdict.get("approved"):
                        note("✅ Reviewer approved the answer.")
                        break
                    note(f"❌ Reviewer rejected: {verdict.get('feedback', '')}")
                    if attempt == MAX_RETRIES:
                        note("Retry limit reached, returning the latest draft.")
                        break
                    note("Consultant is rewriting...")
                    answer, log = consultant(st.session_state.messages, note,
                                             draft=answer,
                                             feedback=verdict.get("feedback", ""),
                                             evidence=evidence)
                    all_evidence += log
                status.update(label="Done (click to see the steps)",
                              state="complete", expanded=False)
            st.markdown(answer)
            st.session_state.messages.append({"role": "assistant", "content": answer,
                                              "steps": steps})
            st.session_state.findings += all_evidence
            st.session_state.report = None  # a new answer makes the old report stale
            st.rerun()
        except Exception as e:
            # Remove the unanswered question so the chat history stays valid
            st.session_state.messages.pop()
            st.session_state.count -= 1
            st.error(f"The request failed.\n\n{e}")
