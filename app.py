# Replace the whole CSS = """ ... """ block in app.py with this one.
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
:root{
  --green:#4A9363; --green-dk:#3B7A52; --green-tint:#DFE9D9;
  --brown:#8A6A4B; --brown-tint:#E9DFCF;
  --bg:#EFEADD; --panel:#F8F4EA; --side:#E6DFCE;
  --line:#D8CFBB; --text:#2F2B23; --muted:#6E6552;
}
html,body,.stApp,[data-testid="stMarkdownContainer"]{font-family:'Inter','Segoe UI',sans-serif}

/* background: warm paper tone with a soft green / brown tint */
.stApp{background:
  radial-gradient(900px 500px at 90% -10%,rgba(74,147,99,.12),transparent 60%),
  radial-gradient(800px 500px at -10% 5%,rgba(138,106,75,.10),transparent 60%),
  var(--bg)}
[data-testid="stHeader"]{background:transparent}
.block-container{max-width:900px;padding-top:2rem}

/* hero */
.hero{position:relative;padding:1.2rem 0 1.1rem;margin-bottom:.6rem}
.hero::after{content:"";position:absolute;left:0;bottom:0;height:2px;width:100%;
  background:linear-gradient(90deg,var(--green),var(--brown) 60%,transparent)}
.status{font:600 .72rem 'Inter',sans-serif;letter-spacing:.14em;color:var(--green-dk);margin-bottom:.5rem}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);margin-right:.55rem;
  box-shadow:0 0 0 3px rgba(74,147,99,.2);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}
.hero h1{margin:0;font:700 2.3rem 'Inter',sans-serif;letter-spacing:-.01em;line-height:1.15;color:var(--text)}
.hero .sub{margin:.45rem 0 .8rem;color:var(--muted);font:400 1rem 'Inter',sans-serif}
.chip{display:inline-block;padding:.15rem .7rem;margin:0 .4rem .2rem 0;border-radius:999px;
  background:var(--green-tint);border:1px solid rgba(74,147,99,.35);color:var(--green-dk);
  font:600 .68rem 'Inter',sans-serif;letter-spacing:.08em}
.note{color:var(--muted);font:400 .78rem 'Inter',sans-serif;margin-top:.5rem}

/* section labels */
.sec{margin:.9rem 0 .35rem;font:600 .7rem 'Inter',sans-serif;letter-spacing:.14em;
  text-transform:uppercase;color:var(--brown)}
.cap{font-size:.82rem;color:var(--muted);margin:.35rem 0}
.cap b{color:var(--text)}

/* chat = soft cards */
[data-testid="stChatMessage"]{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:1rem 1.1rem;margin-bottom:.7rem;box-shadow:0 1px 3px rgba(60,48,30,.06)}
[data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarAssistant"]){border-left:4px solid var(--green)}
[data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"]){border-left:4px solid var(--brown);background:#F3EEE1}

/* input */
[data-testid="stChatInput"]{border:1px solid var(--line);border-radius:12px;background:var(--panel)}
[data-testid="stChatInput"]:focus-within{border-color:var(--green);box-shadow:0 0 0 3px rgba(74,147,99,.18)}

/* buttons */
.stButton>button,.stDownloadButton>button{background:var(--panel);color:var(--text);border:1px solid var(--line);
  border-radius:10px;font:600 .82rem 'Inter',sans-serif;transition:all .15s}
.stButton>button:hover,.stDownloadButton>button:hover{border-color:var(--green);color:var(--green-dk);
  background:var(--green-tint);transform:translateY(-1px)}
.stButton>button[kind="primary"]{background:var(--green);color:#FBF8F0;border:1px solid var(--green);
  box-shadow:0 2px 6px rgba(74,147,99,.30)}
.stButton>button[kind="primary"]:hover{background:var(--green-dk);border-color:var(--green-dk);color:#FBF8F0}

/* containers */
[data-testid="stExpander"]{border:1px solid var(--line);border-radius:10px;background:var(--panel)}
[data-testid="stVerticalBlockBorderWrapper"]:has(.report-mark){border-color:var(--green)!important;
  box-shadow:0 4px 18px -8px rgba(74,147,99,.45);background:var(--panel)}
[data-testid="stSidebar"]{background:var(--side);border-right:1px solid var(--line)}
[data-testid="stProgress"] div[role="progressbar"]>div{background:var(--green)}
::-webkit-scrollbar{width:8px}::-webkit-scrollbar-thumb{background:#C9BEA6;border-radius:8px}
</style>
"""
