# walf.py
import os
import csv
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import re
import json
import time
import uuid
import base64
from difflib import SequenceMatcher
import logging
# Configuration
TIMEOUT = 8
THROTTLE = 0.6
CRAWL_DEPTH = 1
ID_NUM_RANGE_DEFAULT = (1, 5)
UUID_SAMPLE_COUNT = 3
HEADERS = {"User-Agent": "ALFA/1.0 (WALF Module)"}
REPORT_DIR = "reports"
LOG_FILE = "alfa_scan.log"

# Common paths
COMMON_LOGIN_PATHS = ["/login", "/signin", "/users/sign_in", "/auth/login", "/accounts/login", "/signin.php"]
ADMIN_PATHS = ["/admin", "/administrator", "/admin/dashboard", "/manage"]

# Regex patterns
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
NUMERIC_RE = re.compile(r"^\d+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{8,}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# PII regex (for redaction)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\-\s]{6,}\d")

# Setup logging
logger = logging.getLogger("alfa.walf")
logger.setLevel(logging.INFO)

def gen_scan_id():
    return time.strftime("walf-%Y%m%d-%H%M%S", time.localtime())

def gen_finding_id(seq=1):
    scan_id = gen_scan_id()
    return f"{scan_id}-F-{seq:04d}"

def assess_severity(f):
    """Heuristic scoring -> severity + numeric score"""
    score = 0.0
    resp = f.get("response", {}) or {}
    status = resp.get("status")
    sample = (resp.get("sample") or "")[:2000]

    if status == 200:
        score += 3.0
    if status and status in (401,403,404):
        score -= 2.0
    if EMAIL_RE.search(sample) or PHONE_RE.search(sample):
        score += 3.0
    if f.get("content_similarity_to_baseline") is not None:
        sim = f["content_similarity_to_baseline"]
        if sim < 0.95:
            score += 2.0
    scen = (f.get("scenario") or "").lower()
    if "idor" in scen or "hidden" in scen or "sequential" in scen or "mutation" in scen:
        score += 1.0

    if score >= 6:
        severity = "High"
    elif score >= 3:
        severity = "Medium"
    else:
        severity = "Low"
    return severity, round(score,2)

def build_poc_curl(f, session_cookie_name="session"):
    """Build a quick PoC curl string. Replace cookie placeholder before use."""
    t = f.get("target") or f.get("action") or ""
    cookie = "SESS_FAKE"  # placeholder — user must replace with real session
    scen = (f.get("scenario") or "")
    if scen.startswith("hidden_post") or scen.startswith("hidden"):
        action = f.get("action") or t
        field = f.get("field", "id")
        value = f.get("value", "1")
        # simple form POST PoC
        return f"curl -i -X POST -b '{session_cookie_name}={cookie}' -d '{field}={value}' '{action}'"
    else:
        return f"curl -i -b '{session_cookie_name}={cookie}' '{t}'"

def dedupe_findings(findings):
    seen=set(); out=[]
    for f in findings:
        key = (f.get("scenario"), f.get("target"), str(f.get("value")), f.get("action"), f.get("field"))
        if key in seen: continue
        seen.add(key); out.append(f)
    return out

def redact_text(s):
    if not s: return s
    s = EMAIL_RE.sub("[REDACTED_EMAIL]", s)
    s = PHONE_RE.sub("[REDACTED_PHONE]", s)
    s = re.sub(r"\b\d{9,}\b", "[REDACTED_NUMBER]", s)
    return s

def ensure_reports_dir():
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
    except Exception as e:
        logger.debug(f"ensure_reports_dir error: {e}")

def export_csv(findings, fname):
    keys=["id","title","scenario","severity","score","confidence","status","owner","estimated_fix_days","poc_curl","repro_steps","target"]
    try:
        with open(fname,"w",newline="",encoding="utf-8") as fh:
            w=csv.writer(fh)
            w.writerow(keys)
            for f in findings:
                row=[
                    f.get("id",""),
                    f.get("title",""),
                    f.get("scenario",""),
                    f.get("severity",""),
                    f.get("score",""),
                    f.get("confidence",""),
                    f.get("status",""),
                    f.get("owner",""),
                    f.get("estimated_fix_days",""),
                    f.get("poc_curl",""),
                    " | ".join(f.get("repro_steps",[])),
                    f.get("target","")
                ]
                w.writerow(row)
        logger.info(f"[+] CSV exported -> {fname}")
    except Exception as e:
        logger.error(f"[-] CSV export failed: {e}")

def normalise_url(u):
    try:
        p = urlparse(u)
        return urlunparse((p.scheme, p.netloc, p.path, "", p.query, ""))
    except Exception:
        return u

def same_domain(a, b):
    try:
        return urlparse(a).netloc == urlparse(b).netloc
    except Exception:
        return False

def safe_get(session, url, **kwargs):
    try:
        return session.get(url, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except requests.RequestException as e:
        logger.debug(f"safe_get exception for {url}: {e}")
        return e

def safe_post(session, url, data=None, **kwargs):
    try:
        return session.post(url, data=data, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except requests.RequestException as e:
        logger.debug(f"safe_post exception for {url}: {e}")
        return e

def detect_id_type(val):
    if val is None or val == "":
        return None
    v = str(val).strip()
    if UUID_RE.match(v): return "uuid"
    if NUMERIC_RE.match(v): return "numeric"
    if MD5_RE.match(v): return "md5"
    if SHA1_RE.match(v): return "sha1"
    if SHA256_RE.match(v): return "sha256"
    if BASE64_RE.match(v): return "base64-like"
    if len(v) <= 6 and v.isdigit(): return "numeric"
    if len(v) >= 20: return "long-string"
    return "unknown"

def similarity(a, b):
    try:
        return SequenceMatcher(None, a or "", b or "").ratio()
    except Exception:
        return 0.0

def response_sig(resp):
    base = {"status": None, "len": None, "sample": "", "headers": {}, "error": None}
    if isinstance(resp, Exception):
        base["error"] = str(resp)
        return base
    # safe extraction
    try:
        text = getattr(resp, "text", "") or ""
        base["status"] = getattr(resp, "status_code", None)
        base["len"] = len(text)
        base["sample"] = text[:2000]
    except Exception as e:
        base["error"] = f"read-text-error: {e}"
    try:
        base["headers"] = dict(getattr(resp, "headers", {}) or {})
    except Exception:
        base["headers"] = {}
    return base

def login_success_heuristic(resp):
    if isinstance(resp, Exception): return False
    txt = getattr(resp, "text", "") or ""
    if getattr(resp, "status_code", None) in (302,):
        return True
    low = txt.lower()
    if "logout" in low or "sign out" in low or "dashboard" in low or "my account" in low:
        return True
    if getattr(resp, "status_code", None) == 200 and ("login" not in low and "signin" not in low):
        return True
    return False

def _short(text, n=800):
    if not text: return ""
    return text[:n] + ("..." if len(text) > n else "")

def dump_login_debug(resp, session, output_logs):
    """Append structured debug about login response & session cookies into output['logs'].
    IMPORTANT: do NOT log cookie values — only cookie names.
    """
    try:
        headers = dict(getattr(resp, "headers", {}) or {}) if hasattr(resp, "headers") else {}
    except Exception:
        headers = {}
    try:
        cookie_names = list(session.cookies.get_dict().keys())
    except Exception:
        cookie_names = []
    msg = {
        "ts": time.time(),
        "level": "debug",
        "msg": (
            f"login_resp_status={getattr(resp,'status_code',None)} "
            f"history={[getattr(h,'status_code',None) for h in getattr(resp,'history',[])]} "
            f"set-cookie_keys={[k for k in headers.keys() if 'set-cookie' in k.lower() or k.lower()=='set-cookie']} "
            f"session_cookie_names={cookie_names}"
        )
    }
    output_logs.append(msg)
    try:
        body = getattr(resp, "text", "") or ""
        output_logs.append({"ts": time.time(), "level": "debug", "msg": f"login_resp_sample={_short(redact_text(body),400)}"})
    except Exception:
        pass

def verify_session_auth(session, base_url, output_logs, check_paths=None):
    """
    Check a small set of post-login endpoints to confirm we are authenticated.
    Returns (True, evidence) if pass; otherwise (False, details).
    """
    # broaden default checks; include root and common user pages
    if check_paths is None:
        check_paths = ["/", "/users", "/dashboard", "/profile", "/account", "/logout"]
    indicators = ["logout", "dashboard", "my account", "user id", "profile", "sign out", "sign-out"]
    last_sig = None
    for p in check_paths:
        url = urljoin(base_url, p)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        last_sig = sig
        output_logs.append({"ts": time.time(), "level": "debug", "msg": f"verify GET {url} -> status={sig.get('status')} len={sig.get('len')}"} )
        body = (sig.get("sample") or "").lower()
        for ind in indicators:
            if ind in body:
                evidence = {"path": p, "indicator": ind, "status": sig.get("status")}
                output_logs.append({"ts": time.time(), "level": "info", "msg": f"verify success via {p} (indicator='{ind}')"})
                return True, evidence
    return False, {"reason": "no indicator found", "last_status": (last_sig.get("status") if last_sig else None)}

def detect_login_candidates(target, session, logs):
    base = target.rstrip("/")
    candidates = []
    for p in COMMON_LOGIN_PATHS:
        u = urljoin(base, p)
        logs.append(f"[detect] trying common path {u}")
        r = safe_get(session, u, headers=HEADERS)
        time.sleep(THROTTLE)
        if isinstance(r, Exception):
            logs.append(f"  - error {r}")
            candidates.append((u, ""))
            continue
        text = getattr(r, "text", "") or ""
        if "password" in text.lower() or "sign in" in text.lower() or "log in" in text.lower():
            candidates.append((u, text))
            logs.append(f"  - login-like page found: {u}")
        else:
            candidates.append((u, text))
    root = safe_get(session, base, headers=HEADERS)
    time.sleep(THROTTLE)
    if not isinstance(root, Exception):
        soup = BeautifulSoup(getattr(root, "text", "") or "", "html.parser")
        for f in soup.find_all("form"):
            if f.find("input", {"type":"password"}):
                action = f.get("action") or ""
                action_url = urljoin(base, action)
                candidates.append((action_url, str(f)))
                logs.append(f"[detect] form-with-password found on root -> action {action_url}")
    seen=set(); uniq=[]
    for u,html_text in candidates:
        nu = normalise_url(u)
        if nu not in seen:
            seen.add(nu); uniq.append((u,html_text))
    return uniq

def inspect_form_html(html_text):
    """
    Parse inputs and attempt to find CSRF tokens including meta tags.
    Returns: {"auth_candidates": [...], "csrf": {name: value}, "inputs": [...], "html": str(soup)}
    """
    soup = BeautifulSoup(html_text or "", "html.parser")
    inputs=[]; csrf_fields={}; auth_types=set()
    for inp in soup.find_all(("input","textarea","select")):
        name = inp.get("name")
        itype = (inp.get("type") or "text").lower()
        val = inp.get("value") or ""
        if not name:
            continue
        inputs.append({"name":name,"type":itype,"value":val})
        if "email" in name.lower() or "e-mail" in name.lower():
            auth_types.add("email")
        if "user" in name.lower() or "username" in name.lower() or "login" in name.lower():
            auth_types.add("username")
        if itype=="hidden":
            csrf_fields[name]=val

    # additional: capture meta CSRF tokens commonly used by JS
    for meta in soup.find_all("meta"):
        mname = (meta.get("name") or "").lower()
        if mname in ("csrf-token","csrf","xsrf-token","csrfmiddlewaretoken","x-csrf-token","csrf-token"):
            key = meta.get("name") or mname
            csrf_fields[key] = meta.get("content") or meta.get("value") or ""

    if not auth_types:
        for inp in soup.find_all("input"):
            ph = (inp.get("placeholder") or "").lower()
            if "email" in ph: auth_types.add("email")
            if "user" in ph or "username" in ph: auth_types.add("username")
    return {"auth_candidates": sorted(list(auth_types)) or ["unknown"], "csrf": csrf_fields, "inputs": inputs, "html": str(soup)}

def crawl_bfs(session, base_url, depth=CRAWL_DEPTH, logs=None):
    logs = logs or []
    base = base_url.rstrip("/")
    visited=set()
    queue=[(base,0)]
    found_urls=set()
    found_forms=[]
    while queue:
        url, d = queue.pop(0)
        if d>depth: continue
        nu = normalise_url(url)
        if nu in visited: continue
        visited.add(nu)
        logs.append(f"[crawl] {nu} (d={d})")
        r = safe_get(session, nu, headers=HEADERS)
        time.sleep(THROTTLE)
        if isinstance(r, Exception):
            logs.append(f"  - error {r}")
            continue
        text = getattr(r, "text", "") or ""
        soup = BeautifulSoup(text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a.get("href").strip()
            if href.startswith("javascript:") or href.startswith("#") or href.lower().startswith("mailto:"): continue
            full = urljoin(nu, href)
            if same_domain(base, full):
                fnu = normalise_url(full)
                found_urls.add(fnu)
                if fnu not in visited:
                    queue.append((full, d+1))
        for f in soup.find_all("form"):
            action = f.get("action") or ""
            action_url = urljoin(nu, action)
            inputs=[]
            for inp in f.find_all(("input","textarea","select")):
                name = inp.get("name")
                itype = (inp.get("type") or "text").lower()
                val = inp.get("value") or ""
                if name:
                    inputs.append({"name":name,"type":itype,"value":val})
            found_forms.append({"page":nu,"action":normalise_url(action_url),"inputs":inputs})
    return {"urls": sorted(found_urls), "forms": found_forms, "logs": logs}

def detect_ids_in_url(u):
    parsed = urlparse(u)
    ids=[]
    qs = parse_qs(parsed.query)
    for k,v in qs.items():
        if not v: continue
        ids.append({"location":"query","url":normalise_url(u),"param":k,"sample":v[0],"type": detect_id_type(v[0])})
    for seg in parsed.path.strip("/").split("/"):
        t = detect_id_type(seg)
        if t:
            ids.append({"location":"path","url":normalise_url(u),"param":None,"sample":seg,"type":t})
    return ids

def detect_ids_in_form(f):
    ids=[]
    for inp in f.get("inputs", []):
        name = inp.get("name")
        val = inp.get("value") or ""
        if name and ("id" in name.lower() or detect_id_type(val) in ("numeric","uuid","base64-like","md5","sha1","sha256")):
            ids.append({"location":"form","action":f.get("action"),"param":name,"sample":val,"type":detect_id_type(val)})
    return ids

def gen_numeric(start, end): return [str(i) for i in range(start, end+1)]
def gen_uuids(n): return [str(uuid.uuid4()) for _ in range(n)]
def gen_base64_samples(n=3):
    out=[]
    for i in range(n):
        out.append(base64.b64encode(f"user{i}".encode()).decode())
    return out

def run_sequential_path(session, template, id_values, logs):
    findings=[]
    logs.append("[1] Sequential ID Tampering (Path) - LEVEL 3")
    use_brace = "{id}" in template
    baseline = None
    for vid in id_values:
        url = template.replace("{id}", str(vid)) if use_brace else template.rstrip("/") + "/" + str(vid)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
        findings.append({"scenario":"sequential_path","target":url,"value":vid,"response":sig})
        if baseline is None and sig.get("status")==200:
            baseline = sig.get("sample","")
    numeric_vals = []
    try:
        numeric_vals = [int(v) for v in id_values if NUMERIC_RE.match(str(v))]
    except Exception:
        numeric_vals = []
    if numeric_vals:
        found200 = sum(1 for f in findings if f["response"].get("status")==200)
        if found200 >= 2:
            lo = min(numeric_vals); hi = max(numeric_vals)
            for d in range(1, 8):
                for v in (lo-d, hi+d):
                    if v <= 0: continue
                    url = template.replace("{id}", str(v)) if use_brace else template.rstrip("/") + "/" + str(v)
                    r = safe_get(session, url, headers=HEADERS)
                    sig = response_sig(r)
                    logs.append(f"  [expand] GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
                    findings.append({"scenario":"sequential_path_expand","target":url,"value":v,"response":sig})
    if baseline:
        for f in findings:
            resp = f.get("response", {}) or {}
            if resp.get("status")!=200: continue
            sim = similarity(baseline[:2000], resp.get("sample","")[:2000])
            f["content_similarity_to_baseline"] = sim
            if sim < 0.95:
                f["flag"] = "content-diff"
                logs.append(f"  [diff] {f.get('target')} similarity {sim:.2f} -> flagged")
    return findings

def run_sequential_query(session, url_template, param, id_values, logs):
    findings=[]
    logs.append("[2] Sequential ID Tampering (Query Param) - LEVEL 3")
    parsed = urlparse(url_template)
    qs = parse_qs(parsed.query)
    base_noq = parsed._replace(query=None).geturl()
    for vid in id_values:
        qs_local = dict(qs)
        qs_local[param] = [str(vid)]
        new_url = parsed._replace(query=urlencode(qs_local, doseq=True)).geturl()
        r = safe_get(session, new_url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {new_url} -> {sig.get('status')}")
        findings.append({"scenario":"sequential_query","target":new_url,"param":param,"value":vid,"response":sig})
        dup_q = f"{param}={qs_local[param][0]}&{param}={vid}"
        dup_url = base_noq + "?" + dup_q
        r2 = safe_get(session, dup_url, headers=HEADERS)
        s2 = response_sig(r2)
        logs.append(f"  GET (HPP) {dup_url} -> {s2.get('status')}")
        findings.append({"scenario":"sequential_query_hpp","target":dup_url,"param":param,"value":vid,"response":s2})
        rpost = safe_post(session, base_noq, data={param:str(vid)}, headers=HEADERS)
        sp = response_sig(rpost)
        logs.append(f"  POST {base_noq} {param}={vid} -> {sp.get('status')}")
        findings.append({"scenario":"sequential_query_post","target":base_noq,"param":param,"value":vid,"response":sp})
        mutations=[]
        try:
            if NUMERIC_RE.match(str(vid)):
                mutations.append(str(vid).zfill(4))
                mutations.append(hex(int(vid))[2:])
            mutations.append(base64.b64encode(str(vid).encode()).decode())
        except Exception:
            pass
        for m in mutations:
            qs_mut = dict(qs); qs_mut[param]=[m]
            mu = parsed._replace(query=urlencode(qs_mut,doseq=True)).geturl()
            rm = safe_get(session, mu, headers=HEADERS)
            sm = response_sig(rm)
            logs.append(f"  GET (mut) {mu} -> {sm.get('status')}")
            findings.append({"scenario":"sequential_query_mutation","target":mu,"param":param,"value":m,"response":sm})
    return findings

def try_parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None

def run_hidden_field_tests(session, form, id_candidates, logs):
    findings=[]
    logs.append("[3] Hidden Field Manipulation (POST/JSON) - LEVEL 3")
    action = form.get("action")
    post_data = {inp["name"]: inp.get("value","") for inp in form.get("inputs", [])}
    fields = [n for n in post_data.keys() if "id" in n.lower()]
    if not fields:
        fields = [n for n in post_data.keys()][:1] if post_data else []
    if not fields:
        logs.append("  - no postable id-like fields found")
        return findings
    id_pool=[]
    for it in id_candidates:
        if isinstance(it, dict):
            v = it.get("sample");
            if v: id_pool.append(str(v))
        else:
            id_pool.append(str(it))
    id_pool += [str(i) for i in range(1,6)]
    id_pool = list(dict.fromkeys(id_pool))
    for field in fields:
        for candidate in id_pool:
            data = post_data.copy(); data[field] = candidate
            # include Referer/Origin for POSTs too (increase chance accepted)
            headers_post = {**HEADERS}
            try:
                parsed_action = urlparse(action)
                headers_post["Referer"] = urljoin(action, "/")
                headers_post["Origin"] = f"{parsed_action.scheme}://{parsed_action.netloc}"
            except Exception:
                pass
            r = safe_post(session, action, data=data, headers=headers_post)
            sig = response_sig(r)
            logs.append(f"  POST {action} {field}={candidate} -> {sig.get('status')}")
            findings.append({"scenario":"hidden_post","action":action,"field":field,"value":candidate,"response":sig})
            ct = sig.get("headers", {}) or {}
            ct_val = ""
            for hk in ct:
                if hk.lower() == "content-type":
                    ct_val = ct[hk]; break
            if "application/json" in ct_val or (try_parse_json(sig.get("sample","")) is not None):
                headers_json = headers_post.copy(); headers_json["Content-Type"]="application/json"
                rj = safe_post(session, action, data=json.dumps(data), headers=headers_json)
                sj = response_sig(rj)
                logs.append(f"  POST(JSON) {action} {field}={candidate} -> {sj.get('status')}")
                findings.append({"scenario":"hidden_post_json","action":action,"field":field,"value":candidate,"response":sj})
    for field in fields:
        for candidate in id_pool[:3]:
            headers_alt = HEADERS.copy(); headers_alt["Content-Type"]="application/x-www-form-urlencoded; charset=UTF-8"
            ralt = safe_post(session, action, data={field:candidate}, headers=headers_alt)
            salt = response_sig(ralt)
            logs.append(f"  POST(alt-ct) {action} {field}={candidate} -> {salt.get('status')}")
            findings.append({"scenario":"hidden_post_altct","action":action,"field":field,"value":candidate,"response":salt})
    return findings

def run_role_response_comparison(session, url_template, compare_ids, logs):
    findings=[]
    logs.append("[4] Role Response Comparison (self-check) - LEVEL 3")
    samples=[]
    for vid in compare_ids:
        url = url_template.replace("{id}",str(vid)) if "{id}" in url_template else urljoin(url_template, str(vid))
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        txt = sig.get("sample","")
        samples.append((vid, txt, sig))
        logs.append(f"  GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
    if len(samples) >= 2:
        a = samples[0][1]; b = samples[1][1]
        sim = similarity(a, b)
        ja = try_parse_json(a); jb = try_parse_json(b)
        json_diff = None
        if ja is not None and jb is not None and isinstance(ja, dict) and isinstance(jb, dict):
            na = normalize_json(ja); nb = normalize_json(jb)
            keys_a = set(na.keys()); keys_b = set(nb.keys())
            added = list(keys_b - keys_a); removed = list(keys_a - keys_b)
            json_diff = {"added_keys": added, "removed_keys": removed}
            logs.append(f"  JSON diff -> added:{added} removed:{removed}")
        combined = a + "\n" + b
        emails = list(set(EMAIL_RE.findall(combined)))
        phones = list(set(PHONE_RE.findall(combined)))
        findings.append({"scenario":"role_response_comparison","pairs":[(samples[0][0],samples[1][0])],"similarity":sim,"json_diff":json_diff,"emails":emails,"phones":phones,"response":{}})
        logs.append(f"  similarity={sim:.2f} ; emails_found={len(emails)} phones_found={len(phones)}")
    return findings

COMMON_ADMIN_PATHS = ADMIN_PATHS + ["/admin/login","/admin-console","/manage/account","/cms","/dashboard/admin","/admin/api","/api/admin"]
COMMON_GUESS_SUFFIXES = ["/orders/{}","/order/{}","/invoices/{}","/transactions/{}"]

def run_vertical_privilege(session, base_url, logs):
    findings=[]
    logs.append("[5] Vertical Privilege Escalation (/admin) - LEVEL 3")
    for p in COMMON_ADMIN_PATHS:
        url = urljoin(base_url, p)
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {p} -> {sig.get('status')}")
        findings.append({"scenario":"vertical_admin","target":url,"response":sig})
        probe_headers = [
            {"X-Original-URL": p},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": urlparse(base_url).netloc},
        ]
        for hh in probe_headers:
            rh = safe_get(session, url, headers={**HEADERS, **hh})
            sh = response_sig(rh)
            logs.append(f"  header-probe {list(hh.keys())[0]} -> {sh.get('status')}")
            findings.append({"scenario":"vertical_admin_header_probe","target":url,"headers":hh,"response":sh})
    return findings

def run_horizontal_privilege(session, base_url, profile_template, id_values, logs):
    findings=[]
    logs.append("[6] Horizontal Privilege Escalation - LEVEL 3")
    for vid in id_values:
        url = profile_template.replace("{id}",str(vid)) if "{id}" in profile_template else urljoin(base_url, f"/profile/{vid}")
        r = safe_get(session, url, headers=HEADERS)
        sig = response_sig(r)
        logs.append(f"  GET {url} -> {sig.get('status')} ({sig.get('len')} bytes)")
        findings.append({"scenario":"horizontal_profile","target":url,"value":vid,"response":sig})
        for sfx in COMMON_GUESS_SUFFIXES:
            guess = urljoin(base_url, sfx.format(vid))
            rg = safe_get(session, guess, headers=HEADERS)
            sg = response_sig(rg)
            logs.append(f"  GET {guess} -> {sg.get('status')}")
            findings.append({"scenario":"horizontal_nested_guess","target":guess,"value":vid,"response":sg})
    if len(id_values) >= 2:
        a = id_values[0]; b = id_values[1]
        u_a = profile_template.replace("{id}",str(a)) if "{id}" in profile_template else urljoin(base_url, f"/profile/{a}")
        u_b = profile_template.replace("{id}",str(b)) if "{id}" in profile_template else urljoin(base_url, f"/profile/{b}")
        ra = safe_get(session, u_a, headers=HEADERS); rb = safe_get(session, u_b, headers=HEADERS)
        ta, tb = getattr(ra,"text","") or "", getattr(rb,"text","") or ""
        sim = similarity(ta, tb)
        logs.append(f"  profile pair similarity {a}/{b} -> {sim:.2f}")
        findings.append({"scenario":"horizontal_semantic_compare","pair":(a,b),"similarity":sim,"response":{}})
    return findings

def normalize_json(obj):
    if isinstance(obj, dict):
        out={}
        for k,v in obj.items():
            if any(x in k.lower() for x in ["created_at","updated_at","timestamp","ts","expires_at","expiry","last_login","id_token","csrf_token"]):
                continue
            out[k]=normalize_json(v)
        return out
    if isinstance(obj, list):
        return [normalize_json(x) for x in obj]
    return obj

def run_level3_advanced_tests(session, base_url, id_info, logs):
    findings=[]
    logs.append("[L3] Starting Level-3 advanced orchestration")
    numeric_ids = []
    profile_template = None
    for it in id_info:
        if it.get("type")=="numeric":
            try: numeric_ids.append(int(it.get("sample")))
            except: pass
        if it.get("location")=="path" and "/profile/" in (it.get("url") or "") and profile_template is None:
            p = urlparse(it.get("url"))
            segs = p.path.strip("/").split("/")
            new=[]; found=False
            for s in segs:
                if NUMERIC_RE.match(s) and not found:
                    new.append("{id}"); found=True
                else:
                    new.append(s)
            if found:
                profile_template = urljoin(base_url, "/".join(new))
    if not profile_template:
        profile_template = urljoin(base_url, "/profile/{id}")
    id_pool = [str(i) for i in (numeric_ids if numeric_ids else [1,2,3,4,5])]
    id_pool += [str(uuid.uuid4()) for _ in range(3)]
    id_pool = list(dict.fromkeys(id_pool))
    findings += run_sequential_path(session, profile_template, id_pool, logs)
    q_candidate=None; qparam=None
    for s in id_info:
        u = s.get("url") or ""
        parsed = urlparse(u); qs = parse_qs(parsed.query)
        if qs:
            for k,v in qs.items():
                if v and detect_id_type(v[0]) in ("numeric","uuid","unknown"):
                    q_candidate = u; qparam = k; break
        if q_candidate: break
    if q_candidate:
        findings += run_sequential_query(session, q_candidate, qparam, id_pool, logs)
    for it in id_info:
        if it.get("location")=="form":
            try:
                findings.extend(run_hidden_field_tests(session, {"action":it.get("action"), "inputs":[{"name":it.get("param"), "type":"text", "value":it.get("sample")}]}, [it], logs))
            except Exception as e:
                logs.append(f"  [l3] hidden test error: {e}")
    for s in id_info:
        if s.get("type")=="base64-like":
            sample = s.get("sample")
            try:
                dec = base64.b64decode(sample).decode(errors="ignore")
                logs.append(f"  [l3] base64 decode {sample} -> {dec}")
                if dec.isdigit():
                    pool = [dec] + [str(int(dec)+i) for i in (-1,1,2)]
                    findings += run_sequential_path(session, profile_template, pool, logs)
            except Exception as e:
                logs.append(f"  [l3] base64 decode err: {e}")
    for s in id_info:
        if s.get("type")=="uuid":
            try:
                muts = [str(uuid.uuid4()) for _ in range(4)]
                findings += run_sequential_path(session, profile_template, muts, logs)
            except Exception:
                pass
            break
    if len(id_pool) >= 2:
        a = id_pool[0]; b = id_pool[1]
        ua = profile_template.replace("{id}",str(a)); ub = profile_template.replace("{id}",str(b))
        t0 = time.time(); ra = safe_get(session, ua, headers=HEADERS); ta = time.time()-t0
        t1 = time.time(); rb = safe_get(session, ub, headers=HEADERS); tb = time.time()-t1
        logs.append(f"  [timing] {ua} -> {ta:.3f}s ; {ub} -> {tb:.3f}s")
        findings.append({"scenario":"timing_probe","targets":[ua,ub],"times":[ta,tb],"response":{}})
        if abs(ta-tb) > 0.5:
            findings.append({"scenario":"timing_anomaly","details":f"time_diff={abs(ta-tb):.3f}s","response":{}})
    logs.append("[L3] Completed Level-3 orchestration")
    return findings

def run_walf_tests(session, base_url, output_dir):
    """
    Main function to run WALF tests for IDOR and privilege escalation
    """
    logs = []
    findings = []
    
    try:
        # Crawl the target
        crawl_result = crawl_bfs(session, base_url, depth=CRAWL_DEPTH, logs=logs)
        urls = crawl_result['urls']
        forms = crawl_result['forms']
        
        # Detect IDs in URLs and forms
        id_candidates = []
        for u in urls: 
            id_candidates.extend(detect_ids_in_url(u))
        for f in forms: 
            id_candidates.extend(detect_ids_in_form(f))
        
        # Remove duplicates
        uniq = []
        seen = set()
        for it in id_candidates:
            key = (it.get("location"), it.get("url") or it.get("action"), it.get("param"), it.get("sample"))
            if key not in seen:
                seen.add(key)
                uniq.append(it)
        
        # Generate test data
        numeric_ids = [str(i) for i in range(1, 6)]  # 1-5
        uuid_samples = [str(uuid.uuid4()) for _ in range(UUID_SAMPLE_COUNT)]
        id_test_pool = numeric_ids + uuid_samples
        
        # Find profile template
        profile_template = None
        for u in urls:
            segs = urlparse(u).path.strip("/").split("/")
            new = []
            found_num = False
            for s in segs:
                if NUMERIC_RE.match(s):
                    new.append("{id}")
                    found_num = True
                else:
                    new.append(s)
            if found_num:
                profile_template = urljoin(base_url, "/".join(new))
                break
        if not profile_template:
            profile_template = urljoin(base_url, "/profile/{id}")
        
        # Run all tests
        findings.extend(run_sequential_path(session, profile_template, numeric_ids, logs))
        
        # Find query parameter candidate
        query_candidate = None
        qparam = None
        for u in urls:
            parsed = urlparse(u)
            qs = parse_qs(parsed.query)
            for k, v in qs.items():
                if v and (detect_id_type(v[0]) in ("numeric", "uuid", "unknown")):
                    query_candidate = u
                    qparam = k
                    break
            if query_candidate:
                break
        
        if query_candidate:
            findings.extend(run_sequential_query(session, query_candidate, qparam, numeric_ids, logs))
        
        for f in forms:
            findings.extend(run_hidden_field_tests(session, f, id_test_pool, logs))
        
        compare_ids = numeric_ids[:2] if len(numeric_ids) >= 2 else numeric_ids
        findings.extend(run_role_response_comparison(session, profile_template, compare_ids, logs))
        
        findings.extend(run_vertical_privilege(session, base_url, logs))
        findings.extend(run_horizontal_privilege(session, base_url, profile_template, numeric_ids, logs))
        findings.extend(run_level3_advanced_tests(session, base_url, uniq, logs))
        
        # Assess severity for all findings
        for f in findings:
            severity, score = assess_severity(f)
            f['severity'] = severity
            f['score'] = score
            f['confidence'] = "High" if score > 4 else "Medium"
            f['poc_curl'] = build_poc_curl(f)
        
    except Exception as e:
        logger.error(f"Error running WALF tests: {e}")
        logs.append(f"Error running WALF tests: {e}")
    
    return findings