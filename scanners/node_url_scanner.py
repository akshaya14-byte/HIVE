import pickle
import numpy as np
import re
from fastapi import FastAPI
from scipy.sparse import hstack, csr_matrix

from urllib.parse import urlparse

from fastapi.middleware.cors import CORSMiddleware
from firebase_push import push_detection, push_blocklist

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

with open("phishing_model.pkl", "rb") as f:
    saved = pickle.load(f)
clf    = saved["clf_url"]        
scaler = saved["scaler_url"]
url_cols = saved["url_cols"]     
# ──────────────────────────────────────────────
# Feature Engineering (MUST match training)
# ──────────────────────────────────────────────

URL_RE   = re.compile(r"http\S+|www\.\S+")
EMAIL_RE = re.compile(r"\S+@\S+")
NUM_RE   = re.compile(r"\d+")

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".online"}
IP_RE           = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def preprocess_text(text: str) -> str:
    text = str(text).lower()
    text = URL_RE.sub(" URL ", text)
    text = EMAIL_RE.sub(" EMAIL ", text)
    text = NUM_RE.sub(" NUM ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def url_features(url: str) -> list:
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        host   = parsed.hostname or ""
        path   = parsed.path or ""
        query  = parsed.query or ""
    except:
        return [0] * 14

    return [
        len(url),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("//"),
        url.count("?"),
        url.count("="),
        int(IP_RE.match(host) is not None),
        int(any(host.endswith(t) for t in SUSPICIOUS_TLDS)),
        int(parsed.scheme == "https"),
        len(host.split(".")),
        len(path),
        len(query),
        host.count("-"),
    ]

def text_features(text: str) -> list:
    t = str(text).lower()
    words = t.split()
    return [
        len(t),
        len(words),
        t.count("!"),
        t.count("?"),
        sum(1 for c in text if c.isupper()) / max(len(text), 1),
        len(URL_RE.findall(text)),
        int(bool(EMAIL_RE.search(text))),
        0, 0, 0  # placeholder since we're URL-focused
    ]

# ──────────────────────────────────────────────
# API Endpoint
# ──────────────────────────────────────────────

PHISHING_TLDS = {
    "tk","ml","ga","cf","gq","xyz","top","club","online","pw","cc",
    "buzz","icu","cyou","cfd","monster","site","space","fun","ws","biz"
}
BRANDS = [
    "paypal","amazon","apple","google","microsoft","facebook","instagram",
    "netflix","ebay","bank","chase","security","verify","account","update",
    "confirm","login","signin","secure","support","service","helpdesk",
]
KNOWN_LEGIT = [
    "google","youtube","facebook","amazon","wikipedia","twitter","instagram",
    "linkedin","reddit","netflix","apple","microsoft","github","paypal","ebay",
]
IP_RE2 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def levenshtein(a, b):
    if a == b: return 0
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        curr = [i+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca!=cb)))
        prev = curr
    return prev[-1]

def domain_similarity(host):
    h = host.lower().replace("www.", "").split(".")[0]
    best = 0.0
    for l in KNOWN_LEGIT:
        ml = max(len(l), len(h), 1)
        best = max(best, (1 - levenshtein(h, l) / ml) * 100)
    return round(best, 2)

def compute_features(url):
    url = str(url)
    try:
        p    = urlparse(url if url.startswith("http") else "http://"+url)
        host = p.hostname or ""
        path = p.path    or ""
    except:
        host = path = ""
    tld     = host.split(".")[-1].lower() if "." in host else ""
    total   = max(len(url), 1)
    letters = sum(1 for c in url if c.isalpha())
    digits  = sum(1 for c in url if c.isdigit())
    specials = sum(1 for c in url if not c.isalnum() and c not in "://.?=&-_/")
    cont    = sum(1 for i in range(len(url)-1) if url[i]==url[i+1]) / max(len(url)-1, 1)

    base = {
        "URLLength": len(url), "DomainLength": len(host),
        "IsDomainIP": int(bool(IP_RE2.match(host))), "TLDLength": len(tld),
        "NoOfSubDomain": max(0, len(host.split("."))-2),
        "HasObfuscation": int("%" in url), "NoOfObfuscatedChar": url.count("%"),
        "ObfuscationRatio": url.count("%")/total,
        "NoOfLettersInURL": letters, "LetterRatioInURL": letters/total,
        "NoOfDegitsInURL": digits,   "DegitRatioInURL": digits/total,
        "NoOfEqualsInURL": url.count("="), "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "NoOfOtherSpecialCharsInURL": specials, "SpacialCharRatioInURL": specials/total,
        "IsHTTPS": int("https://" in url.lower()),
        "URLCharProb": letters/total, "CharContinuationRate": cont,
    }
    feat_vec = np.array([base.get(c, 0) for c in url_cols], dtype=float)

    sim   = domain_similarity(host)
    extra = {
        "suspicious_tld":    int(tld in PHISHING_TLDS),
        "ip_in_host":        int(bool(IP_RE2.match(host))),
        "domain_similarity": sim,
        "brand_keywords":    sum(1 for b in BRANDS if b in (host+path).lower()),
        "has_login_path":    int(any(kw in path.lower() for kw in
                               ("login","signin","verify","account","update","confirm","secure"))),
        "hyphen_in_domain":  int("-" in host.split(".")[0]) if host else 0,
        "many_params":       int(url.count("=") >= 3),
        "long_url":          int(len(url) > 75),
        "subdomain_count":   max(0, len(host.split("."))-2),
        "tld_full_host":     host.lower(),
    }
    return feat_vec, extra

def rule_score(extra):
    s = 0
    if extra["suspicious_tld"]:          s += 50
    if extra["ip_in_host"]:              s += 60
    if extra["domain_similarity"] < 20:  s += 25
    if extra["brand_keywords"] >= 2:     s += 30
    if extra["brand_keywords"] == 1:     s += 10
    if extra["has_login_path"]:          s += 15
    if extra["hyphen_in_domain"]:        s += 12
    if extra["many_params"]:             s += 10
    if extra["long_url"]:                s += 8
    if extra["subdomain_count"] >= 3:    s += 18
    if any(kw in extra["tld_full_host"] for kw in
           ("free","prize","giveaway","gift","lucky","winner","claim","reward")):
        s += 35
    if extra["domain_similarity"] > 85:  s -= 50
    if extra["domain_similarity"] > 60 and not extra["suspicious_tld"]: s -= 20
    return max(0, min(100, s))

@app.post("/scan_url")
def scan_url(data: dict):
    url = data.get("url")
    if not url:
        return {"error": "No URL provided"}

    feat_vec, extra = compute_features(url)
    x = scaler.transform(feat_vec.reshape(1, -1))

    if hasattr(clf, "predict_proba"):
        ml_prob = float(clf.predict_proba(x)[0][1])
    else:
        score   = clf.decision_function(x)[0]
        ml_prob = float(1 / (1 + np.exp(-score)))

    rule_prob = rule_score(extra) / 100.0
    combined  = 0.40 * ml_prob + 0.60 * rule_prob
    pred      = 1 if combined >= 0.30 else 0

    result = {
        "url":        url,
        "src_ip":     data.get("src_ip", "unknown"),
        "prediction": "PHISHING" if pred == 1 else "LEGITIMATE",
        "is_attack":  pred == 1,
        "risk_score": round(combined, 4),
        "ml_score":   round(ml_prob, 4),
        "rule_score": round(rule_prob, 4),
        "node":       "Campus Block A - URL Scanner",
    }

    # Push to Firebase dashboard
    push_detection(result, detection_type="url")

    return result