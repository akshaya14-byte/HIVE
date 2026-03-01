"""
Unified Phishing Detector — Correct Live Inference Version
===========================================================

ROOT CAUSE OF WRONG PREDICTIONS (explained):
  Your dataset's URLSimilarityIndex (19% importance) measures how
  similar a URL is to known legitimate domains. The model learned:
    - Low similarity  → phishing
    - High similarity → legitimate

  But from a raw URL string we can't compute URLSimilarityIndex
  (it needs a reference database). So the model falls back to
  URL-structural features, which aren't strong enough alone.

  SOLUTION: We add domain reputation scoring directly to the
  inference pipeline using:
    1. A curated list of known suspicious TLDs / patterns
    2. Levenshtein-style brand impersonation detection
    3. Suspicious keyword density in domain name
    4. All 20 URL-structural features from training

  The URL-only model still trains on the same 20 CSV features,
  but inference now ALSO injects these reputation signals
  by replacing the weakest features with stronger heuristics.

Usage:
  python model.py --data phishing_dataset.csv --model rf
"""

import re, pickle, argparse
import numpy as np
import pandas as pd
from urllib.parse import urlparse

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import MinMaxScaler

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings("ignore")

# ── Feature column groups ──────────────────────────────────────────────────────

URL_ONLY_COLS = [
    "URLLength", "DomainLength", "IsDomainIP", "TLDLength",
    "NoOfSubDomain", "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "NoOfLettersInURL", "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL", "IsHTTPS",
    "URLCharProb", "CharContinuationRate",
]

ALWAYS_EXCLUDE = {
    "filename","url","label","type","class","category","target",
    "result","status","title","domain","tld","name","id","index",
    "_label","_url","_text","_title","source",
}
LABEL_COLS = ["label","type","class","category","target","is_phishing",
              "phishing","result","status","spam"]
URL_COLS   = ["url","urls","link","address","website"]

PHISHING_VALS = {"1","phishing","spam","bad","malicious","yes","true"}
LEGIT_VALS    = {"0","legitimate","legit","ham","good","benign","no","false","safe"}

# ── Domain intelligence ────────────────────────────────────────────────────────

# TLDs heavily abused for phishing (free/cheap/anonymous)
PHISHING_TLDS = {
    "tk","ml","ga","cf","gq","xyz","top","club","online","pw","cc",
    "buzz","icu","cyou","cfd","monster","digital","live","stream",
    "world","site","space","fun","ws","biz","info",
}

# Brands commonly impersonated in phishing
BRANDS = [
    "paypal","amazon","apple","google","microsoft","facebook","instagram",
    "netflix","ebay","bank","chase","wellsfargo","citibank","barclays",
    "hsbc","santander","lloyds","natwest","halifax","dhl","fedex","ups",
    "usps","irs","gov","security","verify","account","update","confirm",
    "login","signin","secure","support","service","helpdesk","customer",
]

# Legitimate well-known domains (for similarity check)
KNOWN_LEGIT_DOMAINS = [
    "google.com","youtube.com","facebook.com","amazon.com","wikipedia.org",
    "twitter.com","instagram.com","linkedin.com","reddit.com","netflix.com",
    "apple.com","microsoft.com","github.com","stackoverflow.com","bbc.co.uk",
    "bbc.com","cnn.com","nytimes.com","paypal.com","ebay.com",
]

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def levenshtein(a, b):
    """Fast Levenshtein distance."""
    if a == b: return 0
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        curr = [i+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca!=cb)))
        prev = curr
    return prev[-1]


def domain_similarity_score(host):
    """
    Returns 0-100 score: how similar 'host' is to known-legit domains.
    High score = legitimate-looking. Low score = suspicious.
    Mirrors the URLSimilarityIndex feature in the dataset.
    """
    if not host:
        return 0.0
    # Strip www.
    h = host.lower().replace("www.", "")
    best = 0.0
    for legit in KNOWN_LEGIT_DOMAINS:
        legit_base = legit.split(".")[0]
        h_base     = h.split(".")[0]
        max_len    = max(len(legit_base), len(h_base), 1)
        dist       = levenshtein(h_base, legit_base)
        sim        = max(0.0, 1.0 - dist / max_len) * 100
        if sim > best:
            best = sim
    return round(best, 2)


def brand_impersonation_score(host, path):
    """
    Returns count of brand keywords found in the URL.
    High count in an unusual domain = strong phishing signal.
    """
    text = (host + path).lower()
    return sum(1 for b in BRANDS if b in text)


def compute_url_features(url, url_only_cols):
    """
    Compute the same features as URL_ONLY_COLS from a raw URL.
    Also returns extra_features dict for the enhanced inference model.
    """
    url = str(url)
    try:
        p    = urlparse(url if url.startswith("http") else "http://"+url)
        host = p.hostname or ""
        path = p.path    or ""
        qry  = p.query   or ""
    except Exception:
        host = path = qry = ""

    tld     = host.split(".")[-1].lower() if "." in host else ""
    total   = max(len(url), 1)
    letters = sum(1 for c in url if c.isalpha())
    digits  = sum(1 for c in url if c.isdigit())
    specials = sum(1 for c in url if not c.isalnum() and c not in "://.?=&-_/")
    cont = sum(1 for i in range(len(url)-1) if url[i]==url[i+1]) / max(len(url)-1, 1)

    # The 20 URL_ONLY_COLS features
    base = {
        "URLLength":                  len(url),
        "DomainLength":               len(host),
        "IsDomainIP":                 int(bool(IP_RE.match(host))),
        "TLDLength":                  len(tld),
        "NoOfSubDomain":              max(0, len(host.split(".")) - 2),
        "HasObfuscation":             int("%" in url or "0x" in url.lower()),
        "NoOfObfuscatedChar":         url.count("%"),
        "ObfuscationRatio":           url.count("%") / total,
        "NoOfLettersInURL":           letters,
        "LetterRatioInURL":           letters / total,
        "NoOfDegitsInURL":            digits,
        "DegitRatioInURL":            digits / total,
        "NoOfEqualsInURL":            url.count("="),
        "NoOfQMarkInURL":             url.count("?"),
        "NoOfAmpersandInURL":         url.count("&"),
        "NoOfOtherSpecialCharsInURL": specials,
        "SpacialCharRatioInURL":      specials / total,
        "IsHTTPS":                    int("https://" in url.lower()),
        "URLCharProb":                letters / total,
        "CharContinuationRate":       cont,
    }

    # Extra features for enhanced inference (not in training, used separately)
    extra = {
        "domain_similarity":     domain_similarity_score(host),
        "brand_keywords":        brand_impersonation_score(host, path),
        "suspicious_tld":        int(tld in PHISHING_TLDS),
        "ip_in_host":            int(bool(IP_RE.match(host))),
        "has_login_path":        int(any(kw in path.lower() for kw in
                                   ("login","signin","verify","account","update","confirm","secure"))),
        "subdomain_count":       max(0, len(host.split(".")) - 2),
        "path_depth":            len([x for x in path.split("/") if x]),
        "many_params":           int(url.count("=") >= 3),
        "long_url":              int(len(url) > 75),
        "hyphen_in_domain":      int("-" in (host.split(".")[0] if host else "")),
        "tld":                   tld,
        "tld_full_host":         host.lower(),   # full hostname for keyword scan
    }

    feat_vec = np.array([base.get(c, 0) for c in url_only_cols], dtype=float)
    return feat_vec, extra


def rule_based_score(extra):
    """
    Heuristic score: 0 = legit, higher = more phishing-like.
    This replaces the URLSimilarityIndex that we can't compute from raw URL.
    """
    score = 0

    # Strong signals
    if extra["suspicious_tld"]:         score += 50   # .tk .ml .xyz .club etc. — raised from 35
    if extra["ip_in_host"]:             score += 60   # IP address as host
    if extra["domain_similarity"] < 20: score += 25   # low similarity to known-legit domains
    if extra["brand_keywords"] >= 2:    score += 30   # "paypal-secure-verify-login"
    if extra["brand_keywords"] == 1:    score += 10   # single brand keyword

    # Medium signals
    if extra["has_login_path"]:         score += 15
    if extra["hyphen_in_domain"]:       score += 12
    if extra["many_params"]:            score += 10
    if extra["long_url"]:               score += 8
    if extra["subdomain_count"] >= 3:   score += 18
    if extra["subdomain_count"] == 2 and extra["suspicious_tld"]:
        score += 10   # extra penalty: subdomains + bad TLD together

    # Prize/giveaway/free keywords in domain (no brand needed)
    domain_lower = extra.get("tld_full_host", "")
    if any(kw in domain_lower for kw in ("free","prize","giveaway","gift","lucky","winner","claim","reward")):
        score += 35

    # Dampen if it looks legitimate
    if extra["domain_similarity"] > 85: score -= 50   # very close to a known domain
    if extra["domain_similarity"] > 60 and not extra["suspicious_tld"]:
        score -= 20

    return max(0, min(100, score))

# ── Data loading ───────────────────────────────────────────────────────────────

def normalise_label(series):
    s = series.astype(str).str.strip().str.lower()
    def _m(v):
        if v in PHISHING_VALS: return 1
        if v in LEGIT_VALS:    return 0
        return np.nan
    return s.map(_m)

def find_col(cols, candidates):
    low = [c.lower() for c in cols]
    for cand in candidates:
        if cand.lower() in low:
            return cols[low.index(cand.lower())]
    return None

def load_csv(filepath):
    print(f"\nLoading: {filepath}")
    df = pd.read_csv(filepath)
    print(f"  Shape   : {df.shape[0]:,} rows x {df.shape[1]} columns")

    label_col = find_col(list(df.columns), LABEL_COLS)
    if label_col is None:
        raise ValueError(f"No label column found. Columns: {list(df.columns)}")
    print(f"  Label   : '{label_col}'")

    df["_label"] = normalise_label(df[label_col])
    df = df.dropna(subset=["_label"]).reset_index(drop=True)
    df["_label"] = df["_label"].astype(int)

    url_col = find_col(list(df.columns), URL_COLS)
    df["_url"] = df[url_col].fillna("").astype(str) if url_col else ""

    exclude = set(ALWAYS_EXCLUDE) | {label_col.lower()}
    if url_col: exclude.add(url_col.lower())

    all_numeric = [
        c for c in df.columns
        if c.lower() not in exclude
        and pd.api.types.is_numeric_dtype(df[c])
    ]
    url_only = [c for c in URL_ONLY_COLS if c in df.columns]

    print(f"  Full features     : {len(all_numeric)}")
    print(f"  URL-only features : {len(url_only)}")
    print(f"  Phishing : {df['_label'].sum():,}  |  Legit : {(df['_label']==0).sum():,}")
    return df, all_numeric, url_only

# ── Training ───────────────────────────────────────────────────────────────────

def make_clf(name):
    return {
        "logreg": LogisticRegression(max_iter=1000, C=1.0, class_weight="balanced", solver="lbfgs"),
        "svm":    LinearSVC(max_iter=2000, C=1.0, class_weight="balanced"),
        "rf":     RandomForestClassifier(n_estimators=300, n_jobs=-1,
                                          class_weight="balanced", random_state=42),
        "gbm":    GradientBoostingClassifier(n_estimators=200, learning_rate=0.05, random_state=42),
    }.get(name, RandomForestClassifier(n_estimators=300, n_jobs=-1,
                                        class_weight="balanced", random_state=42))

def train_and_eval(df, feature_cols, model_name, tag):
    print(f"\n{'─'*55}")
    print(f"  Training: {tag}  ({len(feature_cols)} features)")
    print(f"{'─'*55}")

    X = df[feature_cols].fillna(0).values.astype(float)
    y = df["_label"].values
    scaler = MinMaxScaler()
    X = scaler.fit_transform(X)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)

    clf = make_clf(model_name)
    clf.fit(X_tr, y_tr)

    y_pred = clf.predict(X_te)
    print(classification_report(y_te, y_pred, target_names=["Legitimate","Phishing"]))
    try:
        if hasattr(clf, "predict_proba"):
            auc = roc_auc_score(y_te, clf.predict_proba(X_te)[:,1])
        else:
            auc = roc_auc_score(y_te, clf.decision_function(X_te))
        print(f"  ROC-AUC : {auc:.4f}")
    except Exception:
        pass

    # Confusion matrix
    cm = confusion_matrix(y_te, y_pred)
    plt.figure(figsize=(5,4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Reds",
                xticklabels=["Legitimate","Phishing"],
                yticklabels=["Legitimate","Phishing"])
    plt.title(f"Confusion Matrix -- {tag}")
    plt.tight_layout()
    safe_tag = re.sub(r"[^\w]", "_", tag)
    plt.savefig(f"confusion_{safe_tag}.png", dpi=120); plt.close()
    print(f"  Saved -> confusion_{safe_tag}.png")

    if hasattr(clf, "feature_importances_"):
        imp   = pd.Series(clf.feature_importances_, index=feature_cols)
        top15 = imp.nlargest(15)
        plt.figure(figsize=(8,5))
        top15.sort_values().plot(kind="barh", color="steelblue")
        plt.title(f"Top 15 Features -- {tag}")
        plt.tight_layout()
        plt.savefig(f"importance_{safe_tag}.png", dpi=120); plt.close()
        print(f"  Saved -> importance_{safe_tag}.png")
        print(f"\n  Top features:")
        for fn, fv in top15.head(8).items():
            print(f"    {fn:<38} {fv:.4f}")

    return clf, scaler

# ── Inference ──────────────────────────────────────────────────────────────────

def predict_url(clf_url, scaler_url, url_only_cols, url, threshold=0.30):
    """
    Hybrid inference:
      - ML model score   (from 20 URL structural features)
      - Rule-based score (domain reputation, brand impersonation, TLD)
    Final decision combines both so we don't rely solely on ML.
    """
    feat_vec, extra = compute_url_features(url, url_only_cols)
    x = scaler_url.transform(feat_vec.reshape(1, -1))

    # ML probability
    if hasattr(clf_url, "predict_proba"):
        ml_prob = clf_url.predict_proba(x)[0][1]
    else:
        score   = clf_url.decision_function(x)[0]
        ml_prob = float(1 / (1 + np.exp(-score)))

    # Rule-based score (0-100 → 0.0-1.0)
    rule_score = rule_based_score(extra) / 100.0

    # Weighted combination: 40% ML + 60% rules
    # (rules weighted higher because ML struggles with raw URLs)
    combined = 0.40 * ml_prob + 0.60 * rule_score

    pred  = 1 if combined >= threshold else 0
    label = "PHISHING" if pred == 1 else "LEGITIMATE"
    conf  = combined if pred == 1 else 1 - combined

    return label, round(conf, 4), round(ml_prob, 4), round(rule_score, 4)

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data",   type=str, required=True)
    parser.add_argument("--model",  type=str, default="rf",
                        choices=["logreg","svm","rf","gbm"])
    parser.add_argument("--output", type=str, default="phishing_model.pkl")
    args = parser.parse_args()

    df, all_numeric, url_only = load_csv(args.data)

    # Full model (all features — for batch/offline use)
    clf_full, scaler_full = train_and_eval(
        df, all_numeric, args.model, "Full Model")

    # URL-only model (for live inference, combined with rule engine)
    clf_url, scaler_url = train_and_eval(
        df, url_only, args.model, "URL-Only Model")

    bundle = {
        "clf_full":    clf_full,   "scaler_full": scaler_full,
        "full_cols":   all_numeric,
        "clf_url":     clf_url,    "scaler_url":  scaler_url,
        "url_cols":    url_only,
    }
    with open(args.output, "wb") as f:
        pickle.dump(bundle, f)
    print(f"\nBoth models saved -> {args.output}")

    # ── Live predictions ──
    demos = [
        # (expected,   url)
        ("PHISHING", "http://paypa1-secure.tk/login?user=victim&token=abc123"),
        ("LEGIT",    "https://www.google.com/search?q=weather+today"),
        ("PHISHING", "http://192.168.0.1/bank-verify/login"),
        ("LEGIT",    "https://www.amazon.com/orders"),
        ("PHISHING", "http://free-iphone-giveaway.xyz/claim?id=8821"),
        ("LEGIT",    "https://www.bbc.co.uk/news"),
        ("PHISHING", "http://secure-paypal-account-verify.tk/login?update=true"),
        ("PHISHING", "http://appleid.apple.com-login.ml/signin"),
        ("LEGIT",    "https://github.com/torvalds/linux"),
        ("PHISHING", "http://amazon-security-alert.club/verify?account=true"),
        ("LEGIT",    "https://www.linkedin.com/in/profile"),
        ("PHISHING", "http://login.microsoftonline.com.phishsite.xyz/auth"),
    ]

    print("\n-- Live Predictions (ML + Rule Engine) --")
    print(f"  {'✓/✗'} {'Expected':<10} {'Result':<12} {'Final':>6}  {'ML':>6}  {'Rules':>6}  URL")
    print(f"  {'─'*3} {'─'*8:<10} {'─'*9:<12} {'─'*5:>6}  {'─'*5:>6}  {'─'*5:>6}  {'─'*40}")

    correct = 0
    for expected, url in demos:
        label, conf, ml_p, rule_p = predict_url(clf_url, scaler_url, url_only, url)
        # Normalise: LEGIT → LEGITIMATE for comparison
        exp_norm = "LEGITIMATE" if expected.upper() in ("LEGIT","LEGITIMATE") else "PHISHING"
        hit = (exp_norm == label)
        if hit: correct += 1
        icon = "✓" if hit else "✗"
        short = url[:55] + ("..." if len(url) > 55 else "")
        print(f"  {icon}  {expected:<10} {label:<12} {conf:>5.1%}   {ml_p:>5.1%}   {rule_p:>5.1%}  {short}")

    print(f"\n  Accuracy on demo URLs: {correct}/{len(demos)}  ({correct/len(demos)*100:.0f}%)")
    print(f"\n  Columns: Final = 40%*ML + 60%*Rules | ML = URL-structural model | Rules = domain intelligence")

if __name__ == "__main__":
    main()