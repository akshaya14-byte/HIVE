"""
DDoS Detector — CICIDS2017 Real Dataset Training
=================================================
Trains a Random Forest on the real CICIDS2017 dataset
and saves the model to ddos_model.pkl.

Usage:
  python model.py --data Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
"""

import pickle
import argparse
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings("ignore")

# ── Features we use from the dataset ──────────────────────────────────────────

FEATURE_COLS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Average Packet Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "Active Mean",
    "Idle Mean",
]

# ── Load & clean ───────────────────────────────────────────────────────────────

def load_data(path: str):
    print(f"Loading {path} ...")
    df = pd.read_csv(path, low_memory=False)

    # Strip whitespace from column names
    df.columns = [c.strip() for c in df.columns]

    print(f"  Rows   : {len(df):,}")
    print(f"  Labels : {df['Label'].value_counts().to_dict()}")

    available = [c for c in FEATURE_COLS if c in df.columns]
    print(f"  Features found: {len(available)} / {len(FEATURE_COLS)}")

    df = df[available + ["Label"]].copy()

    # Replace inf and drop NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    df["Label"] = df["Label"].str.strip()

    # Undersample BENIGN to balance classes (CICIDS2017 is heavily skewed)
    benign  = df[df["Label"] == "BENIGN"]
    attacks = df[df["Label"] != "BENIGN"]
    if len(benign) > len(attacks):
        benign = benign.sample(n=len(attacks), random_state=42)
        df = pd.concat([benign, attacks]).sample(frac=1, random_state=42).reset_index(drop=True)
        print(f"  Balanced: {len(benign)} BENIGN + {len(attacks)} attack rows")

    print(f"  Rows after cleaning: {len(df):,}")
    return df, available

# ── Train ──────────────────────────────────────────────────────────────────────

def train(path: str):
    df, feature_cols = load_data(path)

    print(f"\nUnique labels: {df['Label'].unique()}")

    X = df[feature_cols].values.astype(float)
    y = df["Label"].values

    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    print(f"Classes: {list(le.classes_)}")

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X_scaled, y_enc, test_size=0.2, stratify=y_enc, random_state=42)

    print(f"\nTraining on {len(X_tr):,} samples...")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_tr, y_tr)

    y_pred = clf.predict(X_te)
    print("\n" + classification_report(y_te, y_pred, target_names=le.classes_))

    # Confusion matrix
    cm = confusion_matrix(y_te, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=le.classes_, yticklabels=le.classes_)
    plt.title("Confusion Matrix — DDoS Detector (CICIDS2017)")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("confusion_ddos.png", dpi=120)
    plt.close()
    print("Saved -> confusion_ddos.png")

    # Feature importance
    imp = pd.Series(clf.feature_importances_, index=feature_cols)
    top = imp.nlargest(15)
    plt.figure(figsize=(8, 5))
    top.sort_values().plot(kind="barh", color="steelblue")
    plt.title("Top 15 Features — DDoS Detector")
    plt.tight_layout()
    plt.savefig("importance_ddos.png", dpi=120)
    plt.close()
    print("Saved -> importance_ddos.png")
    print("\nTop features:")
    for name, val in top.items():
        print(f"  {name:<35} {val:.4f}")

    # Save model
    bundle = {
        "clf":          clf,
        "scaler":       scaler,
        "le":           le,
        "feature_cols": feature_cols,
    }
    with open("ddos_model.pkl", "wb") as f:
        pickle.dump(bundle, f)
    print("\nModel saved -> ddos_model.pkl")

    # Sample predictions
    print("\n-- Sample Predictions --")
    for actual, predicted in zip(
        le.inverse_transform(y_te[:5]),
        le.inverse_transform(clf.predict(X_te[:5]))
    ):
        icon = "✓" if actual == predicted else "✗"
        print(f"  {icon}  Actual: {actual:<20} Predicted: {predicted}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=str, required=True,
                        help="Path to CICIDS2017 CSV file")
    args = parser.parse_args()
    train(args.data)