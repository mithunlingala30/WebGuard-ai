"""
Train the OPTIONAL supervised severity model with scikit-learn.

Usage (from the project root):
    python -m ai_engine.train_model path/to/labeled_findings.csv

CSV columns (header required):
    type,status,confidence_hint,exploitability,severity
    e.g.  missing_csp,observed,0.9,0.4,Medium

No labeled dataset ships with this project, so the model is NOT active by default and the app
reports its classification method as 'rule-based'. Once you train a model it is saved to
ai_engine/models/severity_model.joblib and automatically used as an advisory second opinion.
"""
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier

OUT = Path(__file__).parent / "models" / "severity_model.joblib"


def train(csv_path):
    df = pd.read_csv(csv_path)
    need = {"type", "status", "confidence_hint", "exploitability", "severity"}
    if not need.issubset(df.columns):
        raise SystemExit(f"CSV must contain columns: {sorted(need)}")
    X, y = df[["type", "status", "confidence_hint", "exploitability"]], df["severity"]
    pre = ColumnTransformer([("cat", OneHotEncoder(handle_unknown="ignore"), ["type", "status"])],
                            remainder="passthrough")
    model = Pipeline([("pre", pre), ("clf", DecisionTreeClassifier(max_depth=6, random_state=42))])
    if len(df) >= 20:
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=None)
        model.fit(Xtr, ytr)
        print(classification_report(yte, model.predict(Xte), zero_division=0))
    model.fit(X, y)
    OUT.parent.mkdir(exist_ok=True)
    joblib.dump(model, OUT)
    print(f"Saved model to {OUT}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    train(sys.argv[1])
