import argparse
import joblib
import pandas as pd
from features import extract_url_features, extract_domain_age_days
from content_features import fetch_content_features

MODEL_PATH = "data/model.joblib"


def classify(url: str, deep: bool = False) -> dict:
    bundle = joblib.load(MODEL_PATH)
    clf, feature_cols = bundle["model"], bundle["feature_cols"]

    #same feature function used during training, has to match exactly
    #or the model gets columns it was never trained to read
    feats = extract_url_features(url)
    #domain age is a model feature, so it has to be computed here too. without it the
    #row.get(col, 0) below would silently feed 0 days old, which looks like a brand new domain
    feats["domain_age_days"] = extract_domain_age_days(url)
    if deep:
        feats.update(fetch_content_features(url))

    row = {col: feats.get(col, 0) for col in feature_cols}
    X = pd.DataFrame([row])[feature_cols]

    proba = clf.predict_proba(X)[0]
    verdict = "PHISHING" if proba[1] >= 0.5 else "LEGITIMATE"

    #note this is global feature importance, same list for every url
    #not a real per-prediction explanation, that's coming with shap later
    importances = sorted(zip(feature_cols, clf.feature_importances_), key=lambda x: -x[1])
    top_features = [(name, row[name]) for name, _ in importances[:5]]

    return {
        "url": url,
        "verdict": verdict,
        "confidence": round(float(max(proba)), 3),
        "phishing_probability": round(float(proba[1]), 3),
        "top_features": top_features,
    }


def main():
    parser = argparse.ArgumentParser(description="Classify a URL as phishing or legitimate.")
    parser.add_argument("url", help="URL to classify")
    parser.add_argument("--deep", action="store_true", help="also fetch page content (slower)")
    args = parser.parse_args()

    result = classify(args.url, deep=args.deep)

    print(f"URL:        {result['url']}")
    print(f"Verdict:    {result['verdict']}")
    print(f"Confidence: {result['confidence']}")
    print(f"P(phishing): {result['phishing_probability']}")
    print("Top contributing features:")
    for name, value in result["top_features"]:
        print(f"  {name:25s} = {value}")


if __name__ == "__main__":
    main()
