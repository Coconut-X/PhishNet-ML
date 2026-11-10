import argparse
import joblib
import numpy as np
import pandas as pd
from features import extract_url_features, extract_domain_age_days
from content_features import fetch_content_features, SandboxError

MODEL_PATH = "data/model.joblib"
DEEP_MODEL_PATH = "data/model_deep.joblib"


def classify(url: str, deep: bool = False) -> dict:
    used = "fast"
    #same feature function used during training, has to match exactly
    #or the model gets columns it was never trained to read
    feats = extract_url_features(url)
    path = MODEL_PATH
    if deep:
        #use_cache=False so classifying a url doesnt add it to the dataset cache
        content = None
        try:
            content = fetch_content_features(url, use_cache=False)
        except SandboxError as e:
            used = "fast (sandbox unavailable: " + str(e).replace("\n", " ")[-80:] + ")"
        #if the page didnt load the content values are meaningless zeros, so the deep
        #model would be fed fake data. fall back to the fast model instead
        if content and content["fetch_ok"]:
            feats.update(content)
            path, used = DEEP_MODEL_PATH, "deep"
        elif content:
            used = "fast (page could not be loaded)"
    bundle = joblib.load(path)
    clf, feature_cols = bundle["model"], bundle["feature_cols"]

    #the current models dont use domain age (see docs/iteration-04), but a model trained
    #with it needs it here too, otherwise the 0 below would mean "registered today"
    if "domain_age_days" in feature_cols:
        feats["domain_age_days"] = extract_domain_age_days(url)

    row = {col: feats.get(col, 0) for col in feature_cols}
    X = pd.DataFrame([row])[feature_cols]

    proba = clf.predict_proba(X)[0]
    verdict = "PHISHING" if proba[1] >= 0.5 else "LEGITIMATE"

    #shap values for this one url: how many probability points each feature pushed the
    #phishing probability up (+) or down (-) from the baseline. baseline + all the pushes
    #adds up exactly to the probability above
    import shap
    explainer = shap.TreeExplainer(clf)
    push = explainer.shap_values(X)[0, :, 1]
    baseline = float(explainer.expected_value[1])
    order = np.argsort(-np.abs(push))
    top = order[:5]
    explanation = [{"feature": feature_cols[i], "value": row[feature_cols[i]],
                    "shap": round(float(push[i]), 3)} for i in top]
    other = round(float(push[order[5:]].sum()), 3)

    return {
        "url": url,
        "model": used,
        "verdict": verdict,
        "confidence": round(float(max(proba)), 3),
        "phishing_probability": round(float(proba[1]), 3),
        "baseline": round(baseline, 3),
        "explanation": explanation,
        "other_features": other,
    }


def main():
    parser = argparse.ArgumentParser(description="Classify a URL as phishing or legitimate.")
    parser.add_argument("url", help="URL to classify")
    parser.add_argument("--deep", action="store_true", help="also fetch page content (slower)")
    args = parser.parse_args()

    result = classify(args.url, deep=args.deep)

    print(f"URL:        {result['url']}")
    print(f"Model:      {result['model']}")
    print(f"Verdict:    {result['verdict']}")
    print(f"Confidence: {result['confidence']}")
    print(f"P(phishing): {result['phishing_probability']}")
    print(f"Why (SHAP, probability points, + pushes towards phishing, starting from "
          f"{result['baseline']}):")
    for e in result["explanation"]:
        print(f"  {e['shap']:+.3f}  {e['feature']} = {e['value']}")
    print(f"  {result['other_features']:+.3f}  all other features")


if __name__ == "__main__":
    main()
