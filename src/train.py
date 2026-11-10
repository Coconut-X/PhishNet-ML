import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (StratifiedGroupKFold, cross_val_score,
                                     train_test_split)
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from features import registered_domain

DATA_PATH = "data/dataset.csv"
MODEL_PATH = "data/model.joblib"
DEEP_MODEL_PATH = "data/model_deep.joblib"

#these only mean something when the page actually loaded (fetch_ok == 1), otherwise
#they are all 0. fetch_ok itself is never a feature: most dead pages are phishing
#takedowns, so the model would just learn "page is dead = phishing"
CONTENT_COLS = ["form_action_mismatch", "favicon_brand_match", "external_resource_ratio",
                "has_password_field"]

#still built into dataset.csv but not used by either model. grouped cv showed no gain from
#it and its biggest effect came from the "unknown" value (-1), see docs/iteration-04
DROPPED_COLS = ["domain_age_days"]


def train(df, feature_cols, model_path):
    X = df[feature_cols]
    y = df["label"]

    #stratify keeps the phishing/legit ratio the same in both train and test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    #random forest over a single tree because one tree on 600 rows overfits badly
    #max_depth=10 caps how deep each tree can go so it cant just memorize the training rows
    clf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)

    #5 fold cv on top of the train/test split, gives a more stable score than
    #relying on just one random split
    cv_scores = cross_val_score(clf, X, y, cv=5, scoring="f1")
    print(f"5-fold CV F1: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")

    #same thing but a registered domain never sits in both train and test. a lot of rows
    #share a domain (pages.dev, blogspot.com ...) so the normal cv is too optimistic, this
    #is the number to trust more
    groups = df["url"].map(registered_domain)
    gcv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    g_scores = cross_val_score(clf, X, y, cv=gcv, groups=groups, scoring="f1")
    print(f"5-fold CV F1, grouped by domain: {g_scores.mean():.3f} (+/- {g_scores.std():.3f})")

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    print("\nClassification report (held-out test set):")
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.3f}")

    #shap: for every row, how many probability points each feature added or removed.
    #this ranks features by the average size of that push (mean of the absolute value, so
    #a feature that pushes up in some rows and down in others still counts), over all the
    #rows of this model. "high -> phishing" is the sign of the correlation between the
    #feature's value and its push. classify.py uses the same numbers for a single url
    sv = shap.TreeExplainer(clf).shap_values(X)[..., 1]
    mean_abs = np.abs(sv).mean(axis=0)
    print("\nFeature importance (mean |SHAP|, in probability points):")
    for i in np.argsort(-mean_abs):
        if X.iloc[:, i].nunique() > 1 and sv[:, i].std() > 0:
            corr = np.corrcoef(X.iloc[:, i], sv[:, i])[0, 1]
            direction = "high -> phishing" if corr > 0 else "high -> legit"
        else:
            direction = "-"
        print(f"  {feature_cols[i]:25s} {mean_abs[i]:.3f}   {direction}")

    #saving feature_cols along with the model so classify.py builds the input
    #row in the exact same column order the model was trained on
    joblib.dump({"model": clf, "feature_cols": feature_cols}, model_path)
    print(f"\nSaved model to {model_path}")


def main():
    df = pd.read_csv(DATA_PATH)
    skip = ["url", "label", "fetch_ok"] + CONTENT_COLS + DROPPED_COLS
    url_cols = [c for c in df.columns if c not in skip]

    #fast model: url features, every row, no page needs to be fetched
    print(f"=== fast model: {len(url_cols)} url features, {len(df)} rows ===\n")
    train(df, url_cols, MODEL_PATH)

    #deep model: adds the page content features, but only the rows whose page loaded
    loaded = df[df.fetch_ok == 1]
    counts = loaded.label.value_counts()
    print(f"\n\n=== deep model: {len(url_cols) + len(CONTENT_COLS)} features, "
          f"{len(loaded)} rows ({counts.get(1, 0)} phishing, {counts.get(0, 0)} legit) ===\n")
    train(loaded, url_cols + CONTENT_COLS, DEEP_MODEL_PATH)


if __name__ == "__main__":
    main()
