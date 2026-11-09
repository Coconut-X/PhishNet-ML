import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

DATA_PATH = "data/dataset.csv"
MODEL_PATH = "data/model.joblib"
DEEP_MODEL_PATH = "data/model_deep.joblib"

#these only mean something when the page actually loaded (fetch_ok == 1), otherwise
#they are all 0. fetch_ok itself is never a feature: most dead pages are phishing
#takedowns, so the model would just learn "page is dead = phishing"
CONTENT_COLS = ["form_action_mismatch", "favicon_brand_match", "external_resource_ratio",
                "has_password_field"]


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

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    print("\nClassification report (held-out test set):")
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.3f}")

    #this is global importance, averaged over the whole dataset, not per prediction
    #swapping this for shap values is planned for a later iteration
    importances = sorted(zip(feature_cols, clf.feature_importances_), key=lambda x: -x[1])
    print("\nFeature importances:")
    for name, imp in importances:
        print(f"  {name:25s} {imp:.3f}")

    #saving feature_cols along with the model so classify.py builds the input
    #row in the exact same column order the model was trained on
    joblib.dump({"model": clf, "feature_cols": feature_cols}, model_path)
    print(f"\nSaved model to {model_path}")


def main():
    df = pd.read_csv(DATA_PATH)
    url_cols = [c for c in df.columns if c not in ["url", "label", "fetch_ok"] + CONTENT_COLS]

    #fast model: url + domain age features, every row, no page needs to be fetched
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
