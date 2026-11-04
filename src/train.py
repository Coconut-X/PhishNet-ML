import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

DATA_PATH = "data/dataset.csv"
MODEL_PATH = "data/model.joblib"


def main():
    df = pd.read_csv(DATA_PATH)
    feature_cols = [c for c in df.columns if c not in ("url", "label")]
    X = df[feature_cols]
    y = df["label"]

    #stratify keeps the 50/50 phishing/legit split the same in both train and test
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
    joblib.dump({"model": clf, "feature_cols": feature_cols}, MODEL_PATH)
    print(f"\nSaved model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
