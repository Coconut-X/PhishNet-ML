import os
import sys
import joblib
import numpy as np
import pandas as pd
import shap
import matplotlib
matplotlib.use("Agg")  #no window needed, we just save the pngs
import matplotlib.pyplot as plt
from sklearn.metrics import (accuracy_score, confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score, roc_curve, ConfusionMatrixDisplay)
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict, train_test_split
from features import registered_domain
from classify import classify

DATA = "data/dataset.csv"
MODEL = "data/model.joblib"
OUT = "reports"
CASES = "demo/cases.txt"


def metrics_and_plots(df, clf, cols):
    #same split as train.py (75/25, stratified, seed 42)
    X, y = df[cols], df.label
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    prob = clf.predict_proba(Xte)[:, 1]
    pred = (prob >= 0.5).astype(int)
    p, r, f, _ = precision_recall_fscore_support(yte, pred, average="binary")
    cm = confusion_matrix(yte, pred)

    print("== Held-out test set (%d urls) ==" % len(yte))
    print(f"accuracy {accuracy_score(yte, pred):.3f}  precision {p:.3f}  recall {r:.3f}  "
          f"F1 {f:.3f}  ROC-AUC {roc_auc_score(yte, prob):.3f}")
    print(f"confusion matrix: legit right {cm[0,0]}, legit flagged {cm[0,1]} (false positive), "
          f"phishing missed {cm[1,0]} (false negative), phishing caught {cm[1,1]}")
    wrong = df.loc[Xte.index[pred != yte], "url"]
    for u in wrong:
        print("  wrong:", u[:90])

    #grouped cv, a domain never sits in both train and test, this is the number to trust
    groups = df.url.map(registered_domain)
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    oof = cross_val_predict(clf, X, y, cv=cv, groups=groups, method="predict_proba")[:, 1]
    oof_pred = (oof >= 0.5).astype(int)
    p2, r2, f2, _ = precision_recall_fscore_support(y, oof_pred, average="binary")
    print("\n== Grouped 5-fold CV, all 600 urls (a domain is never in train and test) ==")
    print(f"precision {p2:.3f}  recall {r2:.3f}  F1 {f2:.3f}  ROC-AUC {roc_auc_score(y, oof):.3f}")

    fig, ax = plt.subplots(1, 3, figsize=(16, 4.5))
    ConfusionMatrixDisplay(cm, display_labels=["legit", "phishing"]).plot(ax=ax[0], colorbar=False)
    ax[0].set_title("Confusion matrix (held-out test)")
    for name, yy, pp in [("held-out test", yte, prob), ("grouped CV", y, oof)]:
        fpr, tpr, _ = roc_curve(yy, pp)
        ax[1].plot(fpr, tpr, label=f"{name} (AUC {roc_auc_score(yy, pp):.3f})")
    ax[1].plot([0, 1], [0, 1], "k--", lw=0.8)
    ax[1].set_xlabel("false positive rate"); ax[1].set_ylabel("true positive rate")
    ax[1].set_title("ROC curve"); ax[1].legend(loc="lower right")

    #global shap: which features the model leans on across the test set
    sv = shap.TreeExplainer(clf).shap_values(Xte)[:, :, 1]
    imp = np.abs(sv).mean(axis=0)
    order = np.argsort(imp)
    ax[2].barh([cols[i] for i in order], imp[order])
    ax[2].set_title("Feature importance (mean |SHAP|, probability)")
    plt.tight_layout()
    plt.savefig(f"{OUT}/metrics.png", dpi=130)
    plt.close()
    print(f"\nsaved {OUT}/metrics.png")


def explain_urls(urls):
    print("\n== Why the model decided (SHAP, + pushes towards phishing) ==")
    results = [classify(u) for u in urls]
    for r in results:
        print(f"\n{r['verdict']:10s} P(phishing)={r['phishing_probability']:.2f}  {r['url']}")
        for e in r["explanation"]:
            n = int(round(abs(e["shap"]) * 60))
            bar = ("+" if e["shap"] >= 0 else "-") * max(n, 1)
            print(f"  {e['shap']:+.3f} {e['feature']:22s} = {round(e['value'], 2)!s:6s} {bar}")

    fig, axes = plt.subplots(len(results), 1, figsize=(9, 2.6 * len(results)))
    axes = np.atleast_1d(axes)
    for ax, r in zip(axes, results):
        feats = r["explanation"][::-1]
        vals = [e["shap"] for e in feats]
        ax.barh([f"{e['feature']} = {round(e['value'], 2)}" for e in feats], vals,
                color=["#c0392b" if v > 0 else "#2e86c1" for v in vals])
        ax.axvline(0, color="k", lw=0.8)
        ax.set_title(f"{r['verdict']} ({r['phishing_probability']:.2f}): {r['url'][:70]}", fontsize=9)
    plt.tight_layout()
    plt.savefig(f"{OUT}/explanations.png", dpi=130)
    plt.close()
    print(f"\nsaved {OUT}/explanations.png (red pushes towards phishing, blue towards legit)")


def main():
    os.makedirs(OUT, exist_ok=True)
    bundle = joblib.load(MODEL)
    df = pd.read_csv(DATA)
    metrics_and_plots(df, bundle["model"], bundle["feature_cols"])

    urls = sys.argv[1:]
    if not urls:
        urls = [l.strip() for l in open(CASES) if l.strip() and not l.startswith("#")]
    explain_urls(urls)


if __name__ == "__main__":
    main()
