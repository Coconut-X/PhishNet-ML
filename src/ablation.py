import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (RepeatedStratifiedKFold, StratifiedGroupKFold,
                                     cross_val_score)
from features import registered_domain

DATA_PATH = "data/dataset.csv"
FEATURE = "domain_age_days"
CONTENT = ["form_action_mismatch", "favicon_brand_match", "external_resource_ratio",
           "has_password_field"]


def forest():
    #same settings as train.py so the numbers are comparable
    return RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)


def plain_cv(X, y):
    #5-fold stratified, repeated 5 times with different shuffles to average out luck.
    #rows from the same domain can land in both train and test here
    cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=5, random_state=42)
    return cross_val_score(forest(), X, y, cv=cv, scoring="f1")


def grouped_cv(X, y, groups):
    #same idea, but every row of one registered domain stays on the same side of the split.
    #this is the honest test for a per-domain feature like age: if the model only memorised
    #"pages.dev has age 2043" it cant cheat, because pages.dev is never in train and test
    scores = []
    for seed in range(5):
        cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed)
        scores.extend(cross_val_score(forest(), X, y, cv=cv, groups=groups, scoring="f1"))
    return np.array(scores)


def report(name, scores):
    print(f"  {name:28s} F1 = {scores.mean():.3f} (+/- {scores.std():.3f})")


def main():
    df = pd.read_csv(DATA_PATH)
    y = df["label"]
    groups = df["url"].map(registered_domain)
    #content columns are only filled in for pages that loaded, so they get their own test
    all_cols = [c for c in df.columns if c not in ["url", "label", "fetch_ok"] + CONTENT]
    without = [c for c in all_cols if c != FEATURE]

    print(f"{len(df)} rows, {groups.nunique()} distinct registered domains "
          f"({groups[y == 1].nunique()} phishing, {groups[y == 0].nunique()} legit)\n")

    print("Plain stratified 5-fold, 5 repeats (same domain may be in train and test):")
    report("without domain_age_days", plain_cv(df[without], y))
    report("with domain_age_days", plain_cv(df[all_cols], y))

    print("\nGrouped by registered domain (a domain is never in both train and test):")
    report("without domain_age_days", grouped_cv(df[without], y, groups))
    report("with domain_age_days", grouped_cv(df[all_cols], y, groups))

    print(f"\nOnly {FEATURE} on its own, grouped:")
    report(FEATURE + " alone", grouped_cv(df[[FEATURE]], y, groups))

    content_experiment(df)


def content_experiment(df):
    #do the page content features help? only the rows whose page actually loaded have
    #real content values, so both models are tested on exactly those rows
    loaded = df[df.fetch_ok == 1]
    y = loaded["label"]
    groups = loaded["url"].map(registered_domain)
    url_cols = [c for c in df.columns if c not in ["url", "label", "fetch_ok"] + CONTENT]

    print(f"\n--- page content features, on the {len(loaded)} rows that loaded "
          f"({(y == 1).sum()} phishing, {(y == 0).sum()} legit, {groups.nunique()} domains) ---")
    print("Plain stratified 5-fold, 5 repeats:")
    report("url features only", plain_cv(loaded[url_cols], y))
    report("url + content features", plain_cv(loaded[url_cols + CONTENT], y))
    print("Grouped by registered domain:")
    report("url features only", grouped_cv(loaded[url_cols], y, groups))
    report("url + content features", grouped_cv(loaded[url_cols + CONTENT], y, groups))
    report("content features alone", grouped_cv(loaded[CONTENT], y, groups))

    print("\nmean of each content feature by class (loaded rows):")
    print(loaded.groupby("label")[CONTENT].mean().round(3).to_string())


if __name__ == "__main__":
    main()
