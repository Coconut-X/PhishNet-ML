import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import (RepeatedStratifiedKFold, StratifiedGroupKFold,
                                     cross_val_score)
from features import registered_domain

DATA_PATH = "data/dataset.csv"
FEATURE = "domain_age_days"


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
    all_cols = [c for c in df.columns if c not in ("url", "label")]
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


if __name__ == "__main__":
    main()
