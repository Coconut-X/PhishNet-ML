import csv
import random
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from features import extract_url_features, registered_domain

DATA_DIR = "data"
FRESH_PHISH = f"{DATA_DIR}/openphish_fresh.txt"
N_LEGIT = 300


def read_lines(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def fresh_phishing(train_urls):
    #only urls the model never saw
    urls = [u for u in read_lines(FRESH_PHISH) if u not in train_urls]
    return urls


def fresh_legit(train_domains, n=N_LEGIT):
    #the training sample came from the top ~1500, so look further down the list
    #(rank 2000 to 20000) and skip any domain already used
    pool = []
    with open(f"{DATA_DIR}/top-1m.csv") as f:
        for rank, domain in csv.reader(f):
            if 2000 <= int(rank) <= 20000 and domain not in train_domains:
                pool.append(domain)
            if int(rank) > 20000:
                break
    random.seed(7)
    return [f"https://{d}" for d in random.sample(pool, n)]


def stress_test(clf, cols, legit):
    #fresh legit are bare homepages, which is the easy case (see iteration 0).
    #these paths are made up and may not exist, we only score the url strings
    print("\nstress test: same legit domains with a login-like path added")
    for suffix in ["/login", "/signin", "/account/login?next=/home", "/users/sign_in", "/wp-login.php"]:
        X = pd.DataFrame([{c: extract_url_features(u + suffix).get(c, 0) for c in cols} for u in legit])
        flagged = (clf.predict_proba(X)[:, 1] >= 0.5).mean()
        print(f"  {suffix:28s} flagged as phishing: {flagged:.0%}")


def main():
    bundle = joblib.load(f"{DATA_DIR}/model.joblib")
    clf, cols = bundle["model"], bundle["feature_cols"]

    train = pd.read_csv(f"{DATA_DIR}/dataset.csv")
    train_urls = set(train.url)
    train_domains = {registered_domain(u) for u in train.url}

    phish = fresh_phishing(train_urls)
    legit = fresh_legit(train_domains)
    print(f"fresh phishing: {len(phish)} urls, legit: {len(legit)} urls")

    rows = []
    for url, label in [(u, 1) for u in phish] + [(u, 0) for u in legit]:
        feats = extract_url_features(url)
        row = {c: feats.get(c, 0) for c in cols}
        row["url"], row["label"] = url, label
        row["seen_domain"] = registered_domain(url) in train_domains
        rows.append(row)
    df = pd.DataFrame(rows)

    df["prob"] = clf.predict_proba(df[cols])[:, 1]
    df["pred"] = (df.prob >= 0.5).astype(int)

    def show(name, d):
        print(f"\n=== {name} ({len(d)} rows, {(d.label==1).sum()} phishing) ===")
        print(classification_report(d.label, d.pred, target_names=["legit", "phishing"], zero_division=0))
        print("confusion matrix:\n", confusion_matrix(d.label, d.pred, labels=[0, 1]))
        if d.label.nunique() == 2:
            print(f"ROC-AUC: {roc_auc_score(d.label, d.prob):.3f}")

    show("all fresh urls", df)
    #phishing on domains the model already saw is easier, so split it out
    unseen = df[~((df.label == 1) & df.seen_domain)]
    show("fresh phishing on unseen domains + fresh legit", unseen)

    print("\nphishing missed (first 15):")
    for _, r in df[(df.label == 1) & (df.pred == 0)].head(15).iterrows():
        print(f"  {r.prob:.2f}  {r.url[:100]}")
    print("\nlegit flagged (first 15):")
    for _, r in df[(df.label == 0) & (df.pred == 1)].head(15).iterrows():
        print(f"  {r.prob:.2f}  {r.url[:100]}")
    stress_test(clf, cols, legit)
    print(f"\nphishing on seen domains: {((df.label==1)&df.seen_domain).sum()} of {(df.label==1).sum()}")


if __name__ == "__main__":
    main()
