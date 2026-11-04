import csv
import random
import pandas as pd
from features import extract_url_features
from curated_legit_urls import LOGIN_URLS

DATA_DIR = "data"
N_SAMPLES_PER_CLASS = 300


def load_phishing_urls(path=f"{DATA_DIR}/openphish.txt"):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def load_legit_urls(path=f"{DATA_DIR}/top-1m.csv", n=N_SAMPLES_PER_CLASS):
    #start with the curated real login pages, these have actual paths
    #so the legit class isnt just bare homepages like before
    legit = list(LOGIN_URLS)

    #fill the rest with tranco homepages
    remaining = n - len(legit)
    domains = []
    with open(path) as f:
        reader = csv.reader(f)
        for rank, domain in reader:
            domains.append(domain)
            if len(domains) >= remaining * 5:
                break

    random.seed(42)
    sample = random.sample(domains, remaining)
    legit += [f"https://{d}" for d in sample]

    return legit


def main():
    phishing = load_phishing_urls()
    legit = load_legit_urls(n=min(N_SAMPLES_PER_CLASS, len(phishing)))

    rows = []
    for url in phishing:
        feats = extract_url_features(url)
        feats["url"] = url
        feats["label"] = 1
        rows.append(feats)

    for url in legit:
        feats = extract_url_features(url)
        feats["url"] = url
        feats["label"] = 0
        rows.append(feats)

    df = pd.DataFrame(rows)
    df.to_csv(f"{DATA_DIR}/dataset.csv", index=False)
    print(f"built dataset: {len(df)} rows ({(df.label==1).sum()} phishing, {(df.label==0).sum()} legit)")
    print(f"{len(LOGIN_URLS)} of the legit rows are real login pages, rest are tranco homepages")
    print(f"saved to {DATA_DIR}/dataset.csv")


if __name__ == "__main__":
    main()
