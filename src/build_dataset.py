import csv
import random
import pandas as pd
from features import extract_url_features, extract_domain_age_days, prefetch_domain_ages
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
            #only read 5x what we need instead of the whole million row file, way faster
            if len(domains) >= remaining * 5:
                break

    #fixed seed so re-running this script gives the exact same dataset every time
    random.seed(42)
    sample = random.sample(domains, remaining)
    legit += [f"https://{d}" for d in sample]

    return legit


def main():
    phishing = load_phishing_urls()
    #keep both classes the same size, openphish's free feed is capped around 300
    #so this just makes sure we never ask for more legit urls than we have phishing ones
    legit = load_legit_urls(n=min(N_SAMPLES_PER_CLASS, len(phishing)))

    #look up all the domain ages in parallel first, results land in data/whois_cache.json
    #so re-running this script (or adding features later) doesnt hit whois again
    prefetch_domain_ages(phishing + legit)

    rows = []
    for url in phishing:
        feats = extract_url_features(url)
        feats["domain_age_days"] = extract_domain_age_days(url)
        feats["url"] = url
        feats["label"] = 1
        rows.append(feats)

    for url in legit:
        feats = extract_url_features(url)
        feats["domain_age_days"] = extract_domain_age_days(url)
        feats["url"] = url
        feats["label"] = 0
        rows.append(feats)

    df = pd.DataFrame(rows)
    df.to_csv(f"{DATA_DIR}/dataset.csv", index=False)
    print(f"built dataset: {len(df)} rows ({(df.label==1).sum()} phishing, {(df.label==0).sum()} legit)")
    #-1 means whois gave no usable date. if this is lopsided between the classes the model
    #can learn "unknown age = phishing", so it is worth looking at every time
    unknown = df[df.domain_age_days == -1].groupby("label").size()
    print(f"domain age unknown: {unknown.get(1, 0)} phishing, {unknown.get(0, 0)} legit")
    print(f"{len(LOGIN_URLS)} of the legit rows are real login pages, rest are tranco homepages")
    print(f"saved to {DATA_DIR}/dataset.csv")


if __name__ == "__main__":
    main()
