import csv
import random
import pandas as pd
from features import extract_url_features, extract_domain_age_days, prefetch_domain_ages
from content_features import fetch_content_features, prefetch_content
from curated_legit_urls import LOGIN_URLS

DATA_DIR = "data"
N_SAMPLES_PER_CLASS = 300
N_CRAWLED = 300
N_BARE = 100


def load_phishing_urls(path=f"{DATA_DIR}/openphish.txt"):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]


def load_legit_urls(path=f"{DATA_DIR}/top-1m.csv"):
    #1. curated real login pages, these have actual paths
    legit = list(LOGIN_URLS)

    #2. real urls crawled from top sites (src/collect_legit_urls.py): the homepage the way a
    #browser lands on it (www, trailing slash) plus a few real internal links with paths and
    #queries. before this the legit class was all bare domains, so the model learned
    #"has www / a path / a query = phishing" and flagged normal browsing
    with open(f"{DATA_DIR}/legit_crawled_train.txt") as f:
        crawled = [l.strip() for l in f if l.strip()]
    random.Random(42).shuffle(crawled)
    legit += crawled[:N_CRAWLED]

    #3. some bare tranco homepages, fixed seed so the dataset is the same every build
    domains = []
    with open(path) as f:
        for rank, domain in csv.reader(f):
            domains.append(domain)
            if len(domains) >= N_BARE * 5:
                break
    random.seed(42)
    legit += [f"https://{d}" for d in random.sample(domains, N_BARE)]
    return list(dict.fromkeys(legit))


def main():
    phishing = load_phishing_urls()
    #legit is now bigger than phishing (openphish's free feed is capped around 300), train.py
    #uses class_weight=balanced so the model still treats both classes as equally important
    legit = load_legit_urls()

    #look up all the domain ages in parallel first, results land in data/whois_cache.json
    #so re-running this script (or adding features later) doesnt hit whois again
    prefetch_domain_ages(phishing + legit)

    #same for the page content, but this one loads every page in the docker sandbox
    #(see src/sandbox) and takes a while, results go in data/content_cache.json
    prefetch_content(phishing + legit)


    rows = []
    for url in phishing:
        feats = extract_url_features(url)
        feats["domain_age_days"] = extract_domain_age_days(url)
        feats.update(fetch_content_features(url))
        feats["url"] = url
        feats["label"] = 1
        rows.append(feats)

    for url in legit:
        feats = extract_url_features(url)
        feats["domain_age_days"] = extract_domain_age_days(url)
        feats.update(fetch_content_features(url))
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
    #dead pages get fetch_ok = 0, if this is very lopsided between the classes then
    #"page is alive" is carrying information the model shouldnt get to use
    alive = df[df.fetch_ok == 1].groupby("label").size()
    print(f"pages that loaded: {alive.get(1, 0)} phishing, {alive.get(0, 0)} legit")
    print(f"{len(LOGIN_URLS)} of the legit rows are real login pages, rest are tranco homepages")
    print(f"saved to {DATA_DIR}/dataset.csv")


if __name__ == "__main__":
    main()
