# ml/url_dataset.py
import pandas as pd
import re

def extract_features(url):
    return {
        "length": len(url),
        "digits": sum(c.isdigit() for c in url),
        "special_chars": len(re.findall(r"[@\-_%]", url)),
        "has_https": int(url.startswith("https"))
    }

df = pd.read_csv("malicious_urls.csv")
features = df["url"].apply(extract_features)
X = pd.DataFrame(features.tolist())
y = df["label"]

X["label"] = y
X.to_csv("processed_url_data.csv", index=False)
