import urllib3
import pandas as pd

from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest

urllib3.disable_warnings()

client = Elasticsearch(
    "https://localhost:9200",
    basic_auth=("elastic", os.getenv("ELASTIC_PASSWORD")),
    verify_certs=False,
)

INDEX = "identity-auth-logs"

response = client.search(
    index=INDEX,
    body={
        "query": {
            "match_all": {}
        },
        "size": 5000
    }
)

events = [hit["_source"] for hit in response["hits"]["hits"]]

df = pd.DataFrame(events)

print(f"\nLoaded {len(df)} events")

# =========================
# Convert text → numeric
# =========================

categorical_fields = [
    "source",
    "event_type",
    "country",
    "city",
    "user_agent",
    "app",
    "action",
    "account_type",
    "user_group",
    "device_trust",
]

for field in categorical_fields:
    df[field + "_code"] = (
        df[field]
        .astype("category")
        .cat.codes
    )

# =========================
# Features for ML
# =========================

features = df[
    [
        "source_code",
        "event_type_code",
        "country_code",
        "city_code",
        "user_agent_code",
        "app_code",
        "action_code",
        "account_type_code",
        "user_group_code",
        "device_trust_code",
    ]
]

# =========================
# Train anomaly model
# =========================

model = IsolationForest(
    contamination=0.10,
    random_state=42
)

df["ml_prediction"] = model.fit_predict(features)

# -1 = anomaly
#  1 = normal

anomalies = df[df["ml_prediction"] == -1]

print("\n==============================")
print("ML ANOMALY DETECTION RESULTS")
print("==============================")

print(f"\nTotal events: {len(df)}")
print(f"Anomalies detected: {len(anomalies)}")

print("\nTop ML anomalies:\n")

columns = [
    "@timestamp",
    "user",
    "source",
    "event_type",
    "country",
    "device_trust",
    "app",
    "action",
    "session_id",
    "token_id",
]

print(
    anomalies[columns]
    .head(25)
    .to_string(index=False)
)