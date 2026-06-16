# ============================================================
# LIVE IDENTITY AI SIMULATOR - ML + ATTACK CORRELATION + DEMO SUMMARY
#
# Simulates Okta + Microsoft 365 AITM / stolen token activity.
# Includes:
# - live log generation
# - Elasticsearch ingestion
# - ML baseline trained on normal events only
# - false-positive reduction
# - user behavior baselines
# - sequence analysis
# - attack story correlation into one incident
# - timeline reconstruction
# - simulated SOAR incident/ticket creation
# ============================================================

import json
import random
import time
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import urllib3
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest

warnings.filterwarnings("ignore")
urllib3.disable_warnings()

print("SCRIPT STARTED", flush=True)

# ============================================================
# CONFIGURATION
# ============================================================
import os
from dotenv import load_dotenv

load_dotenv()

ES_URL = os.getenv("ES_URL")
ES_USER = os.getenv("ELASTIC_USER")
ES_PASSWORD = os.getenv("ELASTIC_PASSWORD")
INDEX = os.getenv("INDEX")

RUN_MINUTES = 10
INTERVAL_SECONDS = 30


SOAR_DIR = Path("soar_actions")
SOAR_DIR.mkdir(exist_ok=True)

INCIDENT_DIR = Path("incidents")
INCIDENT_DIR.mkdir(exist_ok=True)

client = Elasticsearch(
    ES_URL,
    basic_auth=(ES_USER, ES_PASSWORD),
    verify_certs=False,
)


# ============================================================
# GLOBAL STATE
# ============================================================

processed_event_ids = set()
processed_incident_keys = set()
cycle_summaries = []

ML_MODEL = None
ML_FEATURE_COLUMNS = None
ML_CATEGORIES = {}

# ============================================================
# USER BASELINES
# ============================================================

USERS = [
    {
        "user": "alice@company.com",
        "account_type": "employee",
        "user_group": "finance",
        "normal_countries": ["GB"],
        "normal_cities": ["London"],
        "normal_apps": ["Microsoft 365", "SharePoint", "Workday"],
        "normal_actions": ["login", "email_access", "file_access"],
        "normal_user_agents": ["Chrome-Windows", "Edge-Windows"],
        "normal_device_trust": ["managed"],
    },
    {
        "user": "charlie@company.com",
        "account_type": "employee",
        "user_group": "security",
        "normal_countries": ["GB", "FR"],
        "normal_cities": ["London", "Paris"],
        "normal_apps": ["Microsoft 365", "CrowdStrike", "Kibana"],
        "normal_actions": ["login", "security_console_access"],
        "normal_user_agents": ["Chrome-Windows", "Firefox-Linux"],
        "normal_device_trust": ["managed"],
    },
    {
        "user": "bob.vendor@partner.com",
        "account_type": "third_party",
        "user_group": "vendor_support",
        "normal_countries": ["IN", "GB"],
        "normal_cities": ["Bangalore", "London"],
        "normal_apps": ["ServiceNow", "Microsoft 365"],
        "normal_actions": ["login", "ticket_update"],
        "normal_user_agents": ["Chrome-Windows", "Chrome-Mac"],
        "normal_device_trust": ["managed"],
    },
    {
        "user": "sarah.vendor@partner.com",
        "account_type": "third_party",
        "user_group": "vendor_support",
        "normal_countries": ["US"],
        "normal_cities": ["New York"],
        "normal_apps": ["ServiceNow", "Microsoft 365"],
        "normal_actions": ["login", "ticket_update"],
        "normal_user_agents": ["Chrome-Mac", "Edge-Windows"],
        "normal_device_trust": ["managed"],
    },
    {
        "user": "svc_backup@company.com",
        "account_type": "service",
        "user_group": "service_account",
        "normal_countries": ["GB"],
        "normal_cities": ["London"],
        "normal_apps": ["BackupPlatform"],
        "normal_actions": ["api_auth", "backup_job"],
        "normal_user_agents": ["ServiceAgent"],
        "normal_device_trust": ["managed"],
    },
    {
        "user": "maria@company.com",
        "account_type": "employee",
        "user_group": "hr",
        "normal_countries": ["GB", "ES"],
        "normal_cities": ["London", "Madrid"],
        "normal_apps": ["Microsoft 365", "Workday", "SharePoint"],
        "normal_actions": ["login", "email_access", "hr_record_access"],
        "normal_user_agents": ["Chrome-Windows", "Edge-Windows"],
        "normal_device_trust": ["managed"],
    },
    {
        "user": "liam@company.com",
        "account_type": "employee",
        "user_group": "engineering",
        "normal_countries": ["GB", "DE"],
        "normal_cities": ["London", "Berlin"],
        "normal_apps": ["Microsoft 365", "GitHub", "Jira", "Confluence"],
        "normal_actions": ["login", "repo_access", "ticket_update", "wiki_access"],
        "normal_user_agents": ["Chrome-Mac", "Firefox-Linux"],
        "normal_device_trust": ["managed"],
    },
    {
        "user": "nina@company.com",
        "account_type": "employee",
        "user_group": "sales",
        "normal_countries": ["US", "GB"],
        "normal_cities": ["New York", "London"],
        "normal_apps": ["Microsoft 365", "Salesforce", "SharePoint"],
        "normal_actions": ["login", "email_access", "crm_access", "file_access"],
        "normal_user_agents": ["Chrome-Windows", "Chrome-Mac"],
        "normal_device_trust": ["managed"],
    },
    {
        "user": "tom.contractor@partner.com",
        "account_type": "third_party",
        "user_group": "contractor",
        "normal_countries": ["NL", "GB"],
        "normal_cities": ["Amsterdam", "London"],
        "normal_apps": ["ServiceNow", "Microsoft 365", "Jira"],
        "normal_actions": ["login", "ticket_update", "wiki_access"],
        "normal_user_agents": ["Edge-Windows", "Chrome-Windows"],
        "normal_device_trust": ["managed"],
    },
    {
        "user": "emma.vendor@partner.com",
        "account_type": "third_party",
        "user_group": "vendor_finance",
        "normal_countries": ["AU", "GB"],
        "normal_cities": ["Sydney", "London"],
        "normal_apps": ["Microsoft 365", "SharePoint"],
        "normal_actions": ["login", "file_access", "email_access"],
        "normal_user_agents": ["Chrome-Mac", "Edge-Windows"],
        "normal_device_trust": ["managed"],
    },
]

# ============================================================
# INDICATORS / LOOKUPS
# ============================================================

NORMAL_IPS = {
    "GB": "81.2.69.144",
    "US": "104.28.201.10",
    "IN": "103.21.244.0",
    "FR": "13.107.42.12",
    "DE": "20.52.144.23",
    "NL": "51.144.164.215",
    "ES": "40.74.52.10",
    "AU": "13.75.147.143",
}

BAD_IPS = ["185.220.101.45", "91.219.236.222", "45.95.147.10"]
BAD_COUNTRIES = ["RU", "CN"]
BAD_CITIES = {"RU": "Moscow", "CN": "Beijing"}

NORMAL_USER_AGENTS = ["Chrome-Windows", "Chrome-Mac", "Edge-Windows", "Firefox-Linux", "ServiceAgent"]
SUSPICIOUS_USER_AGENTS = ["UnknownBrowser", "PythonRequests", "curl/7.68", "Evilginx-SessionReplay"]

ATTACK_IP = "185.220.101.45"
ATTACK_USERS = ["alice@company.com", "charlie@company.com", "bob.vendor@partner.com"]

ATTACK_SEQUENCE_STEPS = [
    "user.mfa.okta_verify.challenge.failed",
    "user.mfa.okta_verify.challenge.success",
    "device.assurance.new_device_detected",
    "user.session.reuse.detected",
    "UserLoggedIn",
    "MailItemsAccessed",
    "InboxRuleCreated",
    "FileDownloaded",
    "OAuthAppConsentGranted",
]

# ============================================================
# HELPERS
# ============================================================

def now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_session_id():
    return "sess-" + str(random.randint(10000, 99999))


def new_token_id():
    return "tok-" + str(random.randint(100000, 999999))


def get_user_profile(username):
    for profile in USERS:
        if profile["user"] == username:
            return profile
    raise ValueError(f"Unknown user profile: {username}")


def parse_ts(value):
    if value.endswith("Z"):
        value = value.replace("Z", "+00:00")
    return datetime.fromisoformat(value)

# ============================================================
# EVENT BUILDER
# ============================================================

def build_event(
    profile,
    source,
    event_type,
    ip,
    country,
    city,
    user_agent,
    app,
    action,
    status,
    expected_action,
    risk_label,
    session_id=None,
    token_id=None,
    device_id=None,
    device_trust="managed",
):
    return {
        "@timestamp": now_iso(),
        "session_id": session_id or new_session_id(),
        "token_id": token_id or new_token_id(),
        "source": source,
        "event_type": event_type,
        "user": profile["user"],
        "account_type": profile["account_type"],
        "user_group": profile["user_group"],
        "ip": ip,
        "country": country,
        "city": city,
        "user_agent": user_agent,
        "device_id": device_id or "managed-device-" + str(random.randint(100, 999)),
        "device_trust": device_trust,
        "app": app,
        "action": action,
        "status": status,
        "expected_action": expected_action,
        "risk_label": risk_label,
    }

# ============================================================
# NORMAL / FALSE POSITIVE EVENT GENERATION
# ============================================================

def generate_normal_event():
    profile = random.choice(USERS)
    country = random.choice(profile["normal_countries"])
    city = random.choice(profile["normal_cities"])
    source = random.choice(["okta", "m365"])
    event_type = "user.session.start" if source == "okta" else "UserLoggedIn"

    return build_event(
        profile=profile,
        source=source,
        event_type=event_type,
        ip=NORMAL_IPS.get(country, "81.2.69.144"),
        country=country,
        city=city,
        user_agent=random.choice(profile["normal_user_agents"]),
        app=random.choice(profile["normal_apps"]),
        action=random.choice(profile["normal_actions"]),
        status="success",
        expected_action=True,
        risk_label="normal",
    )


def generate_false_positive_event():
    profile = random.choice(USERS)
    country = random.choice(profile["normal_countries"])
    source = random.choice(["okta", "m365"])
    event_type = "user.mfa.okta_verify.challenge.failed" if source == "okta" else "UserLoginFailed"

    event = build_event(
        profile=profile,
        source=source,
        event_type=event_type,
        ip=NORMAL_IPS.get(country, "81.2.69.144"),
        country=country,
        city=random.choice(profile["normal_cities"]),
        user_agent=random.choice(profile["normal_user_agents"]),
        app=random.choice(profile["normal_apps"]),
        action="login_failed_or_mfa_retry",
        status="failure",
        expected_action=True,
        risk_label="false_positive",
    )
    event["note"] = "Looks suspicious but matches expected user profile/location/device"
    return event

# ============================================================
# AITM ATTACK CHAIN GENERATION
# ============================================================

def generate_okta_aitm_chain(username):
    profile = get_user_profile(username)
    session_id = new_session_id()
    token_id = new_token_id()
    device_id = "unknown-device-" + str(random.randint(1000, 9999))

    normal_country = random.choice(profile["normal_countries"])
    normal_city = random.choice(profile["normal_cities"])
    bad_country = random.choice(BAD_COUNTRIES)
    bad_city = BAD_CITIES[bad_country]

    chain = []

    chain.append(
        build_event(
            profile=profile,
            source="okta",
            event_type="user.session.start",
            ip=NORMAL_IPS.get(normal_country, "81.2.69.144"),
            country=normal_country,
            city=normal_city,
            user_agent=random.choice(profile["normal_user_agents"]),
            app="Okta",
            action="session_started",
            status="success",
            expected_action=True,
            risk_label="normal",
            session_id=session_id,
            token_id=token_id,
            device_id="managed-device-" + str(random.randint(100, 999)),
            device_trust="managed",
        )
    )

    for _ in range(random.randint(1, 3)):
        chain.append(
            build_event(
                profile=profile,
                source="okta",
                event_type="user.mfa.okta_verify.challenge.failed",
                ip=ATTACK_IP,
                country=bad_country,
                city=bad_city,
                user_agent=random.choice(SUSPICIOUS_USER_AGENTS),
                app="Okta",
                action="mfa_challenge_failed",
                status="failure",
                expected_action=False,
                risk_label="aitm_attack",
                session_id=session_id,
                token_id=token_id,
                device_id=device_id,
                device_trust="unmanaged",
            )
        )

    for event_type, action in [
        ("user.mfa.okta_verify.challenge.success", "mfa_challenge_success"),
        ("device.assurance.new_device_detected", "new_device_added"),
        ("user.session.reuse.detected", "possible_token_reuse"),
    ]:
        chain.append(
            build_event(
                profile=profile,
                source="okta",
                event_type=event_type,
                ip=ATTACK_IP,
                country=bad_country,
                city=bad_city,
                user_agent=random.choice(SUSPICIOUS_USER_AGENTS),
                app="Okta",
                action=action,
                status="success",
                expected_action=False,
                risk_label="aitm_attack",
                session_id=session_id,
                token_id=token_id,
                device_id=device_id,
                device_trust="unmanaged",
            )
        )

    return chain, session_id, token_id, device_id


def generate_m365_aitm_chain(username, session_id, token_id, device_id):
    profile = get_user_profile(username)
    bad_country = random.choice(BAD_COUNTRIES)
    bad_city = BAD_CITIES[bad_country]

    suspicious_sequence = [
        ("UserLoginFailed", "login_failed", "Microsoft 365", "failure"),
        ("UserLoggedIn", "login", "Microsoft 365", "success"),
        ("MailItemsAccessed", "mail_access", "Exchange Online", "success"),
        ("InboxRuleCreated", "create_inbox_rule", "Exchange Online", "success"),
        ("FileDownloaded", "mass_file_download", "SharePoint", "success"),
        ("OAuthAppConsentGranted", "oauth_consent_granted", "Entra ID", "success"),
    ]

    return [
        build_event(
            profile=profile,
            source="m365",
            event_type=event_type,
            ip=ATTACK_IP,
            country=bad_country,
            city=bad_city,
            user_agent=random.choice(SUSPICIOUS_USER_AGENTS),
            app=app,
            action=action,
            status=status,
            expected_action=False,
            risk_label="aitm_attack",
            session_id=session_id,
            token_id=token_id,
            device_id=device_id,
            device_trust="unmanaged",
        )
        for event_type, action, app, status in suspicious_sequence
    ]

# ============================================================
# ELASTICSEARCH INDEXING
# ============================================================

def index_event(event):
    response = client.index(index=INDEX, document=event)
    event_id = response["_id"]
    print(
        f"[LOG] Indexed {event_id}: {event['source']} | {event['user']} | "
        f"{event['event_type']} | {event['ip']} | {event['session_id']}",
        flush=True,
    )
    return event_id

# ============================================================
# ELASTICSEARCH SEARCH FUNCTIONS
# ============================================================

def search_recent_suspicious_events(minutes=15):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

    query = {
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": since}}}],
                "should": [
                    {"terms": {"ip.keyword": BAD_IPS}},
                    {"term": {"event_type.keyword": "user.session.reuse.detected"}},
                    {"term": {"event_type.keyword": "user.mfa.okta_verify.challenge.failed"}},
                    {"term": {"event_type.keyword": "device.assurance.new_device_detected"}},
                    {"term": {"event_type.keyword": "UserLoginFailed"}},
                    {"term": {"event_type.keyword": "InboxRuleCreated"}},
                    {"term": {"event_type.keyword": "OAuthAppConsentGranted"}},
                    {"term": {"expected_action": False}},
                    {"terms": {"user_agent.keyword": SUSPICIOUS_USER_AGENTS}},
                ],
                "minimum_should_match": 1,
            }
        },
        "size": 200,
    }

    response = client.search(index=INDEX, body=query)
    return response["hits"]["hits"]


def search_events_by_session_or_token(session_id=None, token_id=None, minutes=60):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
    should = []

    if session_id:
        should.append({"term": {"session_id.keyword": session_id}})
    if token_id:
        should.append({"term": {"token_id.keyword": token_id}})

    query = {
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": since}}}],
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "size": 500,
        "sort": [{"@timestamp": {"order": "asc"}}],
    }

    response = client.search(index=INDEX, body=query)
    return response["hits"]["hits"]


def search_related_users_by_ip(ip, minutes=60):
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"ip.keyword": ip}},
                    {"range": {"@timestamp": {"gte": since}}},
                ]
            }
        },
        "size": 500,
    }
    response = client.search(index=INDEX, body=query)
    return sorted(set(hit["_source"]["user"] for hit in response["hits"]["hits"]))

# ============================================================
# ML BASELINE TRAINING - NORMAL EVENTS ONLY
# ============================================================

def train_ml_baseline():
    global ML_MODEL, ML_FEATURE_COLUMNS, ML_CATEGORIES

    query = {
        "query": {"term": {"risk_label.keyword": "normal"}},
        "size": 5000,
    }

    response = client.search(index=INDEX, body=query)
    events = [hit["_source"] for hit in response["hits"]["hits"]]

    if len(events) < 20:
        print("[ML] Not enough normal events to train baseline yet", flush=True)
        return False

    df = pd.DataFrame(events)

    fields = [
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

    encoded = pd.DataFrame()
    ML_CATEGORIES = {}

    for field in fields:
        df[field] = df[field].fillna("unknown").astype(str)
        categories = sorted(df[field].unique().tolist())
        ML_CATEGORIES[field] = categories
        encoded[field] = df[field].apply(lambda value: categories.index(value) if value in categories else -1)

    ML_FEATURE_COLUMNS = fields
    ML_MODEL = IsolationForest(contamination=0.10, random_state=42)
    ML_MODEL.fit(encoded)

    print(f"[ML] Trained baseline on {len(df)} normal events", flush=True)
    return True


def calculate_ml_anomaly_score(src):
    if ML_MODEL is None or ML_FEATURE_COLUMNS is None:
        return 0

    row = {}

    for field in ML_FEATURE_COLUMNS:
        value = str(src.get(field, "unknown"))
        categories = ML_CATEGORIES.get(field, [])
        row[field] = categories.index(value) if value in categories else -1

    df = pd.DataFrame([row])
    prediction = ML_MODEL.predict(df)[0]
    raw_score = ML_MODEL.decision_function(df)[0]

    if prediction == -1:
        return 90
    if raw_score < 0.02:
        return 50
    return 20

# ============================================================
# FALSE POSITIVE REDUCTION + USER BASELINES
# ============================================================

def calculate_false_positive_reduction(src):
    profile = get_user_profile(src["user"])
    reduction = 0
    reasons = []

    if src["country"] in profile["normal_countries"]:
        reduction += 10
        reasons.append("Country matches user baseline")

    if src["app"] in profile["normal_apps"]:
        reduction += 10
        reasons.append("Application matches user baseline")

    if src["user_agent"] in profile["normal_user_agents"]:
        reduction += 10
        reasons.append("User agent matches user baseline")

    if src.get("device_trust") in profile["normal_device_trust"]:
        reduction += 10
        reasons.append("Device trust matches user baseline")

    if src["risk_label"] == "false_positive":
        reduction += 20
        reasons.append("Event is labelled as expected false-positive simulation")

    return reduction, reasons

# ============================================================
# SEQUENCE ANALYSIS + ATTACK STORY CORRELATION
# ============================================================

def reconstruct_timeline(events):
    sorted_events = sorted(events, key=lambda e: e["_source"].get("@timestamp", ""))
    timeline = []

    for hit in sorted_events:
        src = hit["_source"]
        timeline.append(
            {
                "timestamp": src.get("@timestamp"),
                "source": src.get("source"),
                "event_type": src.get("event_type"),
                "user": src.get("user"),
                "ip": src.get("ip"),
                "country": src.get("country"),
                "device_id": src.get("device_id"),
                "app": src.get("app"),
                "action": src.get("action"),
                "status": src.get("status"),
            }
        )

    return timeline


def analyze_attack_sequence(events):
    seen_types = [hit["_source"].get("event_type") for hit in events]
    matched_steps = [step for step in ATTACK_SEQUENCE_STEPS if step in seen_types]

    score = 0
    reasons = []

    if len(matched_steps) >= 3:
        score += 30
        reasons.append(f"Attack sequence contains {len(matched_steps)} known AITM/post-compromise steps")

    if "user.mfa.okta_verify.challenge.failed" in seen_types and "user.mfa.okta_verify.challenge.success" in seen_types:
        score += 20
        reasons.append("MFA failure followed by MFA success observed")

    if "device.assurance.new_device_detected" in seen_types:
        score += 20
        reasons.append("New device detected within same attack story")

    if "user.session.reuse.detected" in seen_types:
        score += 30
        reasons.append("Session reuse detected within same attack story")

    if "InboxRuleCreated" in seen_types:
        score += 25
        reasons.append("Inbox rule created after suspicious identity activity")

    if "OAuthAppConsentGranted" in seen_types:
        score += 25
        reasons.append("OAuth consent granted after suspicious identity activity")

    return score, reasons, matched_steps


def build_attack_story(src):
    story_events = search_events_by_session_or_token(
        session_id=src.get("session_id"),
        token_id=src.get("token_id"),
        minutes=60,
    )

    timeline = reconstruct_timeline(story_events)
    sequence_score, sequence_reasons, matched_steps = analyze_attack_sequence(story_events)

    related_users = sorted(set(hit["_source"].get("user") for hit in story_events))
    related_ips = sorted(set(hit["_source"].get("ip") for hit in story_events))
    related_devices = sorted(set(hit["_source"].get("device_id") for hit in story_events))
    related_countries = sorted(set(hit["_source"].get("country") for hit in story_events))

    incident_key = src.get("session_id") or src.get("token_id") or src.get("user")

    return {
        "incident_key": incident_key,
        "event_count": len(story_events),
        "timeline": timeline,
        "sequence_score": sequence_score,
        "sequence_reasons": sequence_reasons,
        "matched_steps": matched_steps,
        "related_users": related_users,
        "related_ips": related_ips,
        "related_devices": related_devices,
        "related_countries": related_countries,
    }

# ============================================================
# RISK SCORING
# ============================================================

def calculate_risk(event):
    src = event["_source"]
    profile = get_user_profile(src["user"])

    risk = 0
    reasons = []

    ml_score = calculate_ml_anomaly_score(src)
    if ml_score >= 70:
        risk += 30
        reasons.append("ML baseline flagged this event as anomalous")
    elif ml_score >= 50:
        risk += 15
        reasons.append("ML baseline marked this event as borderline unusual")

    if src["ip"] in BAD_IPS:
        risk += 40
        reasons.append("IP is listed as malicious")

    if src["country"] not in profile["normal_countries"]:
        risk += 20
        reasons.append("Login country is unusual for this user")

    if src["user_agent"] in SUSPICIOUS_USER_AGENTS:
        risk += 15
        reasons.append("User agent is suspicious")

    if src.get("device_trust") == "unmanaged":
        risk += 20
        reasons.append("Device is unmanaged or newly observed")

    if src["app"] not in profile["normal_apps"] and src["app"] not in ["Okta", "Entra ID"]:
        risk += 15
        reasons.append("Application is unusual for this user/group")

    if src["action"] not in profile["normal_actions"]:
        risk += 15
        reasons.append("Action is unusual for this user/group")

    if src["account_type"] == "third_party":
        risk += 15
        reasons.append("Third-party account increases risk")

    if src["event_type"] in ["user.mfa.okta_verify.challenge.failed", "UserLoginFailed"]:
        risk += 10
        reasons.append("Failed authentication or MFA challenge observed")

    if src["event_type"] in [
        "user.session.reuse.detected",
        "device.assurance.new_device_detected",
        "InboxRuleCreated",
        "OAuthAppConsentGranted",
    ]:
        risk += 25
        reasons.append("High-risk post-authentication or token/session event observed")

    attack_story = build_attack_story(src)
    risk += attack_story["sequence_score"]
    reasons.extend(attack_story["sequence_reasons"])

    fp_reduction, fp_reasons = calculate_false_positive_reduction(src)

    if risk < 80:
        risk = max(0, risk - fp_reduction)
        if fp_reduction > 0:
            reasons.append(f"False-positive reduction applied: -{fp_reduction}")
            reasons.extend(fp_reasons)

    if risk >= 80:
        level = "HIGH"
    elif risk >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return risk, level, reasons, ml_score, attack_story

# ============================================================
# AI REASONING LAYER
# ============================================================

def ai_reasoning_layer(src, risk, level, reasons, attack_story):
    confidence = "High" if level == "HIGH" else "Medium" if level == "MEDIUM" else "Low"

    if "user.session.reuse.detected" in attack_story["matched_steps"]:
        incident_type = "Possible stolen session/token reuse"
    elif "InboxRuleCreated" in attack_story["matched_steps"] or "OAuthAppConsentGranted" in attack_story["matched_steps"]:
        incident_type = "Post-compromise Microsoft 365 activity"
    elif "user.mfa.okta_verify.challenge.failed" in attack_story["matched_steps"]:
        incident_type = "Possible AITM / MFA manipulation"
    else:
        incident_type = "Suspicious identity activity"

    if level == "HIGH":
        recommended_response = [
            "Revoke active sessions",
            "Force password reset",
            "Require MFA re-authentication",
            "Review same session_id/token_id",
            "Investigate related users and IPs",
            "Escalate to IR",
        ]
    elif level == "MEDIUM":
        recommended_response = [
            "Force re-authentication",
            "Create IT support ticket",
            "Review recent user activity",
            "Monitor related accounts",
        ]
    else:
        recommended_response = ["Monitor only"]

    return {
        "incident_type": incident_type,
        "confidence": confidence,
        "risk_level": level,
        "risk_score": risk,
        "assessment": (
            f"The activity for {src['user']} appears to be {level.lower()} risk. "
            f"The story contains {attack_story['event_count']} correlated events using session/token context."
        ),
        "key_evidence": reasons,
        "related_accounts": attack_story["related_users"],
        "recommended_response": recommended_response,
    }

# ============================================================
# SOAR INCIDENT / TICKET SIMULATION
# ============================================================

def create_soar_incident(src, risk, level, reasons, ml_score, attack_story, ai_summary):
    incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{random.randint(1000, 9999)}"

    incident = {
        "incident_id": incident_id,
        "created_at": now_iso(),
        "incident_type": ai_summary["incident_type"],
        "priority": "High" if level == "HIGH" else "Medium" if level == "MEDIUM" else "Low",
        "status": "Open" if level in ["HIGH", "MEDIUM"] else "Monitor",
        "assigned_to": "IT Support / IR",
        "summary": f"Identity attack story correlated for {src['user']}",
        "user": src["user"],
        "account_type": src["account_type"],
        "user_group": src["user_group"],
        "source_ip": src["ip"],
        "country": src["country"],
        "device_id": src["device_id"],
        "device_trust": src["device_trust"],
        "session_id": src["session_id"],
        "token_id": src["token_id"],
        "risk_score": risk,
        "risk_level": level,
        "ml_score": ml_score,
        "reasons": reasons,
        "related_users": attack_story["related_users"],
        "related_ips": attack_story["related_ips"],
        "related_devices": attack_story["related_devices"],
        "related_countries": attack_story["related_countries"],
        "matched_attack_steps": attack_story["matched_steps"],
        "timeline": attack_story["timeline"],
        "requested_actions": ai_summary["recommended_response"],
    }

    if src["account_type"] == "third_party":
        incident["requested_actions"].append("Notify third-party/vendor owner")

    incident_file = INCIDENT_DIR / f"{incident_id}.json"
    ticket_file = SOAR_DIR / f"{incident_id}_ticket.json"

    with open(incident_file, "w") as f:
        json.dump(incident, f, indent=2)

    with open(ticket_file, "w") as f:
        json.dump(incident, f, indent=2)

    print(f"[SOAR] Created incident: {incident_file}", flush=True)
    print(f"[SOAR] Created ticket:   {ticket_file}", flush=True)

    return incident

# ============================================================
# TERMINAL OUTPUT / VISUAL FLOW
# ============================================================

def print_timeline(timeline):
    print("\nTIMELINE RECONSTRUCTION:")
    for item in timeline:
        print(
            f" - {item['timestamp']} | {item['source']} | {item['event_type']} | "
            f"{item['user']} | {item['ip']} | {item['country']} | {item['app']} | {item['action']}"
        )


def print_visual_attack_flow(src, ai_summary, attack_story, ml_score):
    ml_result = "ANOMALOUS" if ml_score >= 70 else "BORDERLINE" if ml_score >= 50 else "NORMAL / LOW ANOMALY"

    print("\n" + "🧭" + "=" * 60)
    print("VISUAL EVENT FLOW")
    print("=" * 60)
    print(f"""
[1] LOG SOURCE
    └── Trigger Event: {src['source']} / {src['event_type']}

[2] IDENTITY
    └── User: {src['user']}
        Type: {src['account_type']}
        Group: {src['user_group']}

[3] SESSION / TOKEN CORRELATION
    └── Session: {src['session_id']}
        Token:   {src['token_id']}
        Correlated Events: {attack_story['event_count']}

[4] TIMELINE RECONSTRUCTION
    └── Matched Attack Steps: {', '.join(attack_story['matched_steps']) if attack_story['matched_steps'] else 'None'}

[5] ML BASELINE REVIEW
    └── Model trained on normal events only.
        ML Anomaly Score: {ml_score}
        Result: {ml_result}

[6] USER BASELINE + FALSE POSITIVE REVIEW
    └── Baseline fields checked:
        - normal country
        - normal app
        - normal action
        - normal user agent
        - normal device trust

[7] AI DECISION
    └── Incident: {ai_summary['incident_type']}
        Confidence: {ai_summary['confidence']}
        Risk: {ai_summary['risk_score']} / {ai_summary['risk_level']}

[8] RELATED ENTITIES
    └── Users: {', '.join(attack_story['related_users']) if attack_story['related_users'] else 'None'}
        IPs: {', '.join(attack_story['related_ips']) if attack_story['related_ips'] else 'None'}
        Devices: {', '.join(attack_story['related_devices']) if attack_story['related_devices'] else 'None'}

[9] SIMULATED SOAR RESPONSE
    └── Incident/ticket created if MEDIUM or HIGH
        Actions: {', '.join(ai_summary['recommended_response'])}
""")
    print("=" * 60 + "\n")

# ============================================================
# INVESTIGATION LOGIC
# ============================================================

def investigate_event(event, source="polling"):
    event_id = event.get("_id", f"webhook-{random.randint(1000, 9999)}")

    if event_id in processed_event_ids:
        return 0

    src = event["_source"]
    risk, level, reasons, ml_score, attack_story = calculate_risk(event)
    ai_summary = ai_reasoning_layer(src, risk, level, reasons, attack_story)

    incident_key = attack_story["incident_key"]

    print("\n" + "=" * 60)
    print(f"AI INCIDENT SUMMARY ({source.upper()})")
    print("=" * 60)
    print(f"Incident Type: {ai_summary['incident_type']}")
    print(f"Risk Level: {level}")
    print(f"Risk Score: {risk}")
    print(f"User: {src['user']} | Session: {src['session_id']} | Token: {src['token_id']}")
    print("\nWhy flagged:")
    for reason in reasons:
        print(f" - {reason}")

    print_visual_attack_flow(src, ai_summary, attack_story, ml_score)
    print_timeline(attack_story["timeline"])

    print("\nAI Recommended Response:")
    for action in ai_summary["recommended_response"]:
        print(f" - {action}")

    incident_created = 0

    if level in ["HIGH", "MEDIUM"]:
        if incident_key not in processed_incident_keys:
            create_soar_incident(src, risk, level, reasons, ml_score, attack_story, ai_summary)
            processed_incident_keys.add(incident_key)
            incident_created = 1
        else:
            incident_created = 0
            print(f"[SOAR] Incident already created for story key: {incident_key}", flush=True)
    else:
        incident_created = 0
        print("[SOAR] No ticket created. Monitor only.", flush=True)

    processed_event_ids.add(event_id)
    return incident_created


def investigate_recent_events():
    events = search_recent_suspicious_events()
    incidents_created = 0

    if not events:
        print("[AI] No suspicious recent events found", flush=True)
        return 0, 0

    print(f"[AI] Found {len(events)} suspicious recent events", flush=True)

    for event in events:
        incidents_created += investigate_event(event, source="polling")

    return len(events), incidents_created



# ============================================================
# DEMO CYCLE SUMMARY OUTPUT
# ============================================================

def demo_cycle_summary(cycle, generated, suspicious, incidents):
    summary = {
        "cycle": cycle,
        "timestamp": now_iso(),
        "generated": generated,
        "suspicious": suspicious,
        "incidents": incidents,
    }

    cycle_summaries.append(summary)

    print("\n" + "=" * 70)
    print(f"SOC REVIEW SUMMARY — CYCLE {cycle}")
    print("=" * 70)
    print(f"Timestamp:               {summary['timestamp']}")
    print(f"Events Generated:        {generated}")
    print(f"Suspicious Events:       {suspicious}")
    print(f"Incidents Triggered:     {incidents}")

    if suspicious > 0:
        print("\nSOC ASSESSMENT:")
        print(" - Suspicious identity activity detected")
        print(" - ML baseline review completed")
        print(" - Attack story correlation performed")
        print(" - Timeline reconstruction completed")
        print(" - SOAR workflow simulation reviewed")
    else:
        print("\nSOC ASSESSMENT:")
        print(" - Environment appears stable")
        print(" - No major identity anomalies detected")

    print("=" * 70 + "\n")


def final_demo_report():
    print("\n" + "#" * 70)
    print("FINAL SOC OPERATIONAL REVIEW")
    print("#" * 70)

    total_cycles = len(cycle_summaries)
    total_generated = sum(item["generated"] for item in cycle_summaries)
    total_suspicious = sum(item["suspicious"] for item in cycle_summaries)
    total_incidents = sum(item["incidents"] for item in cycle_summaries)

    print(f"Simulation Cycles:       {total_cycles}")
    print(f"Total Events:            {total_generated}")
    print(f"Suspicious Events:       {total_suspicious}")
    print(f"SOAR Incidents:          {total_incidents}")

    print("\nPER-CYCLE REVIEW:")
    for item in cycle_summaries:
        print(
            f" - Cycle {item['cycle']} | "
            f"Generated: {item['generated']} | "
            f"Suspicious: {item['suspicious']} | "
            f"Incidents: {item['incidents']}"
        )

    print("\nPLATFORM CAPABILITIES DEMONSTRATED:")
    capabilities = [
        "Identity telemetry simulation",
        "Okta + Microsoft 365 AITM attack simulation",
        "Session/token reuse detection",
        "User behavior baseline comparison",
        "ML anomaly scoring trained on normal events only",
        "False-positive reduction using known-good context",
        "Sequence analysis",
        "Attack story correlation",
        "Timeline reconstruction",
        "Simulated SOAR incident/ticket creation",
    ]

    for capability in capabilities:
        print(f" - {capability}")

    print("\nENTERPRISE SECURITY USE CASE:")
    print("This demo shows how a SOC could use SIEM + analytics + SOAR logic")
    print("to detect identity attacks, correlate related activity, reduce false")
    print("positives, and produce a response-ready incident story.")

    print("#" * 70 + "\n")

# ============================================================
# MAIN LIVE SIMULATION LOOP
# ============================================================

def main():
    print("ENTERED MAIN", flush=True)
    print("Starting live identity AI simulation", flush=True)
    print(f"Run time: {RUN_MINUTES} minutes", flush=True)
    print(f"Interval: {INTERVAL_SECONDS} seconds", flush=True)
    print("Press CTRL+C to stop early\n", flush=True)
    if not client.indices.exists(index=INDEX):
        print(f"[SETUP] Creating missing index: {INDEX}", flush=True)
        client.indices.create(index=INDEX)

    print("[SETUP] Generating starter normal logs for ML baseline...", flush=True)

    for _ in range(30):
        index_event(generate_normal_event())

    print("[ML] Training baseline from existing normal logs...", flush=True)
    train_ml_baseline()

    end_time = time.time() + RUN_MINUTES * 60
    cycle = 0

    #print("[ML] Training baseline from existing normal logs...", flush=True)#
   # train_ml_baseline()# this is being repalce with an new part to create new indexs

    #end_time = time.time() + RUN_MINUTES * 60#
   # cycle = 0#

    while time.time() < end_time:
        cycle += 1
        print(f"\n========== CYCLE {cycle} ==========" , flush=True)

        generated_count = 0

        if cycle % 4 == 0:
            print("[SIM] Generating coordinated AITM attack burst", flush=True)

            for username in ATTACK_USERS:
                okta_chain, session_id, token_id, device_id = generate_okta_aitm_chain(username)

                for event in okta_chain:
                    index_event(event)
                    generated_count += 1

                m365_chain = generate_m365_aitm_chain(username, session_id, token_id, device_id)

                for event in m365_chain:
                    index_event(event)
                    generated_count += 1
        else:
            for _ in range(random.randint(4, 9)):
                # Increased false-positive generation to help demo tuning and ML baseline behavior
                if random.random() < 0.35:
                    index_event(generate_false_positive_event())
                else:
                    index_event(generate_normal_event())
                generated_count += 1

        if cycle % 3 == 0:
            print("[ML] Refreshing normal-behavior baseline...", flush=True)
            train_ml_baseline()

        suspicious_count, incidents_created = investigate_recent_events()

        demo_cycle_summary(
            cycle=cycle,
            generated=generated_count,
            suspicious=suspicious_count,
            incidents=incidents_created,
        )

        print(f"[WAIT] Sleeping {INTERVAL_SECONDS} seconds", flush=True)
        time.sleep(INTERVAL_SECONDS)

    print("\nSimulation finished", flush=True)
    print(f"SOAR tickets saved in: {SOAR_DIR.resolve()}", flush=True)
    print(f"Incidents saved in: {INCIDENT_DIR.resolve()}", flush=True)
    final_demo_report()

if __name__ == "__main__":
    main()
