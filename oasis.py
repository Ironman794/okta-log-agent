r"""
OASIS (Okta Access Security Intelligence System): read-only Okta IAM troubleshooting agent (v2).
Tools: search_logs (paginated + summarized), get_user_status, get_user_authenticators,
       find_apps, get_user_apps, get_app_assignments.

Setup:  pip install anthropic requests "pyjwt[crypto]"
Auth:   OAuth 2.0 client credentials against the Okta org authorization server, using an
        API Services app (OIDC app type) with private_key_jwt client authentication.
Env:    OKTA_ORG_URL=https://your-org.okta.com
        OKTA_CLIENT_ID=0oa...                    (client ID of the API Services app)
        OKTA_PRIVATE_KEY_FILE=/path/to/private_key.pem   (private key, PEM or JWK; public half registered on the app)
        OKTA_KEY_ID=...                          (optional kid; needed if the app has more than one key)
        OKTA_SCOPES=okta.logs.read okta.users.read okta.apps.read   (optional, space-separated; default below)
        ANTHROPIC_API_KEY=...
Run:    python oasis.py                 (interactive prompt; "new" resets, "exit" quits)
        python oasis.py "why is jdoe@example.com failing to sign in today?"   (one question, then exit)
Test tenant / lab data only until your org approves this.
"""
import os, sys, json, time, uuid, collections, datetime as dt
import requests
import jwt
import anthropic

_missing = [v for v in ("OKTA_ORG_URL", "OKTA_CLIENT_ID", "OKTA_PRIVATE_KEY_FILE") if not os.environ.get(v)]
if _missing:
    sys.exit(f"Missing environment variable(s): {', '.join(_missing)}. See the setup notes at the top of this file.")

ORG = os.environ["OKTA_ORG_URL"].rstrip("/")
CLIENT_ID = os.environ["OKTA_CLIENT_ID"]
TOKEN_URL = f"{ORG}/oauth2/v1/token"  # org authorization server (the only one that issues okta.* scopes)
# Least privilege: logs for search_logs, users for get_user_status and the /users/{id}/factors listing,
# apps for the app assignment tools.
SCOPES = os.environ.get("OKTA_SCOPES", "okta.logs.read okta.users.read okta.apps.read")
MODEL = "claude-sonnet-5"

PAGE_SIZE = 100       # events per API page (Okta max 1000)
MAX_PAGES = 10        # hard cap on pages fetched per query
MAX_EVENTS = 1000     # hard cap on total events pulled per query
SAMPLE_SIZE = 40      # events actually shown to the model (rest are summarized)
MAX_ASSIGNEES = 1000  # hard cap on app users/groups fetched per app
ASSIGNEE_SAMPLE = 200 # assigned users actually shown to the model (rest are counted)


# ---------- auth ----------
_token = {"value": None, "expires_at": 0}


def _private_key():
    with open(os.environ["OKTA_PRIVATE_KEY_FILE"]) as f:
        raw = f.read().strip()
    return jwt.algorithms.RSAAlgorithm.from_jwk(raw) if raw.startswith("{") else raw


def _access_token():
    """Client-credentials token, authenticated with a signed JWT assertion. Cached until near expiry."""
    if _token["value"] and time.time() < _token["expires_at"] - 60:
        return _token["value"]
    now = int(time.time())
    kid = os.environ.get("OKTA_KEY_ID")
    assertion = jwt.encode(
        {"iss": CLIENT_ID, "sub": CLIENT_ID, "aud": TOKEN_URL, "iat": now, "exp": now + 300, "jti": str(uuid.uuid4())},
        _private_key(),
        algorithm="RS256",
        headers={"kid": kid} if kid else None,
    )
    r = requests.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "scope": SCOPES,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        },
        headers={"Accept": "application/json"},
        timeout=30,
    )
    if not r.ok:
        raise RuntimeError(f"Okta token request failed ({r.status_code}): {r.text}")
    body = r.json()
    _token["value"] = body["access_token"]
    _token["expires_at"] = time.time() + int(body.get("expires_in", 3600))
    return _token["value"]


def _headers():
    return {"Authorization": f"Bearer {_access_token()}", "Accept": "application/json"}


# ---------- helpers ----------
def _q(s):
    return str(s).replace('"', "").replace("\\", "")


def _slim(e):
    return {
        "time": e.get("published"),
        "event": e.get("eventType"),
        "result": (e.get("outcome") or {}).get("result"),
        "reason": (e.get("outcome") or {}).get("reason"),
        "user": (e.get("actor") or {}).get("alternateId"),
        "app": next((t.get("displayName") for t in e.get("target") or [] if t.get("type") == "AppInstance"), None),
        "ip": (e.get("client") or {}).get("ipAddress"),
        "geo": ((e.get("client") or {}).get("geographicalContext") or {}).get("country"),
        "device": ((e.get("client") or {}).get("userAgent") or {}).get("rawUserAgent"),
        "credential": (e.get("authenticationContext") or {}).get("credentialType"),
        "message": e.get("displayMessage"),
    }


def _top(counter, n=8):
    return [{"value": k, "count": v} for k, v in counter.most_common(n) if k is not None]


def _get_all(url, params=None, cap=MAX_ASSIGNEES):
    """Follow Link: rel="next" pagination up to cap items. Returns (items, truncated)."""
    items, truncated = [], False
    while url:
        r = requests.get(url, headers=_headers(), params=params, timeout=30)
        r.raise_for_status()
        items.extend(r.json())
        params = None
        url = (r.links.get("next") or {}).get("url")
        if url and len(items) >= cap:
            truncated = True
            break
    return items[:cap], truncated


def _slim_app(a):
    return {
        "id": a.get("id"),
        "label": a.get("label"),
        "integration": a.get("name"),
        "status": a.get("status"),
        "signOnMode": a.get("signOnMode"),
    }


def _resolve_app(app):
    """App ID or label -> slim app dict, or an error dict listing candidates when ambiguous."""
    app = str(app).strip()
    if app.startswith("0oa") and " " not in app:
        r = requests.get(f"{ORG}/api/v1/apps/{_q(app)}", headers=_headers(), timeout=30)
        if r.status_code == 404:
            return {"error": "App not found"}
        r.raise_for_status()
        return _slim_app(r.json())
    r = requests.get(f"{ORG}/api/v1/apps", headers=_headers(), params={"q": app, "limit": 50}, timeout=30)
    r.raise_for_status()
    matches = [_slim_app(a) for a in r.json()]
    exact = [a for a in matches if (a["label"] or "").lower() == app.lower()]
    if len(exact) == 1:
        return exact[0]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        return {"error": f"No app matches '{app}'. Try find_apps with a shorter name."}
    return {"error": "Multiple apps match. Ask which one, then retry with its id.", "candidates": matches}


# ---------- tools ----------
def search_logs(user=None, event_type=None, outcome=None, hours_back=24, keyword=None):
    """Paginated System Log search. Returns totals + breakdowns + a sample of recent events."""
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=min(int(hours_back), 168))).strftime("%Y-%m-%dT%H:%M:%SZ")
    clauses = []
    if user:
        clauses.append(f'actor.alternateId eq "{_q(user)}"')
    if event_type:
        clauses.append(f'eventType eq "{_q(event_type)}"')
    if outcome in ("SUCCESS", "FAILURE", "SKIPPED", "ALLOW", "DENY", "CHALLENGE", "UNKNOWN"):
        clauses.append(f'outcome.result eq "{outcome}"')
    params = {"since": since, "limit": PAGE_SIZE, "sortOrder": "DESCENDING"}
    if clauses:
        params["filter"] = " and ".join(clauses)
    if keyword:
        params["q"] = keyword

    events, pages, url, truncated = [], 0, f"{ORG}/api/v1/logs", False
    while url:
        r = requests.get(url, headers=_headers(), params=params if pages == 0 else None, timeout=30)
        if r.status_code == 429:
            return {"error": "Okta rate limit hit (429). Narrow the query or retry later.", "events_fetched": len(events)}
        r.raise_for_status()
        events.extend(_slim(e) for e in r.json())
        pages += 1
        url = (r.links.get("next") or {}).get("url")  # Okta uses Link: rel="next"
        if url and (pages >= MAX_PAGES or len(events) >= MAX_EVENTS):
            truncated = True
            break
    events = events[:MAX_EVENTS]

    return {
        "total_events": len(events),
        "pages_fetched": pages,
        "truncated": truncated,
        "note": "Truncated: more events exist. Narrow user/event_type/outcome/hours_back." if truncated else None,
        "breakdown": {
            "by_event": _top(collections.Counter(e["event"] for e in events)),
            "by_result": _top(collections.Counter(e["result"] for e in events)),
            "by_reason": _top(collections.Counter(e["reason"] for e in events)),
            "by_user": _top(collections.Counter(e["user"] for e in events)),
            "by_ip": _top(collections.Counter(e["ip"] for e in events)),
            "by_country": _top(collections.Counter(e["geo"] for e in events)),
            "by_app": _top(collections.Counter(e["app"] for e in events)),
        },
        "first_event_time": events[-1]["time"] if events else None,
        "last_event_time": events[0]["time"] if events else None,
        "sample_most_recent": events[:SAMPLE_SIZE],
    }


def get_user_status(user):
    """Account state only: no profile PII beyond login."""
    r = requests.get(f"{ORG}/api/v1/users/{_q(user)}", headers=_headers(), timeout=30)
    if r.status_code == 404:
        return {"error": "User not found"}
    r.raise_for_status()
    u = r.json()
    return {
        "id": u.get("id"),
        "login": (u.get("profile") or {}).get("login"),
        "status": u.get("status"),  # ACTIVE, LOCKED_OUT, SUSPENDED, PASSWORD_EXPIRED, DEPROVISIONED, ...
        "created": u.get("created"),
        "activated": u.get("activated"),
        "statusChanged": u.get("statusChanged"),
        "lastLogin": u.get("lastLogin"),
        "lastUpdated": u.get("lastUpdated"),
        "passwordChanged": u.get("passwordChanged"),
    }


def get_user_authenticators(user):
    """Enrolled factors/authenticators. Returns types and status only (no phone numbers or emails)."""
    r = requests.get(f"{ORG}/api/v1/users/{_q(user)}", headers=_headers(), timeout=30)
    if r.status_code == 404:
        return {"error": "User not found"}
    r.raise_for_status()
    uid = r.json()["id"]
    r = requests.get(f"{ORG}/api/v1/users/{uid}/factors", headers=_headers(), timeout=30)
    r.raise_for_status()
    out = []
    for f in r.json():
        out.append({
            "factorType": f.get("factorType"),  # push, signed_nonce (FastPass), webauthn (passkey/security key), token:software:totp, sms, ...
            "provider": f.get("provider"),
            "status": f.get("status"),
            "name": (f.get("profile") or {}).get("authenticatorName"),
            "created": f.get("created"),
            "lastUpdated": f.get("lastUpdated"),
        })
    return {"user_id": uid, "enrolled_count": len(out), "authenticators": out}


def find_apps(query=None):
    """Search apps by label/name, or list them when no query is given."""
    params = {"limit": 200}
    if query:
        params["q"] = query
    apps, truncated = _get_all(f"{ORG}/api/v1/apps", params, cap=200)
    return {"count": len(apps), "truncated": truncated, "apps": [_slim_app(a) for a in apps]}


def get_user_apps(user):
    """Apps assigned to a user, with whether each came from a direct or group assignment."""
    r = requests.get(f"{ORG}/api/v1/users/{_q(user)}", headers=_headers(), timeout=30)
    if r.status_code == 404:
        return {"error": "User not found"}
    r.raise_for_status()
    uid = r.json()["id"]
    params = {"filter": f'user.id eq "{uid}"', "expand": f"user/{uid}", "limit": 200}
    apps, truncated = _get_all(f"{ORG}/api/v1/apps", params)
    out = []
    for a in apps:
        au = (a.get("_embedded") or {}).get("user") or {}
        out.append({
            **_slim_app(a),
            "assignment": au.get("scope"),  # USER = assigned directly, GROUP = inherited from a group
            "assignment_status": au.get("status"),
            "app_username": (au.get("credentials") or {}).get("userName"),
            "assigned": au.get("created"),
        })
    return {"user_id": uid, "app_count": len(out), "truncated": truncated, "apps": out}


def get_app_assignments(app):
    """Users and groups assigned to an app. Logins, assignment type and status only."""
    a = _resolve_app(app)
    if a.get("error"):
        return a
    base = f"{ORG}/api/v1/apps/{a['id']}"
    groups, groups_truncated = _get_all(f"{base}/groups", {"limit": 200, "expand": "group"})
    users, users_truncated = _get_all(f"{base}/users", {"limit": 500, "expand": "user"})
    slim_users = [{
        "user_id": u.get("id"),
        "login": (((u.get("_embedded") or {}).get("user") or {}).get("profile") or {}).get("login"),
        "app_username": (u.get("credentials") or {}).get("userName"),
        "assignment": u.get("scope"),  # USER = assigned directly, GROUP = inherited from a group
        "status": u.get("status"),
        "assigned": u.get("created"),
    } for u in users]
    return {
        "app": a,
        "group_count": len(groups),
        "groups": [{
            "group_id": g.get("id"),
            "name": (((g.get("_embedded") or {}).get("group") or {}).get("profile") or {}).get("name"),
            "priority": g.get("priority"),
        } for g in groups],
        "user_count": len(slim_users),
        "users_by_assignment": _top(collections.Counter(u["assignment"] for u in slim_users)),
        "users_by_status": _top(collections.Counter(u["status"] for u in slim_users)),
        "truncated": users_truncated or groups_truncated,
        "note": f"Showing {ASSIGNEE_SAMPLE} of {len(slim_users)} users." if len(slim_users) > ASSIGNEE_SAMPLE else None,
        "users": slim_users[:ASSIGNEE_SAMPLE],
    }


TOOL_FUNCS = {
    "search_logs": search_logs,
    "get_user_status": get_user_status,
    "get_user_authenticators": get_user_authenticators,
    "find_apps": find_apps,
    "get_user_apps": get_user_apps,
    "get_app_assignments": get_app_assignments,
}

TOOLS = [
    {
        "name": "search_logs",
        "description": (
            "Search Okta System Log (read-only). Auto-paginates and returns totals, breakdowns "
            "(event, result, reason, IP, country, app) plus a sample of recent events. "
            "Useful eventType values: user.session.start (sign-in), user.authentication.auth_via_mfa, "
            "user.authentication.sso, user.account.lock, user.mfa.factor.activate, "
            "policy.evaluate_sign_on, security.threat.detected. Use outcome=FAILURE for failures. "
            "Max lookback 168 hours. If truncated=true, narrow the query."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "description": "Actor login/email"},
                "event_type": {"type": "string"},
                "outcome": {"type": "string", "enum": ["SUCCESS", "FAILURE", "SKIPPED", "ALLOW", "DENY", "CHALLENGE", "UNKNOWN"]},
                "hours_back": {"type": "integer"},
                "keyword": {"type": "string", "description": "Free-text q search"},
            },
        },
    },
    {
        "name": "get_user_status",
        "description": "Get a user's account state (ACTIVE, LOCKED_OUT, SUSPENDED, PASSWORD_EXPIRED, DEPROVISIONED...) and key timestamps (lastLogin, passwordChanged, statusChanged).",
        "input_schema": {"type": "object", "properties": {"user": {"type": "string", "description": "Login/email or Okta user ID"}}, "required": ["user"]},
    },
    {
        "name": "get_user_authenticators",
        "description": "List the authenticators/factors a user has enrolled (Okta Verify push, FastPass, passkey/WebAuthn, TOTP, SMS, etc.) with status. Use when diagnosing MFA failures or lockouts.",
        "input_schema": {"type": "object", "properties": {"user": {"type": "string", "description": "Login/email or Okta user ID"}}, "required": ["user"]},
    },
    {
        "name": "find_apps",
        "description": "Search Okta app integrations by label/name (prefix match), or list apps when query is omitted. Returns id, label, status (ACTIVE/INACTIVE) and sign-on mode. Use to resolve an app name to its id.",
        "input_schema": {"type": "object", "properties": {"query": {"type": "string", "description": "Start of the app label, e.g. 'Salesforce'"}}},
    },
    {
        "name": "get_user_apps",
        "description": "List the apps assigned to a user. assignment=USER means assigned directly, GROUP means inherited from a group. Use for 'what apps does X have' or 'does X have access to Y'.",
        "input_schema": {"type": "object", "properties": {"user": {"type": "string", "description": "Login/email or Okta user ID"}}, "required": ["user"]},
    },
    {
        "name": "get_app_assignments",
        "description": "List the groups and users assigned to an app, with counts by assignment type (USER direct / GROUP inherited) and status. Use for 'who has access to app Y' or 'which groups grant app Y'. If truncated=true, counts are a lower bound.",
        "input_schema": {"type": "object", "properties": {"app": {"type": "string", "description": "App label or Okta app ID (0oa...)"}}, "required": ["app"]},
    },
]

SYSTEM = (
    "You are OASIS (Okta Access Security Intelligence System), a read-only IAM troubleshooting assistant for Okta. "
    "Use the tools to investigate. "
    "Start with get_user_status when a specific user is named; check authenticators when MFA is involved; "
    "use search_logs for the timeline. For app access questions use get_user_apps (one user) or "
    "get_app_assignments (one app), and say whether access is direct or via a group. Summarize: what happened, the pattern (IPs, apps, factor, reason codes), "
    "likely cause, and a suggested next step. Say when results were truncated. "
    "Never claim certainty the data doesn't support. You cannot change anything."
)


def audit(name, args, user=None):
    entry = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(), "tool": name, "args": args}
    if user:
        entry["user"] = user  # set by the web front end (app.py), where several people share one deployment
    with open("agent_audit.log", "a") as f:
        f.write(json.dumps(entry) + "\n")


def ask(client, messages, question):
    """Run one question to completion. Appends to messages so follow-ups keep context."""
    messages.append({"role": "user", "content": question})
    for _ in range(8):  # hard loop cap
        print("[asking OASIS...]", file=sys.stderr, flush=True)
        resp = client.messages.create(model=MODEL, max_tokens=2000, system=SYSTEM, tools=TOOLS, messages=messages)
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            print("".join(b.text for b in resp.content if b.type == "text"))
            return
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                audit(b.name, b.input)
                print(f"[calling Okta: {b.name} {json.dumps(b.input)}]", file=sys.stderr, flush=True)
                try:
                    out = TOOL_FUNCS[b.name](**b.input)
                except Exception as ex:
                    out = {"error": str(ex)}
                if isinstance(out, dict) and out.get("error"):
                    print(f"[Okta error: {out['error']}]", file=sys.stderr, flush=True)
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": json.dumps(out)})
        messages.append({"role": "user", "content": results})
    print("Stopped: too many tool calls.")


def chat(client):
    """Interactive prompt. Follow-up questions share context until 'new' clears it."""
    print("OASIS: Okta Access Security Intelligence System (read-only). Type a question, 'new' to start a fresh conversation, 'exit' to quit.")
    messages = []
    while True:
        try:
            question = input("\noasis> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not question:
            continue
        if question.lower() in ("exit", "quit"):
            return
        if question.lower() == "new":
            messages = []
            print("Started a new conversation.")
            continue
        checkpoint = len(messages)
        try:
            ask(client, messages, question)
        except KeyboardInterrupt:
            del messages[checkpoint:]  # drop the half-finished turn so the history stays valid
            print("\nCancelled.")
        except Exception as ex:
            del messages[checkpoint:]
            print(f"Error: {ex}")


if __name__ == "__main__":
    client = anthropic.Anthropic()
    if len(sys.argv) > 1:
        ask(client, [], " ".join(sys.argv[1:]))
    else:
        chat(client)
