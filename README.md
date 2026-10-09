# Okta Log Agent

A read-only Okta troubleshooting assistant. Ask it a question in plain English ("why is jdoe@example.com failing to sign in today?") and it queries your Okta org through Claude tool calls, then summarizes what happened, the pattern, the likely cause and a suggested next step.

It cannot change anything in Okta. It only requests read scopes and only makes GET calls.

## What it can look up

| Tool | What it does |
| --- | --- |
| `search_logs` | Searches the System Log (up to 7 days back), auto-paginates, and returns totals and breakdowns by event, result, reason, user, IP, country and app, plus a sample of recent events |
| `get_user_status` | Account state (ACTIVE, LOCKED_OUT, SUSPENDED, ...) and key timestamps |
| `get_user_authenticators` | Enrolled factors and their status (types only, no phone numbers or emails) |
| `find_apps` | Finds app integrations by label |
| `get_user_apps` | Apps assigned to a user, and whether each is direct or via a group |
| `get_app_assignments` | Users and groups assigned to an app |

## Requirements

- Python 3.10+
- An Okta org where you can create an API Services app
- An [Anthropic API key](https://console.anthropic.com/)

## Okta setup

1. In the Okta Admin Console, create an app integration of type **API Services**.
2. Set client authentication to **Public key / Private key**, generate a key pair, and save the private key (PEM or JWK) somewhere outside this repo.
3. Under **Okta API Scopes**, grant `okta.logs.read`, `okta.users.read` and `okta.apps.read`.
4. Assign the app an admin role that can read those resources (for example Read-Only Administrator).

## Install

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configure

Set these environment variables:

| Variable | Required | Description |
| --- | --- | --- |
| `OKTA_ORG_URL` | yes | For example `https://your-org.okta.com` |
| `OKTA_CLIENT_ID` | yes | Client ID of the API Services app |
| `OKTA_PRIVATE_KEY_FILE` | yes | Path to the private key (PEM or JWK) |
| `OKTA_KEY_ID` | no | Key ID (`kid`); needed if the app has more than one key |
| `OKTA_SCOPES` | no | Space-separated scopes. Defaults to `okta.logs.read okta.users.read okta.apps.read` |
| `ANTHROPIC_API_KEY` | yes | Your Anthropic API key |

## Run

Interactive, with follow-up questions sharing context:

```bash
python okta_log_agent.py
```

Type `new` to start a fresh conversation and `exit` to quit.

One question, then exit:

```bash
python okta_log_agent.py "why is jdoe@example.com failing to sign in today?"
```

## Data handling

- Tool results (log events, user logins, IP addresses, app assignments) are sent to the Anthropic API so the model can answer. Check that this is acceptable for your organization before pointing it at a production tenant.
- Every tool call is appended to `agent_audit.log` in the current directory, including the logins you asked about. That file is gitignored.
- Each query is capped at 1,000 log events and 1,000 app assignees. The agent says when results were truncated.

## License

[MIT](LICENSE)

## Disclaimer

This is a personal project and is not affiliated with or endorsed by Okta. Use a test tenant or lab data until your organization approves it.
