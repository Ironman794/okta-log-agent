r"""
OASIS web front end (Chainlit): the same tools and prompt as oasis.py, behind Okta sign-in.
Each chat keeps its own conversation, and every tool call is audited with the signed-in user.

Setup:  pip install -r requirements.txt
Env:    everything oasis.py needs, plus an Okta OIDC Web app for tester sign-in:
        OAUTH_OKTA_DOMAIN=your-org.okta.com          (no https://)
        OAUTH_OKTA_CLIENT_ID=0oa...
        OAUTH_OKTA_CLIENT_SECRET=...
        OAUTH_OKTA_AUTHORIZATION_SERVER_ID=false     (org authorization server; omit to use "default")
        CHAINLIT_AUTH_SECRET=...                     (generate with: chainlit create-secret)
        CHAINLIT_URL=https://your-app.example.com    (public URL; taken from Render automatically)
        Sign-in redirect URI on the Okta app: <public URL>/auth/oauth/okta/callback
Run:    chainlit run app.py
"""
import os, sys, json, asyncio
import anthropic
import chainlit as cl

import oasis

# Render sits behind a proxy, so the OAuth redirect URI has to be built from the public URL.
if os.environ.get("RENDER_EXTERNAL_URL"):
    os.environ.setdefault("CHAINLIT_URL", os.environ["RENDER_EXTERNAL_URL"])

client = anthropic.AsyncAnthropic()


@cl.oauth_callback
async def oauth_callback(provider_id, token, raw_user_data, default_user, id_token=None):
    # Who may sign in is controlled in Okta, by assignment to the OIDC app.
    if provider_id == "okta" and default_user.identifier:
        return default_user
    return None


@cl.on_chat_start
async def start():
    cl.user_session.set("messages", [])


async def ask(messages, question, user):
    """Run one question to completion and return the answer. Mirrors oasis.ask."""
    messages.append({"role": "user", "content": question})
    for _ in range(8):  # hard loop cap
        resp = await client.messages.create(
            model=oasis.MODEL, max_tokens=2000, system=oasis.SYSTEM, tools=oasis.TOOLS, messages=messages
        )
        messages.append({"role": "assistant", "content": resp.content})
        if resp.stop_reason != "tool_use":
            return "".join(b.text for b in resp.content if b.type == "text")
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                oasis.audit(b.name, b.input, user)
                # The host's disk is not persistent, so the audit trail also goes to the service logs.
                print(f"[audit] {json.dumps({'user': user, 'tool': b.name, 'args': b.input})}", file=sys.stderr, flush=True)
                async with cl.Step(name=b.name, type="tool") as step:
                    step.input = b.input
                    try:
                        out = await cl.make_async(oasis.TOOL_FUNCS[b.name])(**b.input)
                    except Exception as ex:
                        out = {"error": str(ex)}
                    step.output = f"Okta error: {out['error']}" if isinstance(out, dict) and out.get("error") else "done"
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": json.dumps(out)})
        messages.append({"role": "user", "content": results})
    return "Stopped: too many tool calls."


@cl.on_message
async def on_message(message: cl.Message):
    user = cl.user_session.get("user").identifier
    messages = cl.user_session.get("messages")
    checkpoint = len(messages)
    try:
        answer = await ask(messages, message.content, user)
    except asyncio.CancelledError:  # the user pressed stop
        del messages[checkpoint:]  # drop the half-finished turn so the history stays valid
        raise
    except Exception as ex:
        del messages[checkpoint:]
        answer = f"Error: {ex}"
    await cl.Message(content=answer).send()
