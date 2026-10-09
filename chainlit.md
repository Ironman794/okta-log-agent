# OASIS

**Okta Access Security Intelligence System**: a read-only Okta troubleshooting assistant.

Ask a question in plain English, for example:

- Why is jdoe@example.com failing to sign in today?
- What authenticators does jdoe@example.com have enrolled?
- Who has access to Salesforce, and through which groups?

Follow-up questions share context. Use **New Chat** to start over.

OASIS cannot change anything in Okta. Your questions and the Okta data needed to answer them are sent to the Anthropic API, and every lookup is logged with your sign-in name.
