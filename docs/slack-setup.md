# Slack setup

Slack uses conversation membership rather than document ACLs. Configure a dedicated private test channel.

The contract-tested adapter can post synthetic canary content, invite a test user, remove that user with `conversations.kick`, inspect visible private-channel membership and delete the synthetic message. The required scopes/administrative capability depend on token type and workspace plan; missing capability must be reported as unsupported rather than simulated.

Official references:
- https://docs.slack.dev/reference/methods/conversations.kick/
- https://docs.slack.dev/reference/methods/users.conversations/
