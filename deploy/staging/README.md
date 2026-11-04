# Staging remote RAG host (validation, synthetic data)

`/etc/systemd/system/ap-rag-langchain.service` and `ap-rag-llamaindex.service` (installed 2026-11-05 via SSM)
run `examples/remote_rag_server.py` with `--evidence-subscribe` against `https://ap-gateway.lab.internal:18443`,
which is reached through the user-level tunnel unit `accessproof-remote-rag-tunnel`.

* `Restart=always`, `WantedBy=multi-user.target`.
* `sshd` drop-in `/etc/ssh/sshd_config.d/60-accessproof-tunnel-keepalive.conf` sets `ClientAliveInterval 10` and `ClientAliveCountMax 3`. A dead tunnel's remote forward is released within about 30 s, so the tunnel reconnects in under a minute instead of about 3.5 minutes.
