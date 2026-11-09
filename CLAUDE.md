# AccessProof — Claude Code project orientation

Read [AGENTS.md](AGENTS.md) **first**. Then load [docs/knowledge-graph/graph.json](docs/knowledge-graph/graph.json) and [docs/knowledge-graph/README.md](docs/knowledge-graph/README.md).

Use graph node `source_paths` to reach current code; trace `edges` and `workflows` to understand dependencies and enforcement boundaries. Never treat the graph, stale README snapshots, or synthetic tests as live security certification. Follow the security and deployment constraints in `AGENTS.md`. For Next.js work also read `web-v2/AGENTS.md`.
