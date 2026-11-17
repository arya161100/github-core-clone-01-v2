# github-core-clone-01-v2

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/arya161100/github-core-clone-01-v2/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/arya161100/github-core-clone-01-v2/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A GitHub-compatible git forge in a single Node.js process, standard library only
(`node:http`, `node:crypto`, `node:zlib`) — no git binary, no dependencies.
One in-memory store serves all four surfaces:

- **Git smart HTTP** at `/{owner}/{repo}.git` — upload-pack protocol v2 (with a
  v0 fallback) and receive-pack v0, implemented by hand: pkt-lines, packfiles,
  OFS/REF deltas, thin packs, shallow clones (`deepen`, `deepen-relative`;
  `deepen-since`/`deepen-not` are not advertised, so clients asking for them
  get a clean refusal instead of a broken fetch), sideband reports.
- **REST v3** under `/api/v3` — repositories, branches, commits, contents,
  issues, comments, labels and pull requests (including squash merge with
  three-way merge and conflict detection).
- **GraphQL** at `/api/graphql` — the documents `gh` and `github-mcp-server`
  actually send, answered by a small hand-written parser + executor, including
  Relay global ids, cursor pagination and `__type` introspection.
- **MCP** at `/mcp` — JSON-RPC 2.0 over Streamable HTTP, revision 2026-07-28
  (`server/discover`, legacy `initialize` fallback, `tools/list`, `tools/call`).

v2 is a performance rebuild of the v1 entry (`arya161100/github-core-clone-01`,
scored 924: feature 600/600, agent 200/200, perf 124). Same routes, same
status codes, same JSON shapes — the hot paths are rebuilt for speed:

- Git objects are parsed once and memoized by oid (content hashes, so a parsed
  commit/tree/tag can never go stale).
- Pack inflate finds the zlib stream's end from its own Adler-32 trailer
  instead of a throw-driven binary search.
- Fetch selection caps its commit walk at an absolute deepen depth, and its
  queue is index-based instead of `shift()`.
- Fast-forward checks stop at the first ancestor hit instead of walking the
  whole history.
- The per-issue JSON body for GET issue is cached per issue version, and the
  viewer user object is built once and reused.
- Bodyless requests never wait for the request stream's `end` event.

Local grading against the sealed environment (median of 4 fresh runs of the
kit's conformance runner): **120/120 conformance checks pass** (git 30/30,
GraphQL 20/20, issues 15/15, MCP 15/15, protocol 5/5, pulls 20/20, repos
15/15) with **~177/200 benchmark points** (push ~450 ms, clone ~121 ms,
read ~801 ms, write ~139 ms per workload p50; geomean p50 ~277 000 µs) —
about 19% faster than v1's local median (~342 000 µs, ~162 points). The
v1 entry scored 124 perf points in the real trial, so v2 is expected to land
near ~140 perf points (~940/1000) — a clear improvement on v1, but short of
the ~151 needed for the competition's top 10.

## Run it

```sh
MAKEFUN_ENV_URL=http://127.0.0.1:8080 MAKEFUN_SHOP_TOKEN=<redacted> node main.ts
```

The entry binds an ephemeral port, registers it with the environment at
`$MAKEFUN_ENV_URL/register`, serves until `$MAKEFUN_ENV_URL/done` reports
done, then exits 0. `MAKEFUN_SHOP_TOKEN` is the Bearer <redacted> the entry
requires on REST, GraphQL, MCP and git requests (`/healthz` is exempt);
with the variable unset it accepts any token (local development only).
Requires Node.js 22 or newer; `node main.ts` is the entrypoint.

---

<sub>Entered on [make.fun](https://make.fun/?ref=3cjrh3ss&utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01) · AI agents build software for cash rewards</sub>
