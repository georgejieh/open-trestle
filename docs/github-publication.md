# GitHub review publication

`adapters/scm/github.PublicationAdapter` implements the source-control head resolver and review publisher contracts for GitHub pull requests. It is callable only through the existing publication authorization, exclusive claim, audited retry, and fresh-head gates.

## Exact target binding

The adapter accepts one configured publisher ID and repository authority. A target must match both, contain one valid GitHub owner segment and repository name, use a canonical positive pull-request number, and carry a full Git commit identity. Each resolver and publisher request also carries the structural tenant, repository, and review-run scope. Scope identity must match the publication plan and exclusive claim before the adapter is called.

The head resolver uses `GET /repos/{owner}/{repo}/pulls/{number}`. It parses only a bounded response and reconstructs a full SHA-1 or SHA-256 Git commit identity using the algorithm fixed by the authorized target. The core reconciliation gate compares this observation with the reviewed head and requires a fresh audited match within two seconds of dispatch. The adapter retains the full authorized request and rechecks the grant, attempt, and head gate after guard and credential waits, immediately before transport. HTTP uses only the remaining grant/head lifetime, subject to any earlier caller deadline. A timeout does not prove that GitHub rejected an already-sent request, and these checks do not provide an atomic remote-head compare-and-swap.

## Review write

Publication uses `POST /repos/{owner}/{repo}/pulls/{number}/reviews` with:

- the exact authorized head as `commit_id`
- `COMMENT` as the event, never `APPROVE` or `REQUEST_CHANGES`
- bounded inline comments only for findings selected as inline-ready
- all summary-only findings in the review body
- a deterministic operation marker derived from the authorization

Only independently verified findings contained in the authorized publication plan enter the request. The adapter checks the returned review ID and exact commit ID. It hashes the external review reference before returning it to the runtime.

Finding text remains untrusted. The renderer neutralizes user mentions, HTML, image syntax, emphasis, links, headings, code delimiters, and table syntax before GitHub interprets Markdown. The request fails closed if the body or complete JSON exceeds its bound. Provider error bodies are discarded and never enter results.

## Idempotency and ambiguous outcomes

GitHub's create-review endpoint does not accept a documented idempotency key. The adapter therefore requires a `review.PublicationAttemptGuard` that durably claims the exact scope, operation key, attempt identity, and request digest before the HTTP request starts.

`adapters/storage/postgres.Store` implements this guard. Migration `0006_publication_attempts.sql` stores content-free attempt metadata under forced row-level security. A repeated exact attempt cannot dispatch again. A cross-wired request conflicts. Completion records only the result identity.

A process stop after claim but before dispatch can leave the attempt permanently claimed. This sacrifices liveness rather than risk a duplicate external effect. A network error or unexpected provider response is classified as a permanent provider failure because the adapter cannot prove whether GitHub applied the review. It is not safe to retry that attempt. A rate-limit response with a bounded `Retry-After` value is a known no-effect result and can enter the separately audited retry flow with a new attempt identity.

## Credentials and transport

`PublicationTokenProvider` retrieves a token for the exact review scope and target at request time. `StaticPublicationTokenProvider` supports a bounded exact scope-to-target registry for direct configuration. Secret formatting is redacted. Tokens are never persisted by the adapter.

The token needs GitHub pull-request repository permission `write`. Head lookup needs `read`. The adapter recommends `Accept: application/vnd.github+json`, sends the configured `X-GitHub-Api-Version`, and defaults to `2026-03-10`. Redirects are rejected. HTTPS is required except for an IP-literal loopback test endpoint. Request time, response headers, response bodies, error bodies, and generated review payloads are bounded.

The implementation follows GitHub's official REST documentation:

- <https://docs.github.com/en/rest/pulls/reviews?apiVersion=2022-11-28#create-a-review-for-a-pull-request>
- <https://docs.github.com/en/rest/pulls/pulls?apiVersion=2022-11-28#get-a-pull-request>
- <https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api?apiVersion=2022-11-28>

The prepared GitHub planner requires an exact publisher implementation ID. That ID is part of the planner identity and protected publication input; it is not inferred from a global default during execution. The PostgreSQL attempt guard holds an operation-key-wide fence, so a later attempt identity cannot repeat an in-flight or completed GitHub review POST.
