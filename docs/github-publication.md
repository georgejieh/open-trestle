# GitHub review publication

`adapters/scm/github.PublicationAdapter` posts a review to a GitHub pull request and looks up the pull request's current head commit. It can be called only through the existing publication gates: authorization, an exclusive claim on the publication, audited retries and a fresh check of the head commit. Live GitHub publication is unverified (see the [roadmap](roadmap.md#available-now)). Nothing is published unless an operator runs `trestled` with `--github-enable-publication` and a publication token.

## Matching the target

The adapter is configured with one publisher ID and one repository authority. A target must match both and must have a valid GitHub owner and repository name, a canonical positive pull-request number and a full Git commit ID. Every request to look up the head or publish a review also carries a scope that names the tenant, the repository and the review run. That scope must match the publication plan and the exclusive claim before the adapter is called.

The head lookup uses `GET /repos/{owner}/{repo}/pulls/{number}`. It parses the response and rebuilds a full SHA-1 or SHA-256 commit ID, using the algorithm that the authorized target fixes. The core reconciliation gate compares this observation with the reviewed head and requires a fresh, audited match within two seconds of dispatch.

After any wait for the guard or for a credential, and immediately before it sends the request, the adapter checks the grant, the attempt and the head gate again. The HTTP call uses the time left on the grant and the head check, or an earlier deadline from the caller. A timeout does not show that GitHub rejected a request that was already sent, and the head comparison is not atomic with the publish.

## Writing the review

Publication uses `POST /repos/{owner}/{repo}/pulls/{number}/reviews` with these fields:

- The authorized head as `commit_id`.
- `COMMENT` as the event, not `APPROVE` or `REQUEST_CHANGES`.
- Inline comments, only for findings selected as inline-ready.
- All summary-only findings in the review body.
- An operation marker derived from the authorization.

A finding on removed base lines is summary-only. It is labelled `` `path` removed base lines a-b ``. An inline comment anchors on head lines (side `RIGHT`), because GitHub numbers the left side of a diff from the merge base, which need not be the reviewed base revision. Selection and plan validation refuse an inline finding on the base side, and the adapter refuses to build one.

Only verified findings that the authorized publication plan contains go into the request. The adapter checks the review ID and commit ID that GitHub returns, and it hashes the external review reference before returning it to the runtime.

Before GitHub interprets any Markdown, the renderer neutralizes user mentions, HTML, image syntax, emphasis, links, headings, code delimiters and table syntax. The request is rejected if the body or the complete JSON exceeds its size limit. Provider error bodies are discarded and do not appear in results.

## Retries and unknown outcomes

GitHub's create-review endpoint has no documented idempotency key, so the adapter cannot ask GitHub to ignore a repeated request. Instead it requires a `review.PublicationAttemptGuard`. Before the HTTP request starts, the guard durably claims the scope, operation key, attempt identity and request digest.

`adapters/storage/postgres.Store` implements this guard. Migration `0006_publication_attempts.sql` stores attempt metadata that contains no content, under forced row-level security. A repeat of the same attempt cannot be dispatched again, and a request that does not match its claim is a conflict. When an attempt completes, only the result identity is recorded.

If the process stops after the claim but before dispatch, the attempt can stay claimed permanently. This avoids posting a duplicate review. A network error or an unexpected provider response is a permanent provider failure, because the adapter cannot tell whether GitHub applied the review, so that attempt is not retried. A rate-limit response with a `Retry-After` value had no effect, so it can enter the separately audited retry flow with a new attempt identity.

## Credentials and transport

`PublicationTokenProvider` retrieves a token for the review scope and target at request time. `StaticPublicationTokenProvider` supports a registry that maps each scope to its target, for direct configuration. Secrets are redacted when formatted, and the adapter does not store tokens.

The token needs the GitHub pull-request repository permission `write`. The head lookup needs `read`. The adapter recommends `Accept: application/vnd.github+json`, sends the configured `X-GitHub-Api-Version` and defaults to `2026-03-10`. It rejects redirects, and it requires HTTPS except for an IP-literal loopback test endpoint. Request time, response headers, response bodies, error bodies and generated review payloads have size or time limits.

The prepared GitHub planner requires a publisher implementation ID. That ID is part of the planner identity and of the protected publication input, and Open Trestle does not infer it from a global default when it runs. The PostgreSQL attempt guard holds a fence across the whole operation key, so a later attempt identity cannot repeat a review `POST` that is in flight or already complete.

The implementation follows GitHub's official REST documentation:

- <https://docs.github.com/en/rest/pulls/reviews?apiVersion=2022-11-28#create-a-review-for-a-pull-request>
- <https://docs.github.com/en/rest/pulls/pulls?apiVersion=2022-11-28#get-a-pull-request>
- <https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api?apiVersion=2022-11-28>
