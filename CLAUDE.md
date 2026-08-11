# Go Project Rules

Extends my global rules. Go idioms (errors, concurrency, interfaces, testing methodology) are handled by the installed samber/cc-skills-golang skills. Do not restate them here. gofmt and golangci-lint own formatting, imports, and mechanical naming.

## Commands
- Build: `go build ./...`
- Test: `go test -race ./...`
- Lint: `golangci-lint run`
- Vet: `go vet ./...`

## Tests
- Do not create or modify _test.go files unless I explicitly ask.
- When I do ask for tests, follow the skill's testing methodology.
- Never add a test as a side effect of another task.

## Verification gate
- Before claiming done: build passes, go vet clean, golangci-lint clean, and existing tests pass with -race.
- Report the actual command output, not an assumption.
- If no tests exist for the changed code, say so plainly. Do not write them to close the gap unless asked.

## Repo specifics
- Module `cf-tools`, single `main` package in `main.go`. No internal packages.
- Stdlib `net/http` only. No web framework. Non-stdlib deps are `flynn/noise` and `x/crypto` for the WARP WireGuard handshake.
- There are no `_test.go` files in this repo. Say so rather than implying tests ran.
- The CDN probe must send a Cloudflare-fronted `Host` header (`traceHost`). A bare-IP request to `/cdn-cgi/trace` gets `403 error 1003`, which silently produces a near-empty `all_cdn_v4.txt` instead of failing. The path has no trailing slash; the trailing-slash form 404s.
- The workflow's `test -s` output check passes on a single line, so a near-empty result still publishes a release. Judge a run by its line count, not by CI being green.