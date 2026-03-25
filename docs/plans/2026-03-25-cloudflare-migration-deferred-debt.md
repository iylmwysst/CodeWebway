# Cloudflare Migration Deferred Debt

Date: 2026-03-25

Purpose: record intentional debt that is being deferred while the Cloudflare public-ingress migration is focused on getting the new system working first.

Status: open

## Principle

During the migration, runtime behavior and control-plane correctness take priority over wording cleanup.

This debt is intentional and should not block implementation of the working Cloudflare path.

## Deferred Items

### 1. CLI wording still references zrok

Examples:

- `--zrok`
- help text that says `Create a public URL with zrok`
- help text for `--public-timeout-minutes` and `--public-no-expiry`

Planned cleanup:

- replace provider-specific wording with provider-neutral public-ingress wording
- optionally keep temporary deprecated aliases for compatibility

### 2. Startup banner and console logs still reference zrok

Examples:

- `zrok   : <url>`
- public warning copy mentioning zrok directly
- zrok-specific log path wording

Planned cleanup:

- rename to `Public URL`
- update warnings to describe public exposure generically

### 3. Documentation still describes zrok as the current public-sharing path

Files likely requiring follow-up:

- `README.md`
- `USAGE.md`
- `SECURITY.md`
- `CONTRIBUTING.md`

Planned cleanup:

- update install story
- remove zrok prerequisite wording
- update architecture diagrams and examples

### 4. Test names and fixture URLs still use zrok terminology

Examples:

- test names containing `zrok`
- fixture URLs under `*.zrok.io`

Planned cleanup:

- rename tests to provider-neutral names where possible
- keep literal fixture URLs only when they are not semantically important

### 5. `WebWayFleet/agent` still contains zrok-specific active URL detection

This is separate from the main `CodeWebway` runtime path and should be handled after the main migration path is working.

Planned cleanup:

- either migrate it to provider-neutral runtime detection
- or explicitly mark it as unsupported for the Cloudflare rollout phase

### 6. Cloudflare fleet runtime is standardized on local origin port `8080`

Current behavior:

- Fleet-side Cloudflare ingress is provisioned against `http://localhost:8080`
- the local daemon now coerces Cloudflare-backed fleet runs to port `8080` to keep the tunnel route stable

Planned cleanup:

- document this runtime contract explicitly in user-facing docs
- decide later whether per-machine dynamic origin ports are worth supporting

## Exit Criteria For Debt Cleanup

This debt should be cleaned after:

- Cloudflare provisioning works end-to-end
- `CodeWebway` can start with Cloudflare-managed public ingress
- dashboard launch flow works against the new runtime URL
- temp links still work over the new base URL

## Rule

Do not expand this debt list to include behavior changes that block shipping a working system.
