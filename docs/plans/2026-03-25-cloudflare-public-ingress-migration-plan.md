# Cloudflare Public Ingress Migration Plan

Date: 2026-03-25

Purpose: replace `zrok` as the public ingress layer for `CodeWebway` with Cloudflare-managed public URLs under `codewebway.com`, while preserving the current runtime, temp-link, and dashboard launch behavior.

Status: proposed implementation plan

## 1. Goal

Users should be able to install and run only `CodeWebway` and still receive a public URL for browser terminal access.

The public URL should:

- use a hostname under `codewebway.com`
- be provisioned and managed by our system
- not require the end user to install `zrok`
- not require the end user to hold Cloudflare account credentials

The migration should preserve the existing product behavior as much as possible:

- one runtime exposes one `active_url`
- temp links still work as application-level share links
- dashboard secure launch links still use the current `runtime.url` flow
- terminal, editor, auth, and session behavior remain unchanged

## 2. Non-Goals For This Phase

The following are explicitly out of scope for the first migration:

- redesigning file transfer
- creating one tunnel per share session
- changing temp-link semantics
- replacing the current dashboard launch-token model
- supporting arbitrary custom domains for end users

## 3. Recommended Architecture

Use one remotely managed Cloudflare Tunnel per machine/runtime and assign one stable public hostname per machine.

Recommended hostname form:

- `m-<machine-id>.codewebway.com`

Recommended access model:

- base runtime URL: `https://m-<machine-id>.codewebway.com`
- temp share URL: `https://m-<machine-id>.codewebway.com/t/<token>`

Why this is the best fit for the current system:

- `CodeWebway` already behaves like one runtime maps to one public URL.
- `WebWayFleet` stores a single `active_url` per machine.
- secure dashboard launch already builds on top of the runtime URL rather than on top of provider-specific behavior.
- temp links are already implemented inside the app and do not need public-hostname-per-session complexity.

## 4. Current Coupling To Remove

The current implementation is tightly coupled to `zrok` in several places:

### 4.1 `CodeWebway`

- `src/config.rs`
  - CLI flags are explicitly `--zrok`, `--public-timeout-minutes`, `--public-no-expiry`
- `src/main.rs`
  - `check_zrok_ready()`
  - `spawn_zrok()`
  - zrok token/pid tracking
  - startup banner and warnings reference zrok directly
  - fleet mode forces zrok mode
- `src/fleet.rs`
  - runtime status tracks `zrok_url_state`
  - late URL sync logic is zrok-specific by name

### 4.2 Documentation

- `README.md`
- `USAGE.md`
- `SECURITY.md`
- `CONTRIBUTING.md`

### 4.3 Legacy / Secondary Agent Path

`WebWayFleet/agent` still detects active runtime URLs from zrok token files. This needs either:

- a compatibility update, or
- an explicit statement that `CodeWebway` is the supported runtime path for this migration phase

## 5. Target Control Plane Design

### 5.1 Credential Ownership

End users should not manage Cloudflare credentials.

Credential split:

- `WebWayFleet/api` owns the Cloudflare API token and zone/account configuration
- the machine receives only machine-scoped tunnel material
- the machine does not receive account-wide Cloudflare credentials

### 5.2 Provisioning Responsibilities

`WebWayFleet/api` should provision and manage:

- tunnel creation
- tunnel metadata
- public hostname assignment
- tunnel token issuance for the machine
- tunnel revocation and cleanup on decommission

### 5.3 Machine Metadata

Store Cloudflare-specific metadata on the machine record, without changing the higher-level `active_url` contract.

Suggested fields:

- `public_provider`
- `public_hostname`
- `cloudflare_tunnel_id`
- `public_provisioned_at`
- `public_revoked_at`

The existing `active_url` remains the runtime truth used by launch and status flows.

## 6. Target Runtime Design

### 6.1 Transport Abstraction

`CodeWebway` should stop depending on `zrok` by name and introduce a generic public exposure abstraction.

Suggested conceptual model:

- `PublicExposureProvider`
- `PublicExposureHandle`
- `public_url`
- `public_url_state`
- `public_log_path`

This abstraction should own:

- provider startup
- readiness detection
- URL publication
- log capture
- graceful shutdown
- stale-process cleanup

### 6.2 Cloudflare Runtime Inputs

The local runtime needs enough material to start `cloudflared` without further user action.

Suggested local credential fields:

- `public_provider = cloudflare`
- `public_hostname`
- `cloudflare_tunnel_id`
- `cloudflare_tunnel_token`

### 6.3 Runtime Behavior To Preserve

The migration should preserve:

- localhost binding of the app server
- the current temp-link model
- the current session/token/PIN model
- the current dashboard SSO ticket model
- the current `runtime_instance_id` behavior

## 7. Repo-Level Implementation Plan

## 7.1 `CodeWebway`

### Phase 1: transport abstraction

Files:

- `src/main.rs`
- `src/config.rs`
- `src/fleet.rs`
- new module such as `src/public_exposure.rs`

Tasks:

- extract provider-specific lifecycle out of `start_server()`
- rename zrok-specific runtime fields to provider-neutral names
- centralize startup/shutdown/readiness logic behind one interface
- keep `start_server()` returning one current public URL

### Phase 2: Cloudflare provider implementation

Tasks:

- add cloudflared process manager
- add readiness detection for assigned hostname availability
- add log and child-process monitoring
- add graceful shutdown and cleanup
- keep auto-shutdown semantics aligned with current public mode behavior

### Phase 3: CLI and UX migration

Tasks:

- replace `--zrok` with provider-neutral public exposure flags
- keep a temporary deprecated alias if needed for migration
- update startup banner from `zrok` wording to `Public URL`
- make fleet mode force generic public mode instead of zrok mode

## 7.2 `WebWayFleet/api`

### Phase 1: provider integration

Suggested new module:

- `api/src/lib/cloudflare.ts`

Responsibilities:

- create tunnel
- create hostname
- issue tunnel token
- revoke/delete tunnel

Required environment variables:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_ZONE_ID`
- `PUBLIC_HOSTNAME_SUFFIX`

### Phase 2: schema and provisioning

Files:

- `api/migrations/*`
- `api/src/routes/device.ts`
- `api/src/routes/agent.ts`
- `api/src/routes/machines.ts`

Tasks:

- extend machine metadata for public ingress provider state
- provision tunnel/hostname during machine creation or enable
- return machine-scoped tunnel material at the right point in the enable flow
- support revoke/decommission cleanup

## 7.3 `WebWayFleet/dashboard`

Files:

- `dashboard/src/lib/types.ts`
- machine detail and activation pages as needed

Tasks:

- show provider-neutral public URL copy
- surface hostname where useful
- avoid zrok-branded language in the UI

Dashboard launch flow should remain largely unchanged because it still resolves `runtime.url`.

## 7.4 `WebWayFleet/agent`

Current status:

- still contains zrok-specific URL detection logic

Decision needed:

- either patch it to support provider-neutral runtime detection
- or explicitly treat it as a later follow-up if `CodeWebway` is the only supported runtime path for this project phase

## 8. Suggested Rollout Sequence

1. Add provider-neutral public exposure abstraction in `CodeWebway`
2. Add Cloudflare provisioning support in `WebWayFleet/api`
3. Extend local machine credentials to carry Cloudflare tunnel inputs
4. Implement cloudflared lifecycle in `CodeWebway`
5. Update docs and dashboard copy
6. Canary rollout on internal machines
7. Keep zrok as fallback for one release
8. Remove zrok-specific paths after validation

## 9. Validation Checklist

The migration is not done until the following work end-to-end:

- machine enable flow still succeeds
- terminal start creates a valid runtime URL
- dashboard secure launch URL still opens the runtime
- temp links still redeem correctly
- runtime stop clears `active_url`
- reconnect/restart reuses the assigned hostname correctly
- public ingress cleanup works on shutdown and decommission
- docs match the new installation story

## 10. Risks

### 10.1 Process lifecycle risk

`cloudflared` startup, readiness detection, and cleanup must be robust. A weak implementation will create stale public-ingress state or confusing runtime status.

### 10.2 Scale limits

If the system grows large, Cloudflare tunnel/account limits may matter. This architecture is still far better than per-session tunnels for the current product phase.

### 10.3 Dual-agent divergence

`CodeWebway` and `WebWayFleet/agent` may diverge if only one path is migrated. This should be handled as an explicit product decision, not left ambiguous.

### 10.4 Scope creep

Do not combine this migration with large file-transfer redesign. That should remain a separate project.

## 11. Product Positioning

This migration is worthwhile because it improves:

- installation simplicity
- product ownership of the public URL surface
- brand consistency
- long-term control over ingress behavior

The core rule for implementation is:

Replace the public transport layer, not the application behavior.
