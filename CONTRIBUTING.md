# Contributing

## Project Scope

CodeWebway is a personal remote terminal plus first-party WebWayFleet integration. The core model is still one trusted operator opening their own machine from a browser.

Changes that remain out of scope:

- multi-user shared terminals
- RBAC or account management inside CodeWebway itself
- database-backed session state inside the Rust binary
- enterprise SSO providers beyond the current signed-ticket/dashboard-owner flows
- generic remote agent features unrelated to starting/stopping CodeWebway

If a change touches the boundary between CodeWebway and WebWayFleet, treat both repos as one system and keep the contract aligned.

## Build From Source

Requirements: Rust stable (1.75+ recommended), plus `zrok` only if you are testing public sharing.

```bash
git clone https://github.com/iylmwysst/CodeWebway
cd CodeWebway
cargo build --release
./target/release/codewebway --pin 123456
```

## Development Workflow

```bash
cargo run -- --pin 123456
cargo build
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

CI in this repo currently runs:

- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt --all -- --check`

CodeQL also runs on pushes, pull requests, and a weekly schedule.

## Cross-Repo Changes

If you touch any of these areas, verify the sibling `WebWayFleet` repo at the same time:

- `src/fleet.rs`
- signed SSO ticket format
- host-login challenge flow
- machine start/stop payload fields
- runtime access token reporting
- temp-link or terminal policy fields sent from the dashboard

At minimum, update the matching API/dashboard tests or docs in `WebWayFleet` when the contract changes.

## Docs Policy

Top-level docs in this repo are expected to describe current runtime behavior.

The files under `docs/plans/` are dated design and implementation snapshots. Treat them as historical records:

- do not silently rewrite old plan docs to describe new behavior
- add a new dated plan when the architecture changes again
- update `SECURITY.md`, `USAGE.md`, and contributor docs when behavior actually changes

## Commit Style

Use the existing prefixed imperative style:

- `fix:`
- `feat:`
- `docs:`
- `ux:`
- `build:`

Keep commits atomic and avoid mixing unrelated refactors with behavior changes.

## Pull Request Guidelines

- Keep the PR scoped to one problem.
- Explain the user-visible or security-sensitive behavior change, not just the code diff.
- Add or update tests when behavior changes.
- Update `SECURITY.md` for auth, session, exposure, or secret-handling changes.
- Update docs in both repos when the CodeWebway <-> WebWayFleet contract changes.
