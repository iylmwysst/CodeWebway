# Contributing

## Project Scope

CodeWebway is a **personal web terminal** — a single-binary tool for one operator to access their own machine from a browser. It is not an enterprise remote access platform.

Pull requests that add the following are **out of scope** and will not be merged:

- Multi-user or team access
- User account management or role-based permissions
- Persistent server-side storage or databases
- Complex access control beyond the existing token + PIN model
- Enterprise SSO or LDAP integration

If you are unsure whether a feature fits, open an issue first to discuss before writing code.

## Build from Source

Requirements: [Rust](https://rustup.rs) 1.75+

```bash
git clone https://github.com/iylmwysst/CodeWebway
cd CodeWebway
cargo build --release
./target/release/codewebway
```

## Development Workflow

```bash
cargo run -- --pin 123456          # run locally (note: -- before app flags)
cargo build                        # debug binary
cargo test                         # run all tests
cargo fmt --all                    # format
cargo clippy --all-targets -- -D warnings  # lint
```

All three checks (test, clippy, fmt) run automatically on every push and pull request via CI.

## Commit Style

Prefixed imperative, kept atomic:

| Prefix | When to use |
|--------|-------------|
| `fix:` | Bug fix |
| `feat:` | New feature |
| `docs:` | Documentation only |
| `ux:` | UI/UX or output change |
| `build:` | Build system, CI, dependencies |

Examples:
```
fix: resolve scrollback edge case when --scrollback 0
feat: add --temp-link-max-uses flag
docs: expand threat model in SECURITY.md
```

## Pull Request Guidelines

- Keep PRs small and focused on one thing.
- Run `cargo clippy --all-targets -- -D warnings` before submitting — CI enforces this.
- Describe **the problem** in the PR body, not just what the code does.
- Add or update tests when changing behaviour.
- Security-sensitive changes must include an update to `SECURITY.md`.
