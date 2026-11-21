## Summary

<!-- Briefly describe the architectural problem solved and the modules touched. -->

Fixes #<!-- issue-number -->

## SemVer Classification (for Release Drafter)

- [ ] `security` — Security mesh, Lattice IFC, Vault, Deception, or Macaroons enhancement
- [ ] `enhancement` / `finops` — Backwards-compatible feature or ledger improvement (`Minor`)
- [ ] `fix` / `performance` / `refactor` — Bug fix or internal optimization (`Patch`)
- [ ] `documentation` / `ci` — Docs, templates, or workflow updates
- [ ] `breaking` — Breaking API or wire-protocol change (`Major`)

## Architectural & Security Verification Checklist

- [ ] **Zero Runtime Dependencies:** `package.json` `dependencies` remains empty (`node:` built-ins only).
- [ ] **100% Strict TypeScript & Biome:** `npm run check` passes with zero `any`, zero `!` assertions, and zero warnings.
- [ ] **Explicit `Result<T, SentinelError>`:** No uncaught exceptions thrown across security or ledger boundaries.
- [ ] **Bounded Memory & Complexity:** Stateful maps enforce bounded eviction; regexes pass ReDoS safety checks; secret buffers zeroize on teardown.
- [ ] **Deterministic `VirtualClock` Tests:** Added unit/integration tests in `tests/` without `setTimeout` sleeps, maintaining V8 coverage thresholds (`npm run test:coverage`).
