# Contributing to `mcp-sentinel`

Thank you for your interest in contributing to **`mcp-sentinel`**! Because enterprises rely on this runtime to prevent data exfiltration, prompt injection, and runaway LLM spend, every contribution must uphold strict architectural invariants.

---

## Non-Negotiable Engineering Invariants

1. **Zero External Runtime Dependencies (`dependencies: {}`):**
   - Runtime code inside `src/` MUST use only built-in Node.js `>=20.11` modules (`node:crypto`, `node:http`, `node:stream`, `node:buffer`, etc.) with explicit `node:` import prefixes.
   - CI automatically fails any Pull Request that adds a runtime package to `package.json`.
2. **100% Strict TypeScript & Zero `any`:**
   - All code must pass `tsc --noEmit` with `strict`, `noUncheckedIndexedAccess`, and `verbatimModuleSyntax` enabled, plus `biome lint` with `noExplicitAny: "error"` and `noNonNullAssertion: "error"`.
3. **Explicit Algebraic Error Handling (`Result<T, SentinelError>`):**
   - Never throw raw exceptions across guard, compiler, vault, or ledger boundaries. Return `ok(value)` or `err(createSentinelError(...))`.
4. **Deterministic, Zero-Sleep Unit Tests (`VirtualClock`):**
   - Never use real `setTimeout` sleeps to test TTL expiration, rate-limit refills, or circuit breaker cooldowns. Inject `VirtualClock` from `src/core/clock.ts` and advance simulated time deterministically.
5. **Bounded Memory & Algorithmic Complexity:**
   - Every stateful registry or session tracker must enforce bounded capacity (LRU eviction or TTL reaping) and linear/logarithmic execution guarantees. Secret buffers in `src/vault/` must be zeroized (`Buffer.fill(0)`) on eviction.

---

## Local Development Setup

```bash
git clone [https://github.com/truscotta/mcp-sentinel.git](https://github.com/truscotta/mcp-sentinel.git)
cd mcp-sentinel
npm install
```

### Verification Suite (Run Before Opening a PR)

```bash
# Run strict typecheck, Biome static linter, and Vitest suite
npm run check

# Verify V8 code coverage thresholds
npm run test:coverage

# Verify dual ESM/CJS + CLI production build
npm run build
```

---

## Commit & Pull Request Conventions

We follow **Conventional Commits** so automated `Release Drafter` workflows can classify SemVer releases accurately:

* `feat(vault): ...` — New capability or security control
* `fix(guards): ...` — Bug fix or bypass remediation
* `perf(dsl): ...` — Latency or allocation optimization
* `test(forensics): ...` — Test coverage additions
* `docs(readme): ...` — Documentation updates
* `ci(workflows): ...` / `chore(...): ...` — Build & CI maintenance

Keep commit subject lines concise (under 72 characters) and focused on a single atomic change.

---

## Priority Triage for Sponsors

Issues and adapter PRs submitted by **Pro Supporters**, **Silver Sponsors**, and **Gold Enterprise Partners** via [GitHub Sponsors](https://github.com/sponsors/truscotta) receive expedited review during weekly maintenance cycles.
