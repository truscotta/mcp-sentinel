# Security Policy

`mcp-sentinel` is zero-trust security infrastructure designed to sit on the critical boundary between untrusted LLM cognition and production MCP servers. We treat every security report with the highest engineering priority.

## Supported Versions

| Version | Zero-Dependency Core | Security Advisories & Patches |
| :--- | :--- | :--- |
| `1.0.x` | Yes (`0` npm runtime deps) | Actively Supported |
| `< 1.0.0` | N/A | Unsupported |

## Reporting a Vulnerability (Private Disclosure)

**Please DO NOT open a public GitHub Issue or Pull Request for suspected security vulnerabilities.**

Instead, report vulnerabilities privately through **GitHub Private Vulnerability Reporting**:

1. Navigate to the [**Security Advisories**](https://github.com/truscotta/mcp-sentinel/security/advisories/new) page of this repository.
2. Submit a detailed report including:
   - Affected module and version (e.g., `src/vault/context-vault.ts`, `src/dsl/vm.ts`, `src/guards/payload-firewall.ts`).
   - Minimal, deterministic reproduction payload or `Vitest` test case.
   - Assessment of impact (e.g., Bell-LaPadula lattice bypass, SSRF filter evasion, SPL VM gas exhaustion, or Macaroon forgery).

## High-Priority In-Scope Surfaces

We are particularly interested in reports demonstrating:

* **SPL Bytecode VM Escapes or DoS:** Inputs bypassing `maxVmGas` metering, prototype access guards, or ReDoS static checks.
* **Dual Security Lattice Bypass:** Sequences permitting `CONFIDENTIAL`/`SECRET` vault aliases to detokenize into lower-clearance sinks, or `UNTRUSTED` inputs executing `VERIFIED` sinks.
* **Cryptographic Primitive Misuse:** Weaknesses in `AES-256-GCM` AAD binding, `HMAC-SHA256` Macaroon caveat chaining, `RFC-6962` Merkle domain separation, or `Ed25519` Signed Tree Head verification.
* **Network & Path Firewall Evasion:** Novel IPv4/IPv6/NAT64 SSRF encodings or path traversal sequences bypassing `PayloadFirewall`.
* **Unicode & Prompt Smuggling Evasion:** Unfiltered invisible codepoints or schema mutation vectors bypassing `SchemaLockGuard` or `InjectionShield`.

## Response SLA & Coordinated Disclosure

* **Initial Acknowledgment:** Within **48 hours** of submission.
* **Technical Triage & Severity Classification:** Within **5 business days**.
* **Patch & CVE/GHSA Publication:** Critical and High severity patches target release within **7–14 days**, with full reporter credit in the published GitHub Security Advisory (unless anonymity is requested).

## Safe Harbor

Good-faith security research conducted locally against your own `mcp-sentinel` instances in accordance with this policy is authorized and welcomed.
