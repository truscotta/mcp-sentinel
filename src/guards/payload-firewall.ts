import { Buffer } from 'node:buffer';
import { URL } from 'node:url';
import { compileSafeRegex } from '../dsl/analyzer.js';
import { matchToolGlob } from '../ifc/security-lattice.js';
import { createSentinelError, type SentinelError } from '../types/errors.js';
import { isJsonObject, type JsonObject, type JsonValue } from '../types/jsonrpc.js';
import type { PayloadFirewallConfig } from '../types/policy.js';
import { err, ok, type Result } from '../types/result.js';

export interface FirewallInspectionReport {
  readonly payloadBytes: number;
  readonly maxObservedDepth: number;
}

const DANGEROUS_URI_SCHEMES: ReadonlySet<string> = new Set([
  'file:',
  'gopher:',
  'dict:',
  'ftp:',
  'ldap:',
  'ldaps:',
  'tftp:',
]);

const INTERNAL_HOSTNAMES: ReadonlySet<string> = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'metadata.internal',
  'instance-data',
  'kubernetes.default',
  'kubernetes.default.svc',
  'kubernetes.default.svc.cluster.local',
]);

const SENSITIVE_SYSTEM_PATHS: readonly string[] = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/hosts',
  '/proc/self/environ',
  '/proc/self/cmdline',
  '.ssh/id_rsa',
  '.ssh/id_ed25519',
  '.aws/credentials',
];

function parseIpv4ToUint32(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return null;
  }
  let acc = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return null;
    }
    const octet = Number.parseInt(part, 10);
    if (octet < 0 || octet > 255) {
      return null;
    }
    acc = ((acc << 8) | octet) >>> 0;
  }
  return acc >>> 0;
}

function isPrivateOrReservedIpv4Uint32(addr: number): boolean {
  const u = addr >>> 0;
  // 0.0.0.0/8 (Current network)
  if ((u & 0xff000000) >>> 0 === 0x00000000) return true;
  // 10.0.0.0/8 (RFC1918 Private)
  if ((u & 0xff000000) >>> 0 === 0x0a000000) return true;
  // 100.64.0.0/10 (Carrier-Grade NAT & Cloud Metadata 100.100.100.200)
  if ((u & 0xffc00000) >>> 0 === 0x64400000) return true;
  // 127.0.0.0/8 (Loopback)
  if ((u & 0xff000000) >>> 0 === 0x7f000000) return true;
  // 169.254.0.0/16 (Link-Local & AWS/GCP/Azure IMDS 169.254.169.254)
  if ((u & 0xffff0000) >>> 0 === 0xa9fe0000) return true;
  // 172.16.0.0/12 (RFC1918 Private)
  if ((u & 0xfff00000) >>> 0 === 0xac100000) return true;
  // 192.0.0.0/24 (IETF Protocol Assignments)
  if ((u & 0xffffff00) >>> 0 === 0xc0000000) return true;
  // 192.168.0.0/16 (RFC1918 Private)
  if ((u & 0xffff0000) >>> 0 === 0xc0a80000) return true;
  // 198.18.0.0/15 (Benchmarking)
  if ((u & 0xfffe0000) >>> 0 === 0xc6120000) return true;
  // 224.0.0.0/4 & 240.0.0.0/4 (Multicast, Reserved & Broadcast)
  if ((u & 0xe0000000) >>> 0 === 0xe0000000) return true;
  return false;
}

/**
 * RFC-4291 128-bit IPv6 parser supporting `::` zero compression and embedded
 * trailing IPv4 dotted-quads (e.g., `::ffff:169.254.169.254` and `::ffff:a9fe:a9fe`).
 */
function parseIpv6Words(rawHost: string): Uint16Array | null {
  const withoutZone = rawHost.split('%')[0] ?? rawHost;
  if (!withoutZone.includes(':')) {
    return null;
  }

  let working = withoutZone;
  let embeddedIpv4Words: [number, number] | null = null;

  const lastColon = working.lastIndexOf(':');
  const tail = working.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseIpv4ToUint32(tail);
    if (v4 === null) {
      return null;
    }
    embeddedIpv4Words = [(v4 >>> 16) & 0xffff, v4 & 0xffff];
    working = `${working.slice(0, lastColon)}:0:0`;
  }

  const doubleColonParts = working.split('::');
  if (doubleColonParts.length > 2) {
    return null;
  }

  const parseSide = (segment: string): number[] | null => {
    if (segment.length === 0) {
      return [];
    }
    const tokens = segment.split(':');
    const nums: number[] = [];
    for (const tok of tokens) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(tok)) {
        return null;
      }
      nums.push(Number.parseInt(tok, 16));
    }
    return nums;
  };

  const words = new Uint16Array(8);
  if (doubleColonParts.length === 2) {
    const left = parseSide(doubleColonParts[0] ?? '');
    const right = parseSide(doubleColonParts[1] ?? '');
    if (left === null || right === null || left.length + right.length > 8) {
      return null;
    }
    for (let i = 0; i < left.length; i += 1) {
      words[i] = left[i] ?? 0;
    }
    const rightStart = 8 - right.length;
    for (let i = 0; i < right.length; i += 1) {
      words[rightStart + i] = right[i] ?? 0;
    }
  } else {
    const full = parseSide(working);
    if (full === null || full.length !== 8) {
      return null;
    }
    for (let i = 0; i < 8; i += 1) {
      words[i] = full[i] ?? 0;
    }
  }

  if (embeddedIpv4Words !== null) {
    words[6] = embeddedIpv4Words[0];
    words[7] = embeddedIpv4Words[1];
  }

  return words;
}

function isPrivateOrReservedIpv6(words: Uint16Array): boolean {
  const w0 = words[0] ?? 0;
  const w1 = words[1] ?? 0;
  const w2 = words[2] ?? 0;
  const w3 = words[3] ?? 0;
  const w4 = words[4] ?? 0;
  const w5 = words[5] ?? 0;
  const w6 = words[6] ?? 0;
  const w7 = words[7] ?? 0;

  // Unspecified ::/128 or Loopback ::1/128
  if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0 && w6 === 0) {
    if (w7 === 0 || w7 === 1) {
      return true;
    }
  }

  // IPv4-mapped IPv6 ::ffff:0:0/96 and IPv4-compatible ::/96
  if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && (w5 === 0xffff || w5 === 0)) {
    const mappedV4 = (((w6 << 16) >>> 0) | w7) >>> 0;
    if (isPrivateOrReservedIpv4Uint32(mappedV4)) {
      return true;
    }
  }

  // NAT64 well-known prefix 64:ff9b::/96 wrapping private IPv4
  if (w0 === 0x0064 && w1 === 0xff9b && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0) {
    const embeddedV4 = (((w6 << 16) >>> 0) | w7) >>> 0;
    if (isPrivateOrReservedIpv4Uint32(embeddedV4)) {
      return true;
    }
  }

  // Unique Local Address fc00::/7
  if ((w0 & 0xfe00) === 0xfc00) return true;
  // Link-Local Unicast fe80::/10
  if ((w0 & 0xffc0) === 0xfe80) return true;
  // Multicast ff00::/8
  if ((w0 & 0xff00) === 0xff00) return true;

  return false;
}

function checkHostForSsrf(rawHostname: string): string | null {
  const unbracketed =
    rawHostname.startsWith('[') && rawHostname.endsWith(']')
      ? rawHostname.slice(1, -1)
      : rawHostname;
  const host = unbracketed.trim().toLowerCase().replace(/\.$/, '');
  if (host.length === 0) {
    return null;
  }

  if (
    INTERNAL_HOSTNAMES.has(host) ||
    host.endsWith('.localhost') ||
    host.endsWith('.internal') ||
    host.endsWith('.svc.cluster.local')
  ) {
    return `Internal hostname "${host}" is forbidden`;
  }

  const ipv4 = parseIpv4ToUint32(host);
  if (ipv4 !== null && isPrivateOrReservedIpv4Uint32(ipv4)) {
    return `Private, loopback, or cloud-metadata IPv4 address "${host}" is forbidden`;
  }

  const ipv6 = parseIpv6Words(host);
  if (ipv6 !== null && isPrivateOrReservedIpv6(ipv6)) {
    return `Private, loopback, or IPv4-mapped IPv6 address "${host}" is forbidden`;
  }

  return null;
}

function detectSsrfInString(value: string): string | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return null;
  }

  // Check URI strings (WHATWG URL normalizes decimal/octal/hex IPv4 & IPv4-mapped IPv6!)
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    try {
      const parsedUrl = new URL(trimmed);
      const protocol = parsedUrl.protocol.toLowerCase();
      if (DANGEROUS_URI_SCHEMES.has(protocol)) {
        return `Dangerous URI scheme "${protocol}" is forbidden`;
      }
      const hostViolation = checkHostForSsrf(parsedUrl.hostname);
      if (hostViolation !== null) {
        return hostViolation;
      }
    } catch {
      return `Malformed URI rejected by SSRF parser: "${trimmed.slice(0, 80)}"`;
    }
  }

  // Also check bare IP literals passed directly as `host` / `ip` string fields
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(trimmed) || trimmed.includes('::')) {
    const bareCheck = checkHostForSsrf(trimmed);
    if (bareCheck !== null) {
      return bareCheck;
    }
  }

  return null;
}

function detectPathTraversalInString(value: string): string | null {
  if (value.includes('\0') || value.toLowerCase().includes('%00')) {
    return 'Null-byte path injection detected';
  }

  let normalized = value;
  if (normalized.includes('%')) {
    try {
      normalized = decodeURIComponent(normalized);
    } catch {
      // Keep original string when percent sequence is unrelated to URI encoding
    }
  }

  if (/(?:^|[\\/])\.\.(?:[\\/]|$)/.test(normalized)) {
    return 'Relative directory traversal sequence ("../" or "..\\") is forbidden';
  }

  const lower = normalized.toLowerCase().replace(/\\/g, '/');
  for (const sensitivePath of SENSITIVE_SYSTEM_PATHS) {
    if (lower.includes(sensitivePath)) {
      return `Access to sensitive system path "${sensitivePath}" is forbidden`;
    }
  }

  return null;
}

/**
 * Zero-Trust Payload & Network Firewall enforcing tool allowlists/denylists,
 * payload byte/depth ceilings, RFC-4291 IPv4/IPv6 SSRF prevention, path traversal
 * sanitization, and ReDoS-checked custom pattern blocks.
 */
export class PayloadFirewall {
  private readonly config: PayloadFirewallConfig;
  private readonly compiledBlockedPatterns: readonly {
    readonly raw: string;
    readonly regex: RegExp;
  }[];

  private constructor(
    config: PayloadFirewallConfig,
    compiledBlockedPatterns: readonly { readonly raw: string; readonly regex: RegExp }[],
  ) {
    this.config = config;
    this.compiledBlockedPatterns = compiledBlockedPatterns;
  }

  public static create(config: PayloadFirewallConfig): Result<PayloadFirewall, SentinelError> {
    const compiled: { readonly raw: string; readonly regex: RegExp }[] = [];
    for (const rawPattern of config.blockedPatterns) {
      const regexRes = compileSafeRegex(rawPattern);
      if (!regexRes.ok) {
        return regexRes;
      }
      compiled.push({ raw: rawPattern, regex: regexRes.value });
    }
    return ok(new PayloadFirewall(config, compiled));
  }

  public inspectToolCall(
    toolName: string,
    args: JsonObject,
  ): Result<FirewallInspectionReport, SentinelError> {
    // 1. Denylist takes strict precedence
    if (this.config.deniedTools !== undefined) {
      for (const pattern of this.config.deniedTools) {
        if (matchToolGlob(pattern, toolName)) {
          return err(
            createSentinelError(
              'POLICY_VIOLATION',
              `Tool "${toolName}" is explicitly denied by firewall policy ("${pattern}")`,
              'payload-firewall',
              { toolName, matchedDenylist: pattern },
            ),
          );
        }
      }
    }

    // 2. Allowlist enforcement (when configured)
    if (
      this.config.allowedTools !== undefined &&
      !this.config.allowedTools.some((pattern) => matchToolGlob(pattern, toolName))
    ) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Tool "${toolName}" is not listed in firewall allowedTools`,
          'payload-firewall',
          { toolName },
        ),
      );
    }

    // 3. Payload byte size check
    const serialized = JSON.stringify(args);
    const payloadBytes = Buffer.byteLength(serialized, 'utf8');
    if (payloadBytes > this.config.maxPayloadBytes) {
      return err(
        createSentinelError(
          'POLICY_VIOLATION',
          `Tool "${toolName}" payload size (${payloadBytes} bytes) exceeds firewall limit (${this.config.maxPayloadBytes} bytes)`,
          'payload-firewall',
          { toolName, payloadBytes, maxPayloadBytes: this.config.maxPayloadBytes },
        ),
      );
    }

    // 4. Deep recursive tree inspection for depth, SSRF, Path Traversal & custom patterns
    let maxObservedDepth = 0;

    const inspectString = (text: string, fieldPath: string): SentinelError | null => {
      if (this.config.blockSsrf) {
        const ssrfReason = detectSsrfInString(text);
        if (ssrfReason !== null) {
          return createSentinelError(
            'POLICY_VIOLATION',
            `SSRF firewall blocked "${toolName}" at ${fieldPath}: ${ssrfReason}`,
            'payload-firewall',
            { toolName, fieldPath, category: 'SSRF' },
          );
        }
      }

      if (this.config.blockPathTraversal) {
        const pathReason = detectPathTraversalInString(text);
        if (pathReason !== null) {
          return createSentinelError(
            'POLICY_VIOLATION',
            `Path firewall blocked "${toolName}" at ${fieldPath}: ${pathReason}`,
            'payload-firewall',
            { toolName, fieldPath, category: 'PATH_TRAVERSAL' },
          );
        }
      }

      for (const entry of this.compiledBlockedPatterns) {
        if (entry.regex.test(text)) {
          return createSentinelError(
            'POLICY_VIOLATION',
            `Blocked payload pattern matched on "${toolName}" at ${fieldPath}`,
            'payload-firewall',
            { toolName, fieldPath, category: 'BLOCKED_PATTERN', pattern: entry.raw },
          );
        }
      }

      return null;
    };

    const walk = (node: JsonValue, path: string, depth: number): SentinelError | null => {
      if (depth > maxObservedDepth) {
        maxObservedDepth = depth;
      }
      if (depth > this.config.maxDepth) {
        return createSentinelError(
          'POLICY_VIOLATION',
          `Payload nesting depth (${depth}) exceeds firewall maximum (${this.config.maxDepth}) at ${path}`,
          'payload-firewall',
          { toolName, fieldPath: path, maxDepth: this.config.maxDepth },
        );
      }

      if (node === null || typeof node === 'number' || typeof node === 'boolean') {
        return null;
      }

      if (typeof node === 'string') {
        return inspectString(node, path);
      }

      if (Array.isArray(node)) {
        for (let i = 0; i < node.length; i += 1) {
          const elem = node[i];
          if (elem !== undefined) {
            const violation = walk(elem, `${path}[${i}]`, depth + 1);
            if (violation !== null) {
              return violation;
            }
          }
        }
        return null;
      }

      if (isJsonObject(node)) {
        for (const [key, val] of Object.entries(node)) {
          const keyViolation = inspectString(key, `${path}.${key}(key)`);
          if (keyViolation !== null) {
            return keyViolation;
          }
          if (val !== undefined) {
            const valViolation = walk(val, `${path}.${key}`, depth + 1);
            if (valViolation !== null) {
              return valViolation;
            }
          }
        }
      }

      return null;
    };

    const violation = walk(args, 'args', 0);
    if (violation !== null) {
      return err(violation);
    }

    return ok({
      payloadBytes,
      maxObservedDepth,
    });
  }
}
