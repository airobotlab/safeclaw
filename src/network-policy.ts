/**
 * Container network egress whitelist (Security Layer 3)
 *
 * Restricts outbound traffic from agent containers to a configurable
 * list of allowed domains. Uses iptables inside the container to block
 * all outbound connections except to resolved IPs of allowed domains.
 *
 * Config: ~/.config/nanoclaw/network-allowlist.json
 * If no config exists, a default allowlist is used.
 */
import { execSync } from 'child_process';
import dns from 'dns/promises';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { logger } from './logger.js';

const CONFIG_DIR = path.join(
  process.env.HOME || os.homedir(),
  '.config',
  'nanoclaw',
);
const ALLOWLIST_PATH = path.join(CONFIG_DIR, 'network-allowlist.json');

const DEFAULT_ALLOWED_DOMAINS = [
  'api.anthropic.com',
  'cdn.anthropic.com',
  'sentry.io',
  'statsig.anthropic.com',
];

export interface NetworkAllowlist {
  enabled: boolean;
  allowed_domains: string[];
}

export function loadNetworkAllowlist(): NetworkAllowlist {
  if (fs.existsSync(ALLOWLIST_PATH)) {
    try {
      const data = JSON.parse(fs.readFileSync(ALLOWLIST_PATH, 'utf-8'));
      return {
        enabled: data.enabled !== false,
        allowed_domains: Array.isArray(data.allowed_domains)
          ? data.allowed_domains
          : DEFAULT_ALLOWED_DOMAINS,
      };
    } catch (err) {
      logger.warn({ err }, 'Failed to parse network allowlist, using defaults');
    }
  }
  return { enabled: true, allowed_domains: DEFAULT_ALLOWED_DOMAINS };
}

export function ensureDefaultAllowlist(): void {
  if (!fs.existsSync(ALLOWLIST_PATH)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
    const defaultConfig: NetworkAllowlist = {
      enabled: true,
      allowed_domains: DEFAULT_ALLOWED_DOMAINS,
    };
    fs.writeFileSync(ALLOWLIST_PATH, JSON.stringify(defaultConfig, null, 2) + '\n');
    logger.info({ path: ALLOWLIST_PATH }, 'Created default network allowlist');
  }
}

/**
 * Resolve allowed domains to IP addresses for iptables rules.
 */
async function resolveDomains(domains: string[]): Promise<string[]> {
  const ips = new Set<string>();
  for (const domain of domains) {
    try {
      const addrs = await dns.resolve4(domain);
      for (const addr of addrs) ips.add(addr);
    } catch {
      logger.warn({ domain }, 'Failed to resolve domain for network allowlist');
    }
    try {
      const addrs6 = await dns.resolve6(domain);
      for (const addr of addrs6) ips.add(addr);
    } catch {
      // IPv6 resolution failure is not critical
    }
  }
  return [...ips];
}

/**
 * Build Docker arguments for network egress restriction.
 * The container starts as root, applies iptables rules, then drops to node user.
 */
export async function getNetworkArgs(): Promise<string[]> {
  const policy = loadNetworkAllowlist();
  if (!policy.enabled) {
    logger.info('Network egress restriction disabled');
    return [];
  }

  const allowedIps = await resolveDomains(policy.allowed_domains);
  if (allowedIps.length === 0) {
    logger.warn('No IPs resolved for allowed domains, skipping network restriction');
    return [];
  }

  const allowedDomainsEnv = policy.allowed_domains.join(',');
  const allowedIpsEnv = allowedIps.join(',');

  logger.info(
    { domains: policy.allowed_domains, resolvedIps: allowedIps.length },
    'Network egress whitelist active',
  );

  return [
    '--cap-add=NET_ADMIN',
    '-e', `ALLOWED_EGRESS_IPS=${allowedIpsEnv}`,
    '-e', `ALLOWED_EGRESS_DOMAINS=${allowedDomainsEnv}`,
  ];
}

/**
 * Check if the container image supports iptables-based egress filtering.
 */
export function checkEgressSupport(): boolean {
  try {
    execSync('docker run --rm --cap-add=NET_ADMIN nanoclaw-agent:latest iptables -L -n 2>/dev/null', {
      stdio: 'pipe',
      timeout: 15000,
    });
    return true;
  } catch {
    return false;
  }
}
