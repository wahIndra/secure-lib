import dns from 'node:dns/promises';
import net from 'node:net';
import { OwaspCategory, SecurityViolationError } from './owasp.js';

export class SsrfError extends SecurityViolationError {
  constructor(message) {
    super(OwaspCategory.SSRF, message);
    this.name = 'SsrfError';
  }
}

function ipv4Bytes(ip) {
  return ip.split('.').map((n) => parseInt(n, 10));
}

function isBlockedIpv4([a0, a1, a2]) {
  return (
    a0 === 0 || a0 === 10 || a0 === 127 ||
    (a0 === 100 && (a1 & 0xc0) === 64) ||       // 100.64/10 CGNAT
    (a0 === 169 && a1 === 254) ||               // link-local, cloud metadata
    (a0 === 172 && (a1 & 0xf0) === 16) ||
    (a0 === 192 && a1 === 168) ||
    (a0 === 192 && a1 === 0 && (a2 === 0 || a2 === 2)) ||
    (a0 === 198 && (a1 & 0xfe) === 18) ||       // benchmarking
    (a0 === 198 && a1 === 51 && a2 === 100) ||
    (a0 === 203 && a1 === 0 && a2 === 113) ||
    a0 >= 224                                   // multicast, reserved, broadcast
  );
}

function ipv6Bytes(ip) {
  let addr = ip;
  // Embedded dotted IPv4 tail, e.g. ::ffff:127.0.0.1
  const v4 = addr.match(/(\d+\.\d+\.\d+\.\d+)$/);
  let tail = [];
  if (v4) {
    tail = ipv4Bytes(v4[1]);
    addr = addr.slice(0, -v4[1].length) + '0:0';
  }
  const [head, rest] = addr.split('::');
  const h = head ? head.split(':') : [];
  const r = rest !== undefined && rest !== '' ? rest.split(':') : [];
  const groups = rest !== undefined ? [...h, ...Array(8 - h.length - r.length).fill('0'), ...r] : h;
  const bytes = groups.flatMap((g) => {
    const n = parseInt(g || '0', 16);
    return [(n >> 8) & 0xff, n & 0xff];
  });
  if (v4) bytes.splice(12, 4, ...tail);
  return bytes;
}

/**
 * True for loopback, private, link-local (incl. 169.254.169.254), CGNAT, multicast,
 * unspecified, documentation/benchmark ranges, IPv6 ULA/link-local and IPv6 forms that
 * embed such an IPv4 address (mapped, NAT64, 6to4).
 */
export function isBlockedAddress(ip) {
  const family = net.isIP(ip);
  if (family === 4) return isBlockedIpv4(ipv4Bytes(ip));
  if (family !== 6) return true;
  const b = ipv6Bytes(ip.toLowerCase());
  const zero = (from, to) => b.slice(from, to).every((x) => x === 0);
  if (zero(0, 16) || (zero(0, 15) && b[15] === 1)) return true;                   // :: and ::1
  if ((b[0] & 0xfe) === 0xfc) return true;                                         // fc00::/7
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;                        // fe80::/10
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return true;                        // fec0::/10
  if (b[0] === 0xff) return true;                                                  // multicast
  if (zero(0, 10) && b[10] === 0xff && b[11] === 0xff) return isBlockedIpv4(b.slice(12)); // mapped
  if (zero(0, 12)) return true;                                                    // IPv4-compatible
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return isBlockedIpv4(b.slice(12)); // NAT64
  if (b[0] === 0x20 && b[1] === 0x02) return isBlockedIpv4(b.slice(2, 6));         // 6to4
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true; // documentation
  return false;
}

const defaultResolver = async (host) => {
  if (net.isIP(host)) return [host];
  const records = await dns.lookup(host, { all: true, verbatim: true });
  return records.map((r) => r.address);
};

/**
 * Validates outbound URLs built from user input (webhooks, image fetchers, link previews).
 * Every resolved address is checked. To stop DNS rebinding, connect to the returned
 * `addresses` (e.g. via a custom `lookup`) and disable redirects or validate each hop.
 *
 * @example
 * const guard = new UrlGuard({ allowHosts: ['api.partner.com', '*.cdn.example.com'] });
 * const { url, addresses } = await guard.validate(userUrl);   // throws SsrfError
 */
export class UrlGuard {
  constructor({
    schemes = ['http', 'https'],
    allowHosts = [],
    ports = [80, 443],
    allowPrivateNetworks = false,
    resolver = defaultResolver,
  } = {}) {
    this.schemes = new Set(schemes.map((s) => s.toLowerCase()));
    this.hosts = allowHosts.map((h) => h.toLowerCase());
    this.ports = new Set(ports);
    this.allowPrivate = allowPrivateNetworks;
    this.resolver = resolver;
  }

  async validate(rawUrl) {
    if (typeof rawUrl !== 'string' || rawUrl.length > 2048) throw new SsrfError('missing or oversized URL');
    if (/[\u0000- \u007f\\]/.test(rawUrl)) throw new SsrfError('control character, space or backslash in URL');
    let url;
    try {
      url = new URL(rawUrl);
    } catch {
      throw new SsrfError('malformed URL');
    }
    const scheme = url.protocol.replace(/:$/, '').toLowerCase();
    if (!this.schemes.has(scheme)) throw new SsrfError('scheme not allowed');
    if (url.username || url.password || /^[a-z]+:\/\/[^/?#]*@/i.test(rawUrl)) throw new SsrfError('credentials in URL are not allowed');
    let host = url.hostname.toLowerCase();
    if (!host) throw new SsrfError('URL has no host');
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
    host = host.replace(/\.+$/, '');
    if (host.includes('%')) throw new SsrfError('IPv6 zone id not allowed');
    if (this.hosts.length && !this.#hostAllowed(host)) throw new SsrfError('host not in allowlist');
    const port = url.port ? Number(url.port) : scheme === 'https' ? 443 : 80;
    if (!this.ports.has(port)) throw new SsrfError('port not allowed');

    let addresses;
    try {
      addresses = await this.resolver(host);
    } catch {
      throw new SsrfError('host does not resolve');
    }
    if (!addresses?.length) throw new SsrfError('host does not resolve');
    if (!this.allowPrivate && addresses.some(isBlockedAddress)) {
      throw new SsrfError('host resolves to a private, loopback or reserved address');
    }
    return { url, host, port, addresses };
  }

  async isAllowed(rawUrl) {
    try {
      await this.validate(rawUrl);
      return true;
    } catch (e) {
      if (e instanceof SsrfError) return false;
      throw e;
    }
  }

  #hostAllowed(host) {
    return this.hosts.some((a) => (a.startsWith('*.') ? host.endsWith(a.slice(1)) && host.length > a.length - 1 : a === host));
  }
}
