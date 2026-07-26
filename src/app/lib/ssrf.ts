import dns from "dns";
import { promisify } from "util";

const lookup = promisify(dns.lookup);

/**
 * Validates if a URL is safe to fetch (SSRF Protection).
 * Blocks private/internal IP ranges and localhost.
 */
export async function validateSafeUrl(url: string): Promise<boolean> {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    // 1. Block common local hostnames immediately
    if (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname === "::" ||
      hostname === "::0" ||
      hostname === "::1" ||
      hostname.startsWith("192.168.") ||
      hostname.startsWith("10.") ||
      hostname.endsWith(".local")
    ) {
      return false;
    }

    // 2. Resolve DNS to get the actual IP
    // family: 4 means IPv4, 6 means IPv6. 0 means both.
    const { address } = await lookup(hostname, { family: 0 });

    // 3. Check against private IP ranges
    if (isPrivateIP(address)) {
      return false;
    }

    return true;
  } catch {
    // If DNS resolution fails or URL is invalid, treat as unsafe
    return false;
  }
}

/**
 * Checks if an IP address is private/internal.
 * Supports IPv4 and all IPv6 transition mechanisms (mapped, NAT64, 6to4, Teredo).
 */
function isPrivateIP(ip: string): boolean {
  // IPv4 private ranges — pure IPv4 only (no colon)
  if (ip.includes(".") && !ip.includes(":")) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some((p) => isNaN(p))) return false;

    if (parts[0] === 0) return true;
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    return false;
  }

  if (ip.includes(":")) {
    const lower = ip.toLowerCase();

    // Unspecified / loopback
    if (lower === "::" || lower === "::0" || lower === "::1") return true;

    // ULA (fc00::/7) and link-local (fe80::/10)
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
    if (lower.startsWith("fe80")) return true;

    // Multicast (ff00::/8)
    if (lower.startsWith("ff")) return true;

    // IPv4-mapped ::ffff:x.x.x.x or ::ffff:xxxx:xxxx
    if (lower.startsWith("::ffff:")) {
      const tail = lower.slice(7);
      if (tail.includes(".")) return isPrivateIP(tail);
      const parts = tail.split(":");
      if (parts.length === 2) {
        const hi = parseInt(parts[0], 16);
        const lo = parseInt(parts[1], 16);
        return isPrivateIP(
          `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`,
        );
      }
    }

    // NAT64 well-known 64:ff9b::/96 (RFC 6052) and local-use 64:ff9b:1::/48 (RFC 8215)
    const nat64Match = lower.match(
      /^64:ff9b(?::1)?::([0-9a-f]{1,4}):([0-9a-f]{1,4})$/,
    );
    if (nat64Match) {
      const hi = parseInt(nat64Match[1], 16);
      const lo = parseInt(nat64Match[2], 16);
      return isPrivateIP(
        `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`,
      );
    }

    // 6to4 2002::/16 (RFC 3056) — IPv4 embedded in bits 16–47
    const sixto4Match = lower.match(/^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4}):/);
    if (sixto4Match) {
      const hi = parseInt(sixto4Match[1], 16);
      const lo = parseInt(sixto4Match[2], 16);
      return isPrivateIP(
        `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`,
      );
    }

    // Teredo 2001:0000::/32 (RFC 4380) — block entire prefix
    if (lower.startsWith("2001:0000:") || lower.startsWith("2001:0:")) {
      return true;
    }
  }

  return false;
}

/**
 * Performs a fetch request with SSRF protection by manually handling redirects
 * and validating the URL at each step.
 */
export async function safeFetch(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  let currentUrl = url;
  const maxRedirects = 5;
  let redirectCount = 0;

  while (redirectCount < maxRedirects) {
    const isSafe = await validateSafeUrl(currentUrl);
    if (!isSafe) {
      throw new Error("Invalid or restricted URL detected");
    }

    const response = await fetch(currentUrl, {
      ...options,
      redirect: "manual",
    });

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) {
        throw new Error("Redirect response missing Location header");
      }

      // Resolve relative URLs against the current URL
      currentUrl = new URL(location, currentUrl).toString();
      redirectCount++;
      continue;
    }

    return response;
  }

  throw new Error(`Too many redirects (max: ${maxRedirects})`);
}
