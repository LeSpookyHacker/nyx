/**
 * URL safety helpers (SEC-102).
 *
 * safeUrl validates that a URL uses a safe web scheme (http/https) before it
 * is rendered in an href attribute. This prevents javascript:, data:,
 * vbscript:, and any other non-web scheme from being injected by API responses
 * and executed when a user clicks the link.
 */

/**
 * Return the URL unchanged if it uses http: or https:, otherwise undefined.
 * Safe to pass directly to an <a href={...}> attribute.
 */
export function safeUrl(url: string | undefined | null): string | undefined {
  if (!url) return undefined
  try {
    const parsed = new URL(url)
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') return url
  } catch { /* malformed URL */ }
  return undefined
}
