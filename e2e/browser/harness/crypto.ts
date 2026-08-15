// Cryptographic helpers that reproduce the Zen IdP contracts
// independently, so the browser suite validates them as a black box. The
// standards-based pieces (RFC 4648 Base32 and RFC 6238 TOTP) are delegated
// to battle-tested libraries, and only the Zen IdP-specific derivation is
// implemented here.

import base32Encode from "base32-encode";
import { TOTP } from "otpauth";

const encoder = new TextEncoder();

/**
 * Derives the deterministic TOTP shared secret of a subject: the unpadded
 * Base32 encoding of HMAC-SHA256 over the domain-separated subject and
 * revision, keyed by the SHA-256 digest of the root secret.
 */
export async function deriveTOTPSecret(
  rootSecret: string,
  sub: string,
  revision: number,
): Promise<string> {
  const key = await crypto.subtle.digest("SHA-256", encoder.encode(rootSecret));
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const message = encoder.encode(`zen-idp:totp:${sub}:${revision}`);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, message));
  return base32Encode(mac, "RFC4648", { padding: false });
}

/**
 * Computes the RFC 6238 code of the given secret at the given instant:
 * HMAC-SHA1 over the 30-second counter, truncated to six decimal digits.
 */
export function totpCode(secret: string, at: Date): string {
  const totp = new TOTP({
    secret,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
  });
  return totp.generate({ timestamp: at.getTime() });
}
