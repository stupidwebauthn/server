import { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import * as jose from "jose";
import { CookieOptions } from "hono/utils/cookie";
import { HTTPException } from "hono/http-exception";

export type SameSite = "lax" | "strict" | "Lax" | "Strict";

export type JWTPayload = {
  /**
   * The token is checked to ensure it has not expired.
   */
  exp?: number;
  /**
   * The token is checked to ensure it is not being used before a specified time.
   */
  nbf?: number;
  /**
   * The token is checked to ensure it is not issued in the future.
   */
  iat?: number;
};

// Constants
// ----------------------------------------------------------------

const defaultOptions: CookieOptions = {
  domain: Bun.env.COOKIE_DOMAIN,
  httpOnly: true,
  secure: Bun.env.COOKIE_SECURE !== "false",
};

// Utilities
// ----------------------------------------------------------------

export function encodeSecret(secret: string): Uint8Array {
  const uintSecret = jose.base64url.decode(secret);
  // if (uintSecret.length !== 256) throw "Invalid secret incorrect length";
  return uintSecret;
}

// Methods
// ----------------------------------------------------------------

export function deleteNow(c: Context, key: string) {
  deleteCookie(c, key, defaultOptions);
}

// Create signed cookie, data is stored in unencrypted but verifiable with a signature
export async function jwtSignCreate<P extends JWTPayload>(
  c: Context,
  key: string,
  expires: Date,
  secret: Uint8Array,
  payload: P,
  sameSite: SameSite
): Promise<void> {
  const token = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(expires)
    .sign(secret);

  setCookie(c, key, token, {
    expires: expires,
    sameSite,
    ...defaultOptions,
  });
}

// Read signed cookie, data is stored in unencrypted but verifiable with a signature
export async function jwtSignVerifyRead<P extends JWTPayload>(c: Context, key: string, secret: Uint8Array): Promise<P> {
  try {
    const token = getCookie(c, key);
    if (!token) throw "Missing request cookie: " + key;
    const result = await jose.jwtVerify<P>(token, secret);
    return result.payload;
  } catch (e) {
    throw new HTTPException(401, { message: e!.toString() });
  }
}

// Create an encrypted cookie, data is stored in encrypted
export async function jwtEncryptCreate<P extends JWTPayload>(
  c: Context,
  key: string,
  expires: Date,
  secret: Uint8Array,
  payload: P,
  sameSite: SameSite
): Promise<void> {
  const token = await new jose.EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A128CBC-HS256" })
    .setIssuedAt()
    .setExpirationTime(expires)
    .encrypt(secret);

  setCookie(c, key, token, {
    expires: expires,
    sameSite,
    ...defaultOptions,
  });
}

// Read an encrypted cookie, data is stored in encrypted
export async function jwtDecryptRead<P extends JWTPayload>(c: Context, key: string, secret: Uint8Array): Promise<P> {
  try {
    const token = getCookie(c, key);
    if (!token) throw "Missing request cookie: " + key;
    const result = await jose.jwtDecrypt<P>(token, secret);
    return result.payload;
  } catch (e) {
    throw new HTTPException(401, { message: e!.toString() });
  }
}
