import { Dayjs } from "dayjs";
import { Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import * as jose from "jose";
import { CookieOptions } from "hono/utils/cookie";
import { JWTPayload } from "hono/utils/jwt/types";

// Constants
// ----------------------------------------------------------------

const defaultOptions: CookieOptions = {
  domain: Bun.env.COOKIE_DOMAIN,
  httpOnly: true,
  secure: Bun.env.COOKIE_SECURE !== "false",
  sameSite: Bun.env.COOKIE_SAMESITE as CookieOptions["sameSite"],
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

// Create signed cookie, data is stored in unencrypted but verifiable with a signature
export async function jwtSignCreate<P extends jose.JWTPayload>(
  c: Context,
  key: string,
  expires: Dayjs,
  secret: Uint8Array,
  payload: P
): Promise<void> {
  const token = await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(expires.toDate())
    .sign(secret);

  setCookie(c, key, token, {
    expires: expires.toDate(),
    ...defaultOptions,
  });
}

// Read signed cookie, data is stored in unencrypted but verifiable with a signature
export async function jwtSignVerifyRead<P extends JWTPayload>(c: Context, key: string, secret: Uint8Array): Promise<P> {
  const token = getCookie(c, key);
  if (!token) throw "Missing request cookie: " + key;
  const result = await jose.jwtVerify<P>(token, secret);
  return result.payload;
}

// Create an encrypted cookie, data is stored in encrypted
export async function jwtEncryptCreate<P extends jose.JWTPayload>(
  c: Context,
  key: string,
  expires: Dayjs,
  secret: Uint8Array,
  payload: P
): Promise<void> {
  const token = await new jose.EncryptJWT(payload)
    .setProtectedHeader({ alg: "dir", enc: "A128CBC-HS256" })
    .setIssuedAt()
    .setExpirationTime(expires.toDate())
    .encrypt(secret);

  setCookie(c, key, token, {
    expires: expires.toDate(),
    ...defaultOptions,
  });
}

// Read an encrypted cookie, data is stored in encrypted
export async function jwtDecryptRead<P extends jose.JWTPayload>(
  c: Context,
  key: string,
  secret: Uint8Array
): Promise<P> {
  const token = getCookie(c, key);
  if (!token) throw "Missing request cookie: " + key;
  const result = await jose.jwtDecrypt<P>(token, secret);
  return result.payload;
}
