import { expect, test } from "bun:test";
import * as jose from "jose";
import * as cookie from "./cookie";
import base64url from "base64-url";

const secret = "aorsduyhvzckaf23ulsrtdoapth23risearsoisetn3";

test("Test that signing works", async () => {
  const key = cookie.encodeSecret(secret);
  const token = await new jose.SignJWT({ hidden: "secret" }).setProtectedHeader({ alg: "HS256" }).sign(key);
  expect(token).toStartWith("eyJhbGciOiJIUzI1NiJ9.");

  const { payload } = await jose.jwtVerify(token, key);
  expect(payload.hidden).toBe("secret");
});
test("Test that encryption works", async () => {
  const key = cookie.encodeSecret(secret);
  const token = await new jose.EncryptJWT({ hidden: "secret" })
    .setProtectedHeader({ alg: "dir", enc: "A128CBC-HS256" })
    .setIssuedAt()
    .encrypt(key);
  expect(token).toStartWith("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.");

  const { payload } = await jose.jwtDecrypt(token, key);
  expect(payload.hidden).toBe("secret");
});

test("Url base64", () => {
  const v = base64url.encode("test");
  const vv = base64url.decode(v);
  expect(vv).toEqual("test");
});
