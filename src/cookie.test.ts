import { expect, test } from "bun:test";
import * as jose from "jose";
import * as cookie from "./cookie";
import base64url from "base64-url";

test("Test that signing works", async () => {
  const secret = cookie.encodeSecret("aorsduyhvzckaf23ulsrtdoapth23risearsoisetn3");
  const token = await new jose.SignJWT({}).setProtectedHeader({ alg: "HS256" }).sign(secret);
  expect(token).toStartWith("eyJhbGciOiJIUzI1NiJ9.e30.");
});
test("Test that encryption works", async () => {
  const secret = cookie.encodeSecret("aorsduyhvzckaf23ulsrtdoapth23risearsoisetn3");
  const token = await new jose.EncryptJWT()
    .setProtectedHeader({ alg: "dir", enc: "A128CBC-HS256" })
    .setIssuedAt()
    .encrypt(secret);
  expect(token).toStartWith("eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.");
});

test("Url base64", () => {
  const v = base64url.encode("test");
  const vv = base64url.decode(v);
  expect(vv).toEqual("test");
});
