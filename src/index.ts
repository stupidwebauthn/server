import { Hono } from "hono";
import { deleteCookie } from "hono/cookie";
import { server } from "@passwordless-id/webauthn";
import * as nodemailer from "nodemailer";
import dayjs from "dayjs";
import DB from "./database";
import * as cookie from "./cookie";
import EmailTemplate from "./email_template";
import { JWTPayload } from "hono/utils/jwt/types";
import { AuthenticationJSON, RegistrationJSON } from "@passwordless-id/webauthn/dist/esm/types";
import { HTTPException } from "hono/http-exception";
import { StatusCode } from "hono/utils/http-status";
import config from "./config";
import base64url from "base64-url";

interface JwtPayloadWithUserId extends JWTPayload {
  user_id: number;
}
interface JwtPayloadWithEmailChallenge extends JWTPayload {
  challenge: string;
  email: string;
}
interface JwtPayloadWithUserIdChallenge extends JWTPayload {
  user_id: number;
  challenge: string;
}
interface JwtPayloadWithUserIdJwtVersion extends JWTPayload {
  user_id: number;
  jwt_version: number;
}

const COOKIE_VALID_USER_REGISTER_PASSKEY = "swa_valid_user_register_passkey";
const COOKIE_VALID_USER_WITHOUT_PASSKEY = "swa_valid_user_without_passkey";
const COOKIE_LOGIN_CHALLENGE = "swa_login_challenge";
const COOKIE_EMAIL_CHALLENGE = "swa_email_challenge";
const COOKIE_AUTH = "swa_auth";

const cookie_secret = cookie.encodeSecret(config.COOKIE_SECRET);

const cookie_expires_short = () => dayjs().add(1, "day");
const cookie_expires_long = () => dayjs().add(1, "month");

const db = new DB(config.DATABASE_PATH!);

const transporter = nodemailer.createTransport({
  host: config.SMTP_HOST,
  port: config.SMTP_PORT,
  secure: config.SMTP_SECURE === "true",
  auth: {
    user: config.SMTP_USERNAME,
    pass: config.SMTP_PASSWORD,
  },
  requireTLS: config.SMTP_SECURE === "tls",
  tls:
    config.SMTP_SECURE === "tls"
      ? {
          ciphers: "SSLv3",
        }
      : {
          // do not fail on invalid certs
          rejectUnauthorized: false,
        },
} as nodemailer.TransportOptions);

const emailTemplate = await EmailTemplate(config.EMAIL_TEMPLATE_PATH);

console.log(config);

const app = new Hono()
  // register or login via email and new passkey
  .get("/auth/register/email/challenge", async (c) => {
    const email = c.req.query("email");
    if (!email) throw new HTTPException(400, { message: "Invalid email" });

    const challenge = server.randomChallenge();
    const url = `${config.EMAIL_VALIDATION_URL}?c=${base64url.encode(challenge)}`;

    const html = emailTemplate("__URL__", url);
    // console.log("html", html);
    await transporter.sendMail({
      from: config.SMTP_FROM,
      to: email,
      subject: "Verify your email",
      text: `Verify your email: ${url}`,
      html,
    });

    await cookie.jwtEncryptCreate<JwtPayloadWithEmailChallenge>(
      c,
      COOKIE_EMAIL_CHALLENGE,
      cookie_expires_short(),
      cookie_secret,
      {
        challenge: challenge,
        email: email,
      }
    );
    return c.text("", 201);
  })

  .get("/auth/register/email/validate", async (c) => {
    const queryChallengeBase64 = c.req.query("c");
    if (!queryChallengeBase64) throw new HTTPException(401, { message: "Invalid url" });
    const queryChallenge = base64url.decode(queryChallengeBase64);

    const payload = await cookie
      .jwtDecryptRead<JwtPayloadWithEmailChallenge>(c, COOKIE_EMAIL_CHALLENGE, cookie_secret)
      .catch((err) => {
        throw new HTTPException(400, {
          message: `Link can only be open once, in the same browser, max 24h after email is sent`,
        });
      });
    if (payload.challenge !== queryChallenge)
      throw new HTTPException(401, { message: "Invalid email challenge, please register again" });
    if (!payload.email) throw new HTTPException(401, { message: "Invalid email" });

    const user_id = db.userCreateOrFail(payload.email);

    deleteCookie(c, COOKIE_EMAIL_CHALLENGE);

    await cookie.jwtSignCreate<JwtPayloadWithUserId>(
      c,
      COOKIE_VALID_USER_WITHOUT_PASSKEY,
      cookie_expires_short(),
      cookie_secret,
      {
        user_id,
      }
    );
    return c.text("", 201);
  })

  .post("/auth/register/passkey/challenge", async (c) => {
    const payload = await cookie.jwtSignVerifyRead<JwtPayloadWithUserId>(
      c,
      COOKIE_VALID_USER_WITHOUT_PASSKEY,
      cookie_secret
    );

    const challenge = server.randomChallenge();

    await cookie.jwtEncryptCreate<JwtPayloadWithUserIdChallenge>(
      c,
      COOKIE_VALID_USER_REGISTER_PASSKEY,
      cookie_expires_short(),
      cookie_secret,
      {
        user_id: payload.user_id,
        challenge,
      }
    );
    return c.json({ challenge });
  })

  .post("/auth/register/passkey/validate", async (c) => {
    const payload = await cookie.jwtDecryptRead<JwtPayloadWithUserIdChallenge>(
      c,
      COOKIE_VALID_USER_REGISTER_PASSKEY,
      cookie_secret
    );
    const body = (await c.req.json()) as RegistrationJSON;
    const registrationParsed = await server.verifyRegistration(body, {
      challenge: payload.challenge,
      origin: config.WEBAUTHN_ORIGIN,
    });
    const user = await db.userGetById(payload.user_id);

    db.credentialAdd(payload.user_id, registrationParsed.authenticator.name, registrationParsed.credential);

    await cookie.jwtSignCreate<JwtPayloadWithUserIdJwtVersion>(c, COOKIE_AUTH, cookie_expires_long(), cookie_secret, {
      user_id: payload.user_id,
      jwt_version: user.jwt_version,
    });
    deleteCookie(c, COOKIE_VALID_USER_REGISTER_PASSKEY);
    deleteCookie(c, COOKIE_VALID_USER_WITHOUT_PASSKEY);
    return c.text("", 201);
  })

  .get("/auth/login/challenge", async (c) => {
    const email = c.req.query("email");
    if (!email) throw new HTTPException(401, { message: "Invalid email" });

    const user = await db.userGetByEmail(email);
    const credentials = await db.credentialListByUserIdToSelect(user.id);
    const challenge = server.randomChallenge();

    await cookie.jwtEncryptCreate<JwtPayloadWithUserIdChallenge>(
      c,
      COOKIE_LOGIN_CHALLENGE,
      cookie_expires_short(),
      cookie_secret,
      {
        challenge: challenge,
        user_id: user.id,
      }
    );

    return c.json({
      challenge,
      credentials,
    });
  })

  .post("/auth/login/validate", async (c) => {
    const payload = await cookie
      .jwtDecryptRead<JwtPayloadWithUserIdChallenge>(c, COOKIE_LOGIN_CHALLENGE, cookie_secret)
      .catch((err) => {
        throw new HTTPException(400, { message: `Must be opened in the same browser, mac 30 min after email is sent` });
      });
    const cred_id = parseInt(c.req.query("cred_id") || "");
    if (!cred_id) throw new HTTPException(401, { message: "Invalid credential id" });
    const body = (await c.req.json()) as AuthenticationJSON;

    const user = db.userGetById(payload.user_id);
    const credentialKey = db.credentialByIdAndUserId(payload.user_id, cred_id);

    /* const authenticationParsed = */ await server.verifyAuthentication(body, credentialKey.credential_json, {
      challenge: payload.challenge,
      origin: config.WEBAUTHN_ORIGIN,
      userVerified: true,
    });

    db.credentialUsedNow(credentialKey.id);

    await cookie.jwtSignCreate<JwtPayloadWithUserIdJwtVersion>(c, COOKIE_AUTH, cookie_expires_long(), cookie_secret, {
      user_id: payload.user_id,
      jwt_version: user.jwt_version,
    });
    deleteCookie(c, COOKIE_LOGIN_CHALLENGE);
    return c.text("", 201);
  })

  .post("/auth/auth/validate", async (c) => {
    try {
      const payload = await cookie.jwtSignVerifyRead<JwtPayloadWithUserIdJwtVersion>(c, COOKIE_AUTH, cookie_secret);

      const user = db.userGetById(payload.user_id);
      if (user.jwt_version !== payload.jwt_version)
        throw new HTTPException(401, { message: "Force logout, re-authentication requested" });

      await cookie.jwtSignCreate<JwtPayloadWithUserIdJwtVersion>(c, COOKIE_AUTH, cookie_expires_long(), cookie_secret, {
        user_id: payload.user_id,
        jwt_version: payload.jwt_version,
      });
      return c.json({
        user_id: user.id,
        user_email: user.email,
        user_created_at: user.created_at,
      });
    } catch (err: any | Error | HTTPException) {
      let status: StatusCode = 500;
      if (err instanceof HTTPException) {
        status = err.status;
        if (err.status >= 500) throw err;
      }

      deleteCookie(c, COOKIE_EMAIL_CHALLENGE);
      deleteCookie(c, COOKIE_VALID_USER_REGISTER_PASSKEY);
      deleteCookie(c, COOKIE_VALID_USER_WITHOUT_PASSKEY);
      deleteCookie(c, COOKIE_AUTH);
      c.status(status);
      return c.json({ message: err?.message || err });
    }
  })
  .get("/auth/logout", async (c) => {
    deleteCookie(c, COOKIE_EMAIL_CHALLENGE);
    deleteCookie(c, COOKIE_VALID_USER_REGISTER_PASSKEY);
    deleteCookie(c, COOKIE_VALID_USER_WITHOUT_PASSKEY);
    deleteCookie(c, COOKIE_AUTH);
    return c.text("", 201);
  })

  .get("/auth", async (c) => {
    return c.text("Hello World!");
  })
  .get("/", async (c) => {
    return c.text("Hello World!");
  });

export default app;
