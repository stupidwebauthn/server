import { Hono } from "hono";
import { deleteCookie } from "hono/cookie";
import { server } from "@passwordless-id/webauthn";
import * as nodemailer from "nodemailer";
import dayjs from "dayjs";
import DB, { User } from "./database";
import * as cookie from "./cookie";
import type { JWTPayload } from "./cookie";
import EmailTemplate from "./email_template";
import { AuthenticationJSON, RegistrationJSON } from "@passwordless-id/webauthn/dist/esm/types";
import { HTTPException } from "hono/http-exception";
import { StatusCode } from "hono/utils/http-status";
import config from "./config";
import base64url from "base64-url";
import { createMiddleware } from "hono/factory";
import { userToJson } from "./utils";
import Cron from "croner";
import { rateLimiter } from "hono-rate-limiter";

interface JwtPayloadWithEmail extends JWTPayload {
  email: string;
}
interface JwtPayloadWithEmailChallenge extends JWTPayload {
  challenge: string;
  email: string;
}
interface JwtPayloadWithUserIdJwtVersion extends JWTPayload {
  user_id: number;
  jwt_version: number;
}
interface JwtPayloadWithUserIdChallenge extends JWTPayload {
  challenge: string;
  user_id: number;
}

const COOKIE_VALID_USER_REGISTER_PASSKEY = "swa_valid_user_register_passkey";
const COOKIE_VALID_USER_WITHOUT_PASSKEY = "swa_valid_user_without_passkey";
const COOKIE_LOGIN_CHALLENGE = "swa_login_challenge";
const COOKIE_DOUBLECHECK_CHALLENGE = "swa_doublecheck_challenge";
const COOKIE_EMAIL_CHALLENGE = "swa_email_challenge";
const COOKIE_AUTH = "swa_auth";
const COOKIE_DOUBLECHECK_AUTH = "swa_doublecheck_auth";
const COOKIE_CSRF = "swa_csrf";

const cookie_expires_auth = () => dayjs().add(1, "month").toDate();
const cookie_expires_csrf = () => dayjs().add(15, "seconds").toDate();
const cookie_expires_passkey_challenge = () => dayjs().add(2, "minutes").toDate();
const cookie_expires_email_challenge = () => dayjs().add(2, "hours").toDate();
const cookie_expires_email_to_passkey = () => dayjs().add(1, "hour").toDate();

const cookie_secret = cookie.encodeSecret(config.COOKIE_SECRET);

const limiterEmail = rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes).
  standardHeaders: "draft-6", // draft-6: `RateLimit-*` headers; draft-7: combined `RateLimit` header
  keyGenerator: (c) => c.req.query("email") || "", // Method to generate custom identifiers for clients.
  // store: ... , // Redis, MemoryStore, etc. See below.
});

const db = new DB(config.DATABASE_PATH!);

Cron("@daily", () => {
  console.info("Running daily cron");
  db.userGdprDeleteEnact();
}).trigger();

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
  .use(
    "/auth/auth/*",
    createMiddleware<{
      Variables: {
        auth: User;
      };
    }>(async (c, next) => {
      try {
        const payload = await cookie.jwtSignVerifyRead<JwtPayloadWithUserIdJwtVersion>(c, COOKIE_AUTH, cookie_secret);

        const user = db.userGetById(payload.user_id);
        if (user.jwt_version !== payload.jwt_version)
          throw new HTTPException(401, { message: "Force logout, re-authentication requested" });

        await cookie.jwtSignCreate<JwtPayloadWithUserIdJwtVersion>(
          c,
          COOKIE_AUTH,
          cookie_expires_auth(),
          cookie_secret,
          {
            user_id: payload.user_id,
            jwt_version: payload.jwt_version,
          },
          "Lax"
        );

        c.set("auth", user);
        await next();
      } catch (err: any | Error | HTTPException) {
        let status: StatusCode = 500;
        let errMessage = "HTTP error: " + status;
        if (err instanceof HTTPException) {
          status = err.status;
          if (err.status >= 500) throw err;
          errMessage = err.message;
        } else if (err instanceof Error) {
          errMessage = err.message;
        } else if (typeof err === "string") {
          errMessage = err;
        }

        deleteCookie(c, COOKIE_AUTH);
        const res = c.text(errMessage);
        throw new HTTPException(status, { res });
      }
    })
  )

  // register or login via email and new passkey
  .get("/auth/register/email/challenge", limiterEmail, async (c) => {
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
      cookie_expires_email_challenge(),
      cookie_secret,
      {
        challenge: challenge,
        email: email,
      },
      "Lax"
    );
    return c.text("", 201);
  })

  .get("/auth/register/email/verify", async (c) => {
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

    db.userCreateOrFail(payload.email);

    deleteCookie(c, COOKIE_EMAIL_CHALLENGE);

    await cookie.jwtSignCreate<JwtPayloadWithEmail>(
      c,
      COOKIE_VALID_USER_WITHOUT_PASSKEY,
      cookie_expires_email_to_passkey(),
      cookie_secret,
      {
        email: payload.email,
      },
      "Strict"
    );
    return c.text("", 201);
  })

  .post("/auth/register/passkey/challenge", async (c) => {
    const payload = await cookie.jwtSignVerifyRead<JwtPayloadWithEmail>(
      c,
      COOKIE_VALID_USER_WITHOUT_PASSKEY,
      cookie_secret
    );

    const challenge = server.randomChallenge();

    await cookie.jwtEncryptCreate<JwtPayloadWithEmailChallenge>(
      c,
      COOKIE_VALID_USER_REGISTER_PASSKEY,
      cookie_expires_passkey_challenge(),
      cookie_secret,
      {
        challenge,
        email: payload.email,
      },
      "Strict"
    );
    return c.json({ challenge, email: payload.email });
  })

  .post("/auth/register/passkey/verify", async (c) => {
    const payload = await cookie.jwtDecryptRead<JwtPayloadWithEmailChallenge>(
      c,
      COOKIE_VALID_USER_REGISTER_PASSKEY,
      cookie_secret
    );
    const body = (await c.req.json()) as RegistrationJSON;
    const registrationParsed = await server.verifyRegistration(body, {
      challenge: payload.challenge,
      origin: config.WEBAUTHN_ORIGIN,
    });
    const user = await db.userGetByEmail(payload.email);
    if (body.user.name !== user.email)
      throw new HTTPException(400, { message: "Attempted to verify with a different email" });

    db.credentialAdd(user.id, registrationParsed.authenticator.name, registrationParsed.credential);

    await cookie.jwtSignCreate<JwtPayloadWithUserIdJwtVersion>(
      c,
      COOKIE_AUTH,
      cookie_expires_auth(),
      cookie_secret,
      {
        user_id: user.id,
        jwt_version: user.jwt_version,
      },
      "Lax"
    );
    deleteCookie(c, COOKIE_VALID_USER_REGISTER_PASSKEY);
    deleteCookie(c, COOKIE_VALID_USER_WITHOUT_PASSKEY);
    return c.text("", 201);
  })

  .get("/auth/login/challenge", async (c) => {
    const email = c.req.query("email");
    if (!email) throw new HTTPException(401, { message: "Invalid email" });

    const user = await db.userGetByEmail(email);
    const credentials = await db.credentialInfosByUserId(user.id);
    const challenge = server.randomChallenge();

    await cookie.jwtEncryptCreate<JwtPayloadWithEmailChallenge>(
      c,
      COOKIE_LOGIN_CHALLENGE,
      cookie_expires_passkey_challenge(),
      cookie_secret,
      {
        challenge,
        email: user.email,
      },
      "Strict"
    );

    return c.json({
      challenge,
      credentials,
    });
  })

  .post("/auth/login/verify", async (c) => {
    const payload = await cookie
      .jwtDecryptRead<JwtPayloadWithEmailChallenge>(c, COOKIE_LOGIN_CHALLENGE, cookie_secret)
      .catch((err) => {
        throw new HTTPException(400, { message: `Must be opened in the same browser, max 30 min after email is sent` });
      });
    const body = (await c.req.json()) as AuthenticationJSON;

    const user = db.userGetByEmail(payload.email);
    const credentialKey = db.credentialByIdAndUserId(user.id, body.id);

    /* const authenticationParsed = */ await server.verifyAuthentication(body, credentialKey.credential_json, {
      challenge: payload.challenge,
      origin: config.WEBAUTHN_ORIGIN,
      userVerified: true,
    });

    db.credentialUsedNow(credentialKey.id);

    await cookie.jwtSignCreate<JwtPayloadWithUserIdJwtVersion>(
      c,
      COOKIE_AUTH,
      cookie_expires_auth(),
      cookie_secret,
      {
        user_id: user.id,
        jwt_version: user.jwt_version,
      },
      "Lax"
    );
    deleteCookie(c, COOKIE_LOGIN_CHALLENGE);
    return c.text("", 201);
  })

  .get("/auth/logout", async (c) => {
    deleteCookie(c, COOKIE_AUTH);
    return c.text("", 201);
  })

  .get("/auth/auth/validate", async (c) => {
    const user = c.get("auth");
    return c.json(userToJson(user));
  })
  .get("/auth/auth/csrf/challenge", async (c) => {
    const user = c.get("auth");
    await cookie.jwtSignCreate<JwtPayloadWithUserIdJwtVersion>(
      c,
      COOKIE_CSRF,
      cookie_expires_csrf(),
      cookie_secret,
      {
        user_id: user.id,
        jwt_version: user.jwt_version,
      },
      "Strict"
    );
    return c.text("", 201);
  })
  .get("/auth/auth/csrf/validate", async (c) => {
    try {
      const user = c.get("auth");
      await cookie.jwtSignVerifyRead<JwtPayloadWithUserIdJwtVersion>(c, COOKIE_CSRF, cookie_secret);
      return c.json(userToJson(user));
    } catch (err) {
      deleteCookie(c, COOKIE_CSRF);
      return c.text("Csrf check failed", 400);
    }
  })

  .get("/auth/auth/doublecheck/challenge", async (c) => {
    const user = c.get("auth");
    const challenge = server.randomChallenge();

    const credentials = await db.credentialInfosByUserId(user.id);

    await cookie.jwtEncryptCreate<JwtPayloadWithUserIdChallenge>(
      c,
      COOKIE_DOUBLECHECK_CHALLENGE,
      cookie_expires_passkey_challenge(),
      cookie_secret,
      {
        challenge,
        user_id: user.id,
      },
      "Strict"
    );

    return c.json({
      challenge,
      credentials,
    });
  })
  .post("/auth/auth/doublecheck/verify", async (c) => {
    const user = c.get("auth");
    const payload = await cookie
      .jwtDecryptRead<JwtPayloadWithUserIdChallenge>(c, COOKIE_DOUBLECHECK_CHALLENGE, cookie_secret)
      .catch((err) => {
        throw new HTTPException(400, { message: `You were too slow at using your passkey, please try again` });
      });
    if (user.id !== payload.user_id)
      throw new HTTPException(400, { message: "Access denied: Email is not the same as the current user" });
    const body = (await c.req.json()) as AuthenticationJSON;
    const credentialKey = db.credentialByIdAndUserId(user.id, body.id);

    await server.verifyAuthentication(body, credentialKey.credential_json, {
      challenge: payload.challenge,
      origin: config.WEBAUTHN_ORIGIN,
      userVerified: true,
    });

    await cookie.jwtSignCreate<JwtPayloadWithUserIdJwtVersion>(
      c,
      COOKIE_DOUBLECHECK_AUTH,
      cookie_expires_csrf(),
      cookie_secret,
      {
        user_id: user.id,
        jwt_version: user.jwt_version,
      },
      "Lax"
    );
    deleteCookie(c, COOKIE_DOUBLECHECK_CHALLENGE);
    return c.text("", 201);
  })
  .get("/auth/auth/doublecheck/validate", async (c) => {
    try {
      const user = c.get("auth");
      const payload = await cookie.jwtSignVerifyRead<JwtPayloadWithUserIdJwtVersion>(
        c,
        COOKIE_DOUBLECHECK_AUTH,
        cookie_secret
      );
      if (payload.user_id !== user.id) throw "Invalid double check cookie user id";
      if (payload.jwt_version !== user.jwt_version) throw "Invalid double check cookie jwt version";

      return c.json(userToJson(user));
    } catch (err) {
      deleteCookie(c, COOKIE_DOUBLECHECK_AUTH);
      return c.text("Double authentication check failed", 400);
    }
  })
  .delete("/auth/auth/doublecheck/verify", async (c) => {
    const user = c.get("auth");
    const payload = await cookie
      .jwtDecryptRead<JwtPayloadWithUserIdChallenge>(c, COOKIE_DOUBLECHECK_CHALLENGE, cookie_secret)
      .catch(() => {
        throw new HTTPException(400, { message: `You were too slow at using your passkey, please try again` });
      });
    if (user.id !== payload.user_id)
      throw new HTTPException(400, { message: "Access denied: Cookie's user is not the same as the current user" });
    const body = (await c.req.json()) as AuthenticationJSON;
    const credentialKey = db.credentialByIdAndUserId(user.id, body.id);

    await server.verifyAuthentication(body, credentialKey.credential_json, {
      challenge: payload.challenge,
      origin: config.WEBAUTHN_ORIGIN,
      userVerified: true,
    });

    db.credentialDeleteById(credentialKey.id);

    deleteCookie(c, COOKIE_AUTH);
    deleteCookie(c, COOKIE_CSRF);
    deleteCookie(c, COOKIE_DOUBLECHECK_CHALLENGE);
    deleteCookie(c, COOKIE_DOUBLECHECK_AUTH);
    deleteCookie(c, COOKIE_EMAIL_CHALLENGE);
    deleteCookie(c, COOKIE_LOGIN_CHALLENGE);
    deleteCookie(c, COOKIE_VALID_USER_REGISTER_PASSKEY);
    deleteCookie(c, COOKIE_VALID_USER_WITHOUT_PASSKEY);
    return c.text("", 201);
  })
  .put("/auth/auth/doublecheck/panic", async (c) => {
    try {
      const user = c.get("auth");
      const payload = await cookie.jwtSignVerifyRead<JwtPayloadWithUserIdJwtVersion>(
        c,
        COOKIE_DOUBLECHECK_AUTH,
        cookie_secret
      );
      if (payload.user_id !== user.id) throw "Invalid double check cookie user id";
      if (payload.jwt_version !== user.jwt_version) throw "Invalid double check cookie jwt version";

      db.userPanic(user.id);
      deleteCookie(c, COOKIE_AUTH);
      deleteCookie(c, COOKIE_CSRF);
      deleteCookie(c, COOKIE_DOUBLECHECK_CHALLENGE);
      deleteCookie(c, COOKIE_DOUBLECHECK_AUTH);
      deleteCookie(c, COOKIE_EMAIL_CHALLENGE);
      deleteCookie(c, COOKIE_LOGIN_CHALLENGE);
      deleteCookie(c, COOKIE_VALID_USER_REGISTER_PASSKEY);
      deleteCookie(c, COOKIE_VALID_USER_WITHOUT_PASSKEY);
      return c.text("", 201);
    } catch (err) {
      deleteCookie(c, COOKIE_DOUBLECHECK_AUTH);
      return c.text("Double authentication check failed", 400);
    }
  })

  // GDPR
  .get("/auth/auth/doublecheck/gdpr/data", async (c) => {
    const user = c.get("auth");
    const credentials = await db.credentialInfosByUserId(user.id);
    return c.json({ user: userToJson(user), credentials });
  })
  .post("/auth/auth/doublecheck/gdpr/delete-set", async (c) => {
    let user = c.get("auth");
    db.userGdprDeleteSetDate(user.id, config.GDPR_DELETE_DELAY_DAYS);
    user = db.userGetById(user.id);
    return c.json(userToJson(user));
  })
  .post("/auth/auth/doublecheck/gdpr/delete-unset", async (c) => {
    let user = c.get("auth");
    db.userGdprDeleteUnset(user.id);
    user = db.userGetById(user.id);
    return c.json(userToJson(user));
  })

  .get("/auth", async (c) => {
    return c.text("Hello World!");
  })
  .get("/", async (c) => {
    c.header("");
    return c.text(
      "Welcome to Stupid Webauthn!, Generally you shouldn't be seeing this, the webmaster should be proxying /auth/ to http://stupidwebauthn/auth/"
    );
  });

export default app;
