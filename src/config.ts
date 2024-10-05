import { z } from "zod";
function Config() {
  const schema = z.object({
    SMTP_HOST: z.string(),
    SMTP_PORT: z.number(),
    SMTP_SECURE: z.string(),
    SMTP_USERNAME: z.string(),
    SMTP_PASSWORD: z.string(),
    SMTP_FROM: z.string(),
    EMAIL_VALIDATION_URL: z.string(),
    WEBAUTHN_ORIGIN: z.string(),
    COOKIE_DOMAIN: z.string(),
    COOKIE_SECURE: z.string(),
    COOKIE_SECRET: z.string(),
    DATABASE_PATH: z.string(),
    EMAIL_TEMPLATE_PATH: z.string(),
    GDPR_DELETE_DELAY_DAYS: z.number(),
  });

  return schema.parse({
    SMTP_HOST: Bun.env.SMTP_HOST,
    SMTP_PORT: parseInt(Bun.env.SMTP_PORT || ""),
    SMTP_SECURE: Bun.env.SMTP_SECURE,
    SMTP_USERNAME: Bun.env.SMTP_USERNAME,
    SMTP_PASSWORD: Bun.env.SMTP_PASSWORD,
    SMTP_FROM: Bun.env.SMTP_FROM,
    EMAIL_VALIDATION_URL: Bun.env.EMAIL_VALIDATION_URL,
    WEBAUTHN_ORIGIN: Bun.env.WEBAUTHN_ORIGIN,
    COOKIE_DOMAIN: Bun.env.COOKIE_DOMAIN,
    COOKIE_SECURE: Bun.env.COOKIE_SECURE,
    COOKIE_SECRET: Bun.env.COOKIE_SECRET,
    DATABASE_PATH: Bun.env.DATABASE_PATH,
    EMAIL_TEMPLATE_PATH: Bun.env.EMAIL_TEMPLATE_PATH,
    GDPR_DELETE_DELAY_DAYS: parseInt(Bun.env.GDPR_DELETE_DELAY_DAYS || "30"),
  });
}

export default Config();
