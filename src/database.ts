import { CredentialInfo } from "@passwordless-id/webauthn/dist/esm/types";
import { Database } from "bun:sqlite";
import { HTTPException } from "hono/http-exception";

export interface User {
  id: number;
  email: string;
  jwt_version: number;
  gdpr_delete_at: string | null;
  created_at: string;
}
export interface Credential {
  id: number;
  user_id: number;
  name: string;
  credential_id: string;
  credential_data: string;
  credential_json: CredentialInfo;
  used_at: string;
  created_at: string;
}

export default class DB {
  private db: Database;
  constructor(path: string) {
    const db = new Database(path, { create: true });
    migrations(db);
    this.db = db;
  }

  userCreateOrFail(email: string): number {
    this.db.exec(`INSERT OR IGNORE INTO users (email) values (?)`, [email]);
    const id = (
      this.db.query("SELECT id FROM users WHERE email = ?").get(email) as {
        id: number;
      } | null
    )?.id;
    if (!id) throw "User not found";

    return id;
  }
  userGetById(id: number): User {
    const user = this.db.query("SELECT * FROM users WHERE id = ? LIMIT 1").get(id) as null | User;
    if (!user) throw new HTTPException(400, { message: "User not found" });
    return user;
  }
  userGetByEmail(email: string): User {
    const user = this.db.query("SELECT * FROM users WHERE email = ? LIMIT 1").get(email) as null | User;
    if (!user) throw new HTTPException(400, { message: "User not found" });
    return user;
  }
  userGdprDeleteSetDate(userId: number, days: number) {
    this.db.exec(`UPDATE users SET gdpr_delete_at = datetime('now','+${days} day') WHERE id = ?`, [userId]);
  }
  userGdprDeleteUnset(userId: number) {
    this.db.exec(`UPDATE users SET gdpr_delete_at = NULL WHERE id = ?`, [userId]);
  }
  userGdprDeleteEnact() {
    const res = this.db.query(`SELECT id FROM users WHERE gdpr_delete_at < datetime('now')`).all() as
      | { id: number }[]
      | null;
    if (!res) throw "Unable to find users to delete";
    if (res.length === 0) return;
    const userIds = res.map((e) => e.id);
    this.db.exec(`DELETE FROM credentials WHERE user_id IN (?)`, userIds);
    this.db.exec(`DELETE FROM users WHERE id IN (?)`, userIds);
  }
  credentialInfosByUserId(userId: number): CredentialInfo[] {
    const list = this.db
      .query("SELECT id, credential_data FROM credentials WHERE user_id = ?")
      .all(userId) as Credential[];
    for (const credential of list) {
      credential.credential_json = JSON.parse(credential.credential_data);
    }
    return list.map((v) => v.credential_json);
  }
  credentialByIdAndUserId(userId: number, credentialId: string): Credential {
    const credential = this.db
      .query("SELECT * FROM credentials WHERE user_id = ? and credential_id = ? LIMIT 1")
      .get(userId, credentialId) as null | Credential;
    if (!credential) throw new HTTPException(400, { message: "Credential not found" });
    credential.credential_json = JSON.parse(credential.credential_data);
    return credential;
  }
  credentialAdd(user_id: number, name: string, credentialInfo: CredentialInfo): void {
    const credential_id = credentialInfo.id;
    const credential_data = JSON.stringify(credentialInfo);
    this.db.exec("INSERT INTO credentials (user_id, name, credential_id, credential_data) VALUES (?, ?, ?, ?)", [
      user_id,
      name,
      credential_id,
      credential_data,
    ]);
  }
  credentialUsedNow(credentialId: number) {
    this.db.exec(`UPDATE credentials SET used_at = datetime() WHERE id = ?`, [credentialId]);
  }
}

function migrations(db: Database) {
  let version = getDatabaseVersion(db);
  if (version === 0) {
    db.exec(`CREATE TABLE IF NOT EXISTS users
    (
      id          INTEGER PRIMARY KEY,
      email       TEXT NOT NULL UNIQUE,
      jwt_version INTEGER NOT NULL DEFAULT (0),
      created_at  TEXT NOT NULL DEFAULT (datetime())
    )`);
    version = incrementDatabaseVersion(db, version);
  }
  if (version === 1) {
    db.exec(`ALTER TABLE users ADD COLUMN gdpr_delete_at TEXT`);
    version = incrementDatabaseVersion(db, version);
  }
}

// Thanks to: https://github.com/patlux
function getDatabaseVersion(db: Database): number {
  const result = db.prepare("PRAGMA user_version").get();
  if (typeof (result as any)?.user_version === "number") {
    return (result as any)?.user_version as number;
  }
  throw new Error(`Unexpected result when getting user_version: "${result}".`);
}

// Thanks to: https://github.com/patlux
function incrementDatabaseVersion(db: Database, currentVersion: number): number {
  let version = currentVersion + 1;
  db.exec(`PRAGMA user_version = ${version}`);
  return version;
}
