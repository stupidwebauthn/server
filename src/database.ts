import { CredentialInfo } from "@passwordless-id/webauthn/dist/esm/types";
import { Database } from "bun:sqlite";
import { HTTPException } from "hono/http-exception";

export interface User {
  id: number;
  email: string;
  jwt_version: number;
  created_at: number;
}
export interface Credential {
  id: number;
  user_id: number;
  name: string;
  credential_id: string;
  credential_data: string;
  credential_json: CredentialInfo;
}
export interface CredentialSelect {
  id: number;
  name: string;
  credential: CredentialInfo;
}

export default class DB {
  private db: Database;
  constructor(path: string) {
    const db = new Database(path, { create: true });
    db.run(`create table if not exists users
(
  id          integer primary key,
  email       text not null unique,
  jwt_version integer not null default (0),
  created_at  text not null default (datetime())
)`);
    db.run(`create table if not exists credentials
(
   id              integer primary key,
   user_id         integer not null,
   name            text not null,
   credential_id   text not null,
   credential_data text not null,
   used_at         text not null default (datetime()),
   created_at      text not null default (datetime())
)`);
    this.db = db;
  }

  userCreateOrFail(email: string): number {
    this.db.run(`insert or ignore into users (email) values (?)`, [email]);
    const id = (
      this.db.query("select id from users where email = ?").get(email) as {
        id: number;
      } | null
    )?.id;
    if (!id) throw "User not found";

    return id;
  }
  userGetById(id: number): User {
    const user = this.db.query("select * from users where id = ? limit 1").get(id) as null | User;
    if (!user) throw new HTTPException(400, { message: "User not found" });
    return user;
  }
  userGetByEmail(email: string): User {
    const user = this.db.query("select * from users where email = ? limit 1").get(email) as null | User;
    if (!user) throw new HTTPException(400, { message: "User not found" });
    return user;
  }
  credentialListByUserIdToSelect(userId: number): CredentialSelect[] {
    const list = this.db.query("select * from credentials where user_id = ?").all(userId) as Credential[];
    for (const credential of list) {
      credential.credential_json = JSON.parse(credential.credential_data);
    }
    return list.map<CredentialSelect>((v) => ({
      id: v.id,
      name: v.name,
      credential: v.credential_json,
    }));
  }
  credentialByIdAndUserId(userId: number, credentialId: number): Credential {
    const credential = this.db
      .query("select * from credentials where user_id = ? and id = ? limit 1")
      .get(userId, credentialId) as null | Credential;
    if (!credential) throw new HTTPException(400, { message: "Credential not found" });
    credential.credential_json = JSON.parse(credential.credential_data);
    return credential;
  }
  credentialAdd(user_id: number, name: string, credentialInfo: CredentialInfo): void {
    const credential_id = credentialInfo.id;
    const credential_data = JSON.stringify(credentialInfo);
    this.db.run("INSERT INTO credentials (user_id, name, credential_id, credential_data) VALUES (?, ?, ?, ?)", [
      user_id,
      name,
      credential_id,
      credential_data,
    ]);
  }
  credentialUsedNow(credentialId: number) {
    this.db.run(`UPDATE credentials SET used_at = datetime() WHERE id = ?`, [credentialId]);
  }
}
