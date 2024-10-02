import { User } from "./database";

export interface UserJson {
  id: number;
  email: string;
  jwt_version: number;
  gdpr_delete_at: string | null;
  created_at: string;
}

function sqliteDateUtcOrNull(date: string | null) {
  if (!date) return null;
  return date + " UTC";
}

export function userToJson(u: User): UserJson {
  return {
    id: u.id,
    email: u.email,
    jwt_version: u.jwt_version,
    gdpr_delete_at: sqliteDateUtcOrNull(u.gdpr_delete_at),
    created_at: u.created_at + " UTC",
  };
}
