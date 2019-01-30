export enum UserGroup { Guest, User, SiteAdmin };

export class TokenInfo {
  isExpired: boolean;
  isValid: boolean;
  userName: string;
  group: UserGroup;
}
