import { SignupData } from "../SignupData";
import { UserSession } from "../user/UserSession";
import { LoginData } from "../LoginData";
import { TokenInfo } from "../TokenInfo";

export interface AuthService {
  verifyJwt(header: string): Promise<TokenInfo>;

  /**
   * Decodes a JWT token and throws an Unauthorized error if its UserGroup
   * isn't User or SiteAdmin.
   */
  verifyAuthorizedJwt(header: string): Promise<TokenInfo>;

  signup(signupData: SignupData): Promise<void>;
  login(loginData: LoginData): Promise<UserSession>;
  refresh(authHeader: string): Promise<UserSession>;
  deleteUser(userName: string): Promise<void>;
}