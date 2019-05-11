import { LoginProvider } from "./LoginProvider";
import { LoginData } from "../LoginData";
import { LogoutData } from "./LogoutData";
import { UserSession } from "../user/UserSession";
import { CognitoConfig } from '../auth/AwsAuthServiceConfig';
import { LoginProviderUser } from "./LoginProviderUser";
import { AuthError } from '../auth/AuthError';
export declare class AwsCognitoLoginProvider implements LoginProvider {
    config: CognitoConfig;
    static toAuthError: (error: any) => AuthError;
    constructor(config: CognitoConfig);
    /**
     * Constructs a CognitoUser that is needed for login and token refresh.
     */
    private getCognitoUser;
    private userFromCognitoUserSession;
    getUser(loginData: LoginData): Promise<LoginProviderUser>;
    refresh(accessToken: string): Promise<UserSession>;
    logout(logoutData: LogoutData): Promise<void>;
}
