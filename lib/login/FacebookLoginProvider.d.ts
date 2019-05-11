import { LoginProvider } from "./LoginProvider";
import { LoginData } from "../LoginData";
import { LogoutData } from "./LogoutData";
import { UserSession } from "../user/UserSession";
import { FacebookConfig } from "../auth/AwsAuthServiceConfig";
import { LoginProviderUser } from "./LoginProviderUser";
export declare class FacebookLoginProvider implements LoginProvider {
    config: FacebookConfig;
    constructor(config: FacebookConfig);
    private createPermanentPassword;
    getUser(loginData: LoginData): Promise<LoginProviderUser>;
    refresh(accessToken: string): Promise<UserSession>;
    logout(logoutData: LogoutData): Promise<void>;
}
